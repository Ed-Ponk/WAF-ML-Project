import os, sys, math, time, json, re
import joblib
import pandas as pd
import numpy as np
import asyncpg, asyncio
from collections import Counter
from urllib.parse import unquote
from fastapi import FastAPI, Request, HTTPException


# ══════════════════════════════════════════════════════════════════
# 1. CONFIGURACIÓN Y CARGA DEL ENSEMBLE
# ══════════════════════════════════════════════════════════════════
# Usamos el archivo unificado que empaqueta todo el cerebro del WAF
MODEL_PATH = os.getenv("MODEL_PATH", "waf_ensemble_final.pkl")

if not os.path.exists(MODEL_PATH):
    sys.exit(f"[ERROR] Ensemble no encontrado: {MODEL_PATH}")

print("Cargando cerebro híbrido (LGBM + MLP)...")
bundle = joblib.load(MODEL_PATH)

# Extraemos componentes del diccionario
lgbm_model = bundle["lgbm_model"]
mlp_model  = bundle["mlp_model"]
mlp_scaler = bundle["mlp_scaler"]
lgbm_cols  = bundle["lgbm_features"] # Las 33 columnas
mlp_cols   = bundle["mlp_features"]  # Las 36 columnas
lgbm_encoders = bundle["lgbm_encoders"] 

app = FastAPI(title="WAF-ML Hybrid Engine", version="2.0")
db_pool = None
DATABASE_URL = "postgresql://user:pass@database:5432/waf_db"

# ══════════════════════════════════════════════════════════════════
# 2. EXTRACCIÓN DE CARACTERÍSTICAS (Sincronizada con tu dataset)
# ══════════════════════════════════════════════════════════════════

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    n    = len(text)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def extract_features(method: str, url: str, payload: str) -> pd.DataFrame:
    # Normalización inicial para coincidir con el entrenamiento 
    combined = (url + " " + payload).lower()
    path_only = url.split("?")[0] if "?" in url else url
    query_part = url.split("?")[1] if "?" in url else ""
    
    # 1. Diccionario base de características
    f = {
        "method": method.upper(),
        "url_path_len": len(path_only),
        "url_query_len": len(query_part),           # ← Nueva
        "url_path_depth": len([s for s in path_only.split('/') if s]),
        "payload_len": len(payload),                # ← Nueva
        "payload_entropy": shannon_entropy(payload),
    }

    # 2. Regex de Seguridad (OE2)
    PATTERNS = {
        "sql": r"(?i)(select|union|insert|update|delete|drop|waitfor|sleep|benchmark|0x[0-9a-f]+|--|;|\/\*)",
        "xss": r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\(|<iframe|<img[^>]+src\s*=)",
        "rce": r"(?i)(phpunit|eval\s*\(|exec\s*\(|system\s*\(|shell_exec|`[^`]+`|base64_decode)",
        "path": r"(\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows|boot\.ini)",
        "ldap": r"(?i)(\*\)\(|\(\||\(&|objectclass=|cn=)",
        "xxe":  r"(?i)(<!entity|<!doctype|system\s+['\"])",
        "graphql": r"(?i)(\{__schema|\{__type|query\s*\{|mutation\s*\{)",
        "oracle_sql": r"(?i)(dbms_pipe|dbms_output|utl_http|v\$|sys\.)",
        "open_redirect": r"(?i)(redirect_to=https?|url=https?|next=https?)"
    }

    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, combined)
        f[f"has_{name}"] = int(len(matches) > 0)
        f[f"count_{name}"] = len(matches)

    # === Features adicionales que faltaban ===
    f["has_double_dash"] = int("--" in combined)
    f["has_backtick"] = int("`" in combined)
    f["has_semicolon"] = int(";" in combined)
    f["has_union_select"] = int(bool(re.search(r"(?i)union.*select", combined)))
    
    f["count_digits"] = len(re.findall(r"\d", combined))
    f["count_special_chars"] = len(re.findall(r"[^\w\s]", combined))
    
    f["has_url_encoding"] = int(bool(re.search(r"%[0-9a-fA-F]{2}", combined)))
    f["has_single_quote"] = int("'" in combined or "%27" in combined)
    f["has_comment_sql"] = int(bool(re.search(r"--|\/\*|#\s*$", combined)))
    f["has_tautology"] = int(bool(re.search(r"(?i)(or|and)\s+[\d'\"]+\s*=\s*[\d'\"]+", combined)))
    f["count_special_encoded"] = len(re.findall(r"%[0-9a-fA-F]{2}", combined))
    
    f["has_xmlrpc"] = int("xmlrpc.php" in url.lower())
    f["has_wp_admin"] = int(bool(re.search(r"(?i)(wp-login|wp-admin|wp-json)", url)))
    f["has_timebased_sql"] = int(bool(re.search(r"(?i)(waitfor|sleep\s*\(|benchmark\s*\()", combined)))
    f["has_header_injection"] = int(bool(re.search(r"(?i)(set-cookie|x-forwarded-for)", combined)))
    
    # Obfuscación
    lucz_segments = re.findall(r"/d_[0-9a-f]{8}", url)
    f["has_lucz_obfuscation"] = int(len(lucz_segments) > 0)
    f["count_lucz_segments"] = len(lucz_segments)
    
    # CRLF y otros
    f["has_crlf"] = int(bool(re.search(r"(%0d%0a|\r\n)", combined)))
    f["count_crlf"] = len(re.findall(r"(%0d%0a|\r\n)", combined))
    
    f["has_any_injection"] = int(any(f.get(f"has_{k}", 0) for k in PATTERNS) or f["has_timebased_sql"])

    return pd.DataFrame([f])


# ══════════════════════════════════════════════════════════════════
# 3. LÓGICA DE INFERENCIA
# ══════════════════════════════════════════════════════════════════
METODOS_MAESTROS = ["PUT", "POST", "GET", "CONNECT", "DELETE", "HEAD", "PATCH", "OPTIONS", "PROPFIND", "ROAJ"]

async def get_ensemble_score(df_raw: pd.DataFrame):
    try:
        # --- A. PREPARACIÓN LIGHTGBM (sin cambios) ---
        df_lgbm = df_raw.copy()
        m_enc = lgbm_encoders.get("method") if isinstance(lgbm_encoders, dict) else lgbm_encoders
        try:
            df_lgbm['method'] = m_enc.transform(df_lgbm['method'].astype(str))
        except:
            df_lgbm['method'] = 0
        df_lgbm = df_lgbm.reindex(columns=lgbm_cols, fill_value=0)
        prob_lgbm = lgbm_model.predict(df_lgbm.values)[0]

        # --- B. PREPARACIÓN MLP — FIX DIMENSIONAL ---
        df_mlp = df_raw.copy()
        method_val = df_mlp['method'].iloc[0].upper()

        # Eliminar columna method original
        df_mlp = df_mlp.drop(columns=['method'], errors='ignore')

        # Crear los 10 dummies manualmente — garantiza siempre 42 columnas
        for m in METODOS_MAESTROS:
            df_mlp[f"method_{m}"] = int(method_val == m)

        # Reindex contra mlp_cols del bundle — fill_value=0 cubre columnas faltantes
        df_mlp = df_mlp.reindex(columns=mlp_cols, fill_value=0)

        print(f"🔍 DEBUG MLP: {len(df_mlp.columns)} columnas → esperadas: {len(mlp_cols)}")

        # Escalado
        df_mlp_sc = mlp_scaler.transform(
            pd.DataFrame(df_mlp.values, columns=mlp_cols)
        )
        prob_mlp  = mlp_model.predict_proba(df_mlp_sc)[0, 1]

        print(f"🔍 LGBM: {prob_lgbm:.4f} | MLP: {prob_mlp:.4f} | MIN: {min(prob_lgbm, prob_mlp):.4f}")
        # Ensemble ponderado
        return float(min(prob_lgbm, prob_mlp))

    except Exception as e:
        print(f"⚠️ Error en Inferencia: {e}")
        import traceback
        traceback.print_exc()
        return 0.50


# ══════════════════════════════════════════════════════════════════
# 4. CONEXION A BASE DE DATOS
# ══════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    global db_pool
    # El host 'database' debe coincidir con el nombre del servicio en tu docker-compose.yml
    retries = 5
    while retries > 0:
        try:
            db_pool = await asyncpg.create_pool("postgresql://user:pass@database:5432/waf_db")
            print("✅ Conexión a PostgreSQL establecida")
            break
        except Exception as e:
            retries -= 1
            print(f"⚠️ Esperando a la base de datos... ({retries} intentos restantes)")
            await asyncio.sleep(3) # Espera 3 segundos antes de reintentar
    
    if not db_pool:
        sys.exit("❌ No se pudo conectar a la base de datos tras varios intentos")

@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()

# ══════════════════════════════════════════════════════════════════
# 5. ENDPOINT PRINCIPAL (TRES ZONAS)
# ══════════════════════════════════════════════════════════════════

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def waf_core(request: Request, path_name: str):
    start_time = time.time()
    
    original_url = request.headers.get("x-original-uri", "")
    original_method = request.headers.get("x-original-method", request.method)

    # Fallback si no viene el header
    if not original_url:
        original_url = "/" + path_name

    url_inspect   = unquote(original_url).lower()
    client_ip     = request.headers.get("x-real-ip", request.client.host)

    try:
        body = await request.body()
        payload = body.decode("utf-8", errors="ignore") 

        # === DEBUG SIEMPRE ===
        print(f"\n🔍 DEBUG REQUEST: {request.method} {url_inspect}")
        

        # Extracción y Heurística
        df_features = extract_features(request.method, url_inspect, payload)
        f_dict = df_features.iloc[0].to_dict()

        print(f"🔍 DEBUG FEATURES: {len(df_features.columns)} columnas generadas")
        print(f"🔍 Columnas: {sorted(df_features.columns.tolist())}")
        print(f"🔍 DEBUG FEATURES DICT: {f_dict}")

        # CAPA 1: Descarte Rápido
        if (original_method == "GET" and
            f_dict['has_any_injection'] == 0 and
            f_dict['count_special_chars'] <= 2 and
            f_dict['payload_entropy'] < 1.0 and
            not f_dict.get('has_sql', 0) and
            not f_dict.get('has_xss', 0)):
            score = 0.05
            print("⚡ Fast path — tráfico limpio aprobado")
        else:
            print("🔄 Usando inferencia ML completa...")
            score = await get_ensemble_score(df_features)
        
    except Exception as e:
        print(f"❌ Error crítico: {e}")
        score, f_dict = 0.50, {"url_path_len": 0}

    # Lógica de Tres Zonas
    if score >= 0.70:   verdict, action = 1, "BLOCK"
    elif score >= 0.40: verdict, action = 0, "LOG"
    else:               verdict, action = 0, "ALLOW"

    latency = (time.time() - start_time) * 1000

    print(f"✅ FINAL: Score={score:.4f} | Action={action} | Latency={latency:.1f}ms")

    # Persistencia (Async)
    if db_pool:
        asyncio.create_task(save_to_db(
            client_ip, 
            request.method, 
            url_inspect, 
            payload, 
            score, 
            verdict, 
            action, 
            latency, 
            f_dict
        ))

    if action == "BLOCK":
        raise HTTPException(status_code=403, detail="Blocked by Hybrid WAF")

    return {"verdict": verdict, "action": action, "score": round(float(score), 4), "latency_ms": round(latency, 2)}


async def save_to_db(client_ip: str, method: str, url_inspect: str, payload: str, score: float, verdict: int, action: str, latency: float, f_dict: dict):
    # Validamos que el pool de conexiones exista antes de intentar usarlo
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO waf_events (
                        ip_origen, metodo_http, url, payload,
                        url_length, payload_length, shannon_entropy,
                        score_ml, veredicto, accion, tiempo_inferencia_ms,
                        features_json
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ''', 
                client_ip, 
                method, 
                url_inspect, 
                payload,
                f_dict.get('url_path_len', 0), 
                len(payload), 
                f_dict.get('payload_entropy', 0),
                float(score), 
                verdict, 
                action, 
                latency, 
                json.dumps(f_dict))
        except Exception as db_e:
            print(f"⚠️ Error al guardar en DB: {db_e}")