import os, sys, time, json
import joblib
import pandas as pd
import asyncpg, asyncio
import threading
import psutil
from urllib.parse import unquote, parse_qs
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
import httpx
# SafeUnpickler not imported here — reload uses joblib.load() directly,
# which handles numpy arrays and compressed formats that raw pickle can't.


# ══════════════════════════════════════════════════════════════════
# 1. CONFIGURACIÓN Y CARGA DEL ENSEMBLE
# ══════════════════════════════════════════════════════════════════
# Usamos el archivo unificado que empaqueta todo el cerebro del WAF
MODEL_PATH = os.getenv("MODEL_PATH", "waf_ensemble_final.pkl")
MODEL_VERSION = os.getenv("WAF_MODEL_VERSION", "v3 (no loaded)")

# Variables globales del modelo — se cargan en startup o via reload
lgbm_model = None
mlp_model  = None
mlp_scaler = None
lgbm_cols  = None
mlp_cols   = None
lgbm_encoders = None
TH_ALLOW = 0.30
TH_BLOCK = 0.70
WEIGHT_LGBM = 0.60
WEIGHT_MLP  = 0.40
_model_loaded = False
_bundle_metadata = {}  # extra fields: algorithm, accuracy, f1_score, feature_count, training_date

def _load_ensemble(path: str) -> bool:
    """Carga el bundle del modelo desde path. Retorna True si ok."""
    global lgbm_model, mlp_model, mlp_scaler, lgbm_cols, mlp_cols, lgbm_encoders
    global TH_ALLOW, TH_BLOCK, WEIGHT_LGBM, WEIGHT_MLP, MODEL_VERSION, _model_loaded

    if not os.path.exists(path):
        print(f"⚠️ Modelo no encontrado en {path} — modo degradado")
        _model_loaded = False
        return False

    print(f"Cargando cerebro híbrido (LGBM + MLP) desde {path}...")
    import datetime as _dt
    bundle = joblib.load(path)

    lgbm_model  = bundle["lgbm_model"]
    mlp_model   = bundle["mlp_model"]
    mlp_scaler  = bundle["mlp_scaler"]
    lgbm_cols   = bundle["lgbm_features"]
    mlp_cols    = bundle["mlp_features"]
    lgbm_encoders = bundle["lgbm_encoders"]

    _TH = bundle.get("thresholds", {"allow": 0.30, "block": 0.70})
    TH_ALLOW = _TH.get("allow", 0.30)
    TH_BLOCK = _TH.get("block", 0.70)

    _W = bundle.get("weights", {"lgbm": 0.60, "mlp": 0.40})
    WEIGHT_LGBM = _W.get("lgbm", 0.60)
    WEIGHT_MLP  = _W.get("mlp",  0.40)

    MODEL_VERSION = (
        bundle.get("model_version")
        or bundle.get("metadata", {}).get("version")
        or os.getenv("WAF_MODEL_VERSION")
    )
    if not MODEL_VERSION:
        _mtime = os.path.getmtime(path)
        MODEL_VERSION = f"v3 ({_dt.datetime.fromtimestamp(_mtime).strftime('%Y-%m-%d')})"

    # Extraer metadatos adicionales del bundle
    meta = bundle.get("metadata", {})
    _bundle_metadata["algorithm"] = meta.get("algorithm", "LightGBM + MLP Neural Net")
    _bundle_metadata["accuracy"] = meta.get("accuracy")
    _bundle_metadata["f1_score"] = meta.get("f1_score")
    _bundle_metadata["feature_count"] = meta.get("feature_count",
        len(bundle.get("lgbm_features", [])) + len(bundle.get("mlp_features", [])))
    _bundle_metadata["training_date"] = meta.get("training_date",
        _dt.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d'))

    _model_loaded = True
    print(f"✅ Modelo cargado: {MODEL_VERSION}")
    return True

_load_ensemble(MODEL_PATH)

# Backend proxy — adónde reenviar requests permitidos
# Nginx inyecta X-Backend; si no llega (benchmark directo), se usa DEFAULT_BACKEND
DEFAULT_BACKEND = os.getenv("DEFAULT_BACKEND", "")

app = FastAPI(title="WAF-ML Hybrid Engine", version="2.0")
db_pool = None
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://waf_user:waf_pass@database:5432/waf_db")

# ── Health check — usado por Docker para marcar el contenedor healthy ──
@app.get("/health")
async def health():
    return {
        "status": "ok" if _model_loaded else "degraded",
        "model": MODEL_PATH,
        "model_loaded": _model_loaded,
        "model_version": MODEL_VERSION,
    }

reload_lock = threading.Lock()

@app.post("/reload_model")
async def reload_model():
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=400, detail=f"Model file not found at {MODEL_PATH}")
        
    try:
        with reload_lock:
            # Use joblib.load() — handles numpy arrays, compressed formats,
            # and pickle protocol extensions that raw pickle.Unpickler can't.
            bundle = joblib.load(MODEL_PATH)
            
            # Validate expected keys
            required_keys = ["lgbm_model", "mlp_model", "mlp_scaler", "lgbm_features", "mlp_features", "lgbm_encoders"]
            for key in required_keys:
                if key not in bundle:
                    raise ValueError(f"Missing required key in model bundle: {key}")
            
        # Use shared loader to update all globals
        if not _load_ensemble(MODEL_PATH):
            raise HTTPException(status_code=400, detail="Model file disappeared after validation")
            
        print(f"✅ Model successfully reloaded from {MODEL_PATH}")
        return {
            "status": "success",
            "message": f"Model successfully reloaded from {MODEL_PATH}",
            "version": MODEL_VERSION,
            "metadata": {
                "algorithm": _bundle_metadata.get("algorithm"),
                "accuracy": _bundle_metadata.get("accuracy"),
                "f1_score": _bundle_metadata.get("f1_score"),
                "feature_count": _bundle_metadata.get("feature_count"),
                "training_date": _bundle_metadata.get("training_date"),
            },
        }
        
    except Exception as e:
        err_msg = str(e)
        print(f"❌ Error reloading model: {err_msg}")
        raise HTTPException(status_code=400, detail=f"Failed to reload model: {err_msg}")

# ══════════════════════════════════════════════════════════════════
# 2. EXTRACCIÓN DE CARACTERÍSTICAS (Copia estática local)
# ══════════════════════════════════════════════════════════════════
# Importamos desde extract_features.py (en el mismo directorio).
# 
# ⚠️  Este archivo es una COPIA de:
#     thesis/ScriptsFeatures/extract_features.py
#     Si modificás las features, actualizá AMBOS archivos.
from extract_features import extract_features_df, shannon_entropy


# ══════════════════════════════════════════════════════════════════
# 3. LÓGICA DE INFERENCIA
# ══════════════════════════════════════════════════════════════════
async def get_ensemble_score(df_raw: pd.DataFrame):
    if not _model_loaded:
        return 0.50  # Default: duda (LOG) si no hay modelo cargado
    
    try:
        m_enc = lgbm_encoders.get("method") if isinstance(lgbm_encoders, dict) else lgbm_encoders

        # --- A. LIGHTGBM — label-encoded method ---
        df_lgbm = df_raw.copy()
        try:
            df_lgbm['method'] = m_enc.transform(df_lgbm['method'].astype(str))
        except:
            df_lgbm['method'] = 0
        df_lgbm = df_lgbm.reindex(columns=lgbm_cols, fill_value=0)
        prob_lgbm = lgbm_model.predict(df_lgbm.values)[0]

        # --- B. MLP — 'method' excluido del MLP v2 (no está en mlp_cols) ---
        df_mlp = df_raw.copy()
        # No se aplica label-encoding de method: mlp_cols no lo incluye.
        # reindex con fill_value=0 maneja columnas faltantes automáticamente.
        df_mlp = df_mlp.reindex(columns=mlp_cols, fill_value=0)

        df_mlp_sc = mlp_scaler.transform(
            pd.DataFrame(df_mlp.values, columns=mlp_cols)
        )
        prob_mlp  = mlp_model.predict_proba(df_mlp_sc)[0, 1]

        # Estrategia WEIGHTED — pesos globales cargados del bundle (0.60 LGBM / 0.40 MLP)
        ensemble = float(WEIGHT_LGBM * prob_lgbm + WEIGHT_MLP * prob_mlp)
        print(f"🔍 LGBM: {prob_lgbm:.4f} | MLP: {prob_mlp:.4f} | WEIGHTED: {ensemble:.4f}")
        return ensemble

    except Exception as e:
        print(f"⚠️ Error en Inferencia: {e}")
        import traceback
        traceback.print_exc()
        return 0.50


# ══════════════════════════════════════════════════════════════════
# 4. CONEXION A BASE DE DATOS
# ══════════════════════════════════════════════════════════════════

@app.on_event("shutdown")
async def shutdown():
    global _hw_task
    if _hw_task:
        _hw_task.cancel()
    if db_pool:
        await db_pool.close()

# ══════════════════════════════════════════════════════════════════
# 5. MONITOREO DE HARDWARE (Background task cada 30s)
# ══════════════════════════════════════════════════════════════════

_hw_task = None

async def _read_cpu_pct() -> float:
    """Lee uso de CPU con psutil (media sobre 1s de intervalo)."""
    try:
        # Ejecutar en thread separado para no bloquear el event loop
        return await asyncio.to_thread(psutil.cpu_percent, interval=1)
    except Exception:
        return 0.0

async def _read_ram_mb() -> float:
    """Lee uso de RAM con psutil."""
    try:
        mem = await asyncio.to_thread(lambda: psutil.virtual_memory())
        return round(mem.used / (1024 * 1024), 2)
    except Exception:
        return 0.0

async def _poll_hardware_metrics():
    """Cada 30s lee CPU/RAM del contenedor y lo guarda en waf_hardware_metrics."""
    global db_pool
    while True:
        try:
            await asyncio.sleep(30)
            if not db_pool:
                continue
            cpu = await _read_cpu_pct()
            ram = await _read_ram_mb()
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO waf_hardware_metrics (container_name, cpu_usage_pct, ram_usage_mb) VALUES ($1, $2, $3)",
                    "ml-engine", cpu, ram
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"⚠️ Hardware poll error: {e}")

@app.on_event("startup")
async def startup():
    global db_pool, _hw_task
    # El host 'database' debe coincidir con el nombre del servicio en tu docker-compose.yml
    retries = 5
    while retries > 0:
        try:
            db_pool = await asyncpg.create_pool(DATABASE_URL)
            print("✅ Conexión a PostgreSQL establecida")
            break
        except Exception as e:
            retries -= 1
            print(f"⚠️ Esperando a la base de datos... ({retries} intentos restantes)")
            await asyncio.sleep(3)
    
    if not db_pool:
        print("⚠️ ADVERTENCIA: Iniciando en modo LOCAL. Los logs no se guardarán en la DB.")
        db_pool = None
    else:
        # Iniciar background polling de hardware
        _hw_task = asyncio.create_task(_poll_hardware_metrics())
        print("✅ Monitoreo de hardware iniciado (cada 30s)")

def _should_use_fast_path(original_method: str, f_dict: dict) -> bool:
    """Determina si una solicitud GET limpia puede saltarse la inferencia ML.

    La heurística de descarte rápido evita llamar al ensemble LGBM+MLP
    para tráfico GET legítimo que claramente no contiene ataques.

    El umbral count_special_chars <= 15 permite URLs REST normales
    (ej: /api/v1/users/123/posts?page=1&limit=10 tiene ~9 caracteres
    especiales según la regex [^\\w\\s]) mientras sigue bloqueando
    URLs heavily obfuscated.

    En WAF_BENCHMARK_MODE=1, el fast-path se desactiva completamente
    para evaluar el rendimiento real del ensemble ML.
    """
    if os.environ.get("WAF_BENCHMARK_MODE") == "1":
        return False
    return (
        original_method == "GET"
        and f_dict.get('has_any_injection', 0) == 0
        and f_dict.get('has_evasion_encoding', 0) == 0   # v1.3: encoding de evasión real
        and f_dict.get('count_special_chars', 0) <= 15
        and f_dict.get('payload_entropy', 0) < 1.0
        and not f_dict.get('has_sql', 0)
        and not f_dict.get('has_xss', 0)
    )


# ══════════════════════════════════════════════════════════════════
# 5. ENDPOINT PRINCIPAL (TRES ZONAS)
# ══════════════════════════════════════════════════════════════════

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def waf_core(request: Request, path_name: str):
    start_time = time.time()
    
    original_url = request.headers.get("x-original-uri", "")
    original_method = request.headers.get("x-original-method", request.method)

    # Fallback si no viene el header (benchmark directo sin nginx)
    if not original_url:
        original_url = request.url.path
        if request.url.query:
            original_url += "?" + request.url.query

    client_ip     = request.headers.get("x-real-ip", request.client.host)

    payload = ""
    f_dict = {"url_path_len": 0, "payload_entropy": 0}
    score = 0.50

    try:
        body = await asyncio.wait_for(request.body(), timeout=1.0)
        payload = body.decode("utf-8", errors="ignore") 

        # ── Parseo POST form-urlencoded (v2.0) ─────────────────────
        # Extraer solo los VALUES para que extract_features no diluya
        # la señal de ataque con los nombres de campo.
        # Ej: "email=admin' OR 1=1--&password=123" → "admin' OR 1=1-- 123"
        values_only = payload
        extra_features = {}
        if payload and request.method in ("POST", "PUT"):
            try:
                params = parse_qs(payload)
                if params:
                    values = [v[0] for v in params.values()]
                    values_only = " ".join(values)
                    extra_features["body_is_form"] = 1
                    extra_features["max_field_value_len"] = max(len(v) for v in values)
                    extra_features["body_field_count"] = len(params)
            except Exception:
                pass  # fallback: body plano

        # === DEBUG SIEMPRE ===
        print(f"\n🔍 DEBUG REQUEST: {request.method} {original_url}")

        # Extracción y Heurística (módulo compartido)
        # Usamos original_url raw (no unquote) para que extract_features
        # detecte URL encoding, has_double_encoding, etc. internamente.
        # Usamos values_only (post form parseado) en vez del body crudo.
        df_features = extract_features_df(request.method, original_url, values_only, include_extras=True)
        f_dict = df_features.iloc[0].to_dict()
        f_dict.update(extra_features)

        #print(f"🔍 DEBUG FEATURES: {len(df_features.columns)} columnas generadas")
        #print(f"🔍 Columnas: {sorted(df_features.columns.tolist())}")
        #print(f"🔍 DEBUG FEATURES DICT: {f_dict}")

        # CAPA 1: Descarte Rápido
        if _should_use_fast_path(original_method, f_dict):
            score = 0.05
            print("⚡ Fast path — tráfico limpio aprobado")
        else:
            print("🔄 Usando inferencia ML completa...")
            score = await get_ensemble_score(df_features)
        
    except asyncio.TimeoutError:
        print("⚠️ Timeout: No se recibió el cuerpo, procesando solo URL")
        payload = ""
        df_features = extract_features_df(request.method, original_url, payload, include_extras=True)
        f_dict = df_features.iloc[0].to_dict()

        # Fast path también aplica cuando no hay cuerpo (ej: auth_request de nginx).
        # En este contexto, request.method es GET (subrequest auth_request).
        # Usamos request.method en lugar de original_method porque sin cuerpo
        # no hay diferencia entre GET y POST para el análisis de URL.
        if _should_use_fast_path(request.method, f_dict):
            score = 0.05
            print("⚡ Fast path — tráfico limpio aprobado (timeout handler)")
        else:
            score = await get_ensemble_score(df_features)

    # Lógica de Tres Zonas (umbrales desde bundle del modelo)
    if score >= TH_BLOCK:   verdict, action = 1, "BLOCK"
    elif score >= TH_ALLOW: verdict, action = 0, "LOG"
    else:                   verdict, action = 0, "ALLOW"

    latency = (time.time() - start_time) * 1000

    print(f"✅ FINAL: Score={score:.4f} | Action={action} | Latency={latency:.1f}ms")

    # Capturar user-agent
    user_agent = request.headers.get("user-agent", "")

    # Persistencia (Async)
    if db_pool:
        asyncio.create_task(save_to_db(
            client_ip, 
            user_agent,
            request.method, 
            original_url, 
            payload, 
            score, 
            verdict, 
            action, 
            latency, 
            f_dict
        ))

    if action == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={"detail": "Blocked by Hybrid WAF"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": str(round(float(score), 4))},
        )

    # ── Proxy al backend ──────────────────────────────────────────
    # Si es ALLOW o LOG, reenviar la request al backend real
    backend_url = request.headers.get("X-Backend", DEFAULT_BACKEND)
    if backend_url:
        try:
            # Reconstruir la URL completa del backend
            target_url = backend_url.rstrip("/") + "/" + path_name.lstrip("/")
            if request.url.query:
                target_url += "?" + request.url.query

            # Headers a reenviar (sin los de nginx/ml-engine internos)
            forward_headers = {}
            for k, v in request.headers.items():
                kl = k.lower()
                if kl in ("x-backend", "x-original-uri", "x-original-method",
                          "x-real-ip", "content-encoding"):
                    continue
                forward_headers[k] = v

            # Leer body crudo (ya lo tenemos en payload, pero mejor leer directo)
            body_bytes = await request.body()

            async with httpx.AsyncClient(timeout=30.0) as client:
                backend_resp = await client.request(
                    method=request.method,
                    url=target_url,
                    headers=forward_headers,
                    content=body_bytes,
                    follow_redirects=False,
                )

            # Agregar headers del WAF a la respuesta del backend
            resp_headers = dict(backend_resp.headers)
            resp_headers["X-WAF-Action"] = action
            resp_headers["X-WAF-Score"] = str(round(float(score), 4))

            # Reescribir Location si apunta al hostname interno del backend
            external_host = request.headers.get("host", "localhost")
            scheme = request.headers.get("x-forwarded-proto", "http")
            backend_host = backend_url.rstrip("/")

            location = resp_headers.get("location", "")
            if location and backend_host in location:
                resp_headers["location"] = location.replace(
                    backend_host,
                    f"{scheme}://{external_host}",
                )

            # Reescribir body si contiene el hostname interno
            body = backend_resp.content
            if backend_host.encode() in body:
                body = body.replace(
                    backend_host.encode(),
                    f"{scheme}://{external_host}".encode(),
                )

            return Response(
                content=body,
                status_code=backend_resp.status_code,
                headers=resp_headers,
            )

        except Exception as proxy_err:
            print(f"⚠️ Error proxy al backend: {proxy_err}")
            # Si falla el proxy, devolver error 502
            return JSONResponse(
                status_code=502,
                content={"detail": "Backend unavailable"},
                headers={"X-WAF-Action": action, "X-WAF-Score": str(round(float(score), 4))},
            )

    # Sin backend configurado (benchmark directo) — responder con veredicto
    headers = {
        "X-WAF-Action": action,
        "X-WAF-Score": str(round(float(score), 4)),
    }
    return JSONResponse(
        content={"verdict": verdict, "action": action, "score": round(float(score), 4), "latency_ms": round(latency, 2)},
        headers=headers,
    )


async def save_to_db(client_ip: str, user_agent: str, method: str, url_inspect: str, payload: str, score: float, verdict: int, action: str, latency: float, f_dict: dict):
    # Validamos que el pool de conexiones exista antes de intentar usarlo
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO waf_events (
                        ip_origen, user_agent, metodo_http, url, payload,
                        url_length, payload_length, special_char_count, shannon_entropy,
                        score_ml, veredicto, accion, tiempo_inferencia_ms,
                        features_json, waf_version
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ''', 
                client_ip, 
                user_agent,
                method, 
            url_inspect if 'url_inspect' in locals() else original_url, 
                payload,
                f_dict.get('url_path_len', 0), 
                len(payload), 
                f_dict.get('count_special_chars', 0),
                f_dict.get('payload_entropy', 0),
                float(score), 
                verdict, 
                action, 
                latency, 
                json.dumps(f_dict),
                MODEL_VERSION)
        except Exception as db_e:
            print(f"⚠️ Error al guardar en DB: {db_e}")
