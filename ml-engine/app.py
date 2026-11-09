from typing import Dict, Any, Optional, Tuple
import os, sys, time, json, base64, hashlib, hmac
import socket, ipaddress
from dataclasses import dataclass
import pandas as pd
import asyncpg, asyncio
import threading
import psutil
from urllib.parse import unquote, parse_qs, urlsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from starlette.datastructures import Headers
import httpx
from safe_unpickler import load_bundle_safe, SecurityError


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
    try:
        # Carga validada por la whitelist de safe_unpickler. Si el archivo
        # referencia un módulo/clase fuera de la whitelist se rechaza ANTES
        # de tocar los globals: el modelo activo queda intacto (modo degradado).
        bundle = load_bundle_safe(path)
    except SecurityError as e:
        print(f"❌ CARGA RECHAZADA por whitelist: {e}")
        print("   El modelo activo queda intacto (modo degradado).")
        _model_loaded = False
        return False

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

# JWT_SECRET compartido con el dashboard (opción A). Fail-closed: sin la env,
# verify_admin_jwt() rechaza siempre. Sin fallback hardcodeado.
JWT_SECRET = os.getenv("JWT_SECRET")

# Whitelist de backends del proxy (X-Backend / DEFAULT_BACKEND). CSV.
# Valores fuera de la lista se rechazan (anti-SSRF vía header). Se normaliza
# (strip + quitar trailing slash) para no rechazar tráfico legítimo por un "/"
# al final (p.ej. http://pyme-php-backend:80/ vs ...:80). Scheme y host se
# comparan tal cual: un descalce https vs http es un error de config audible
# (403 + log), no algo que convenga silenciar.
def _normalize_backend(url: str) -> str:
    return url.strip().rstrip("/")

BACKEND_ALLOWLIST = {
    _normalize_backend(url)
    for url in os.getenv("BACKEND_ALLOWLIST", "").split(",")
    if url.strip()
}

# Entorno: sólo WAF_ENV="development" explícito habilita compatibilidad legacy
# (X-Backend, X-App-Slug). Ausente o cualquier otro valor = producción.
WAF_ENV = (os.getenv("WAF_ENV", "") or "").strip().lower()
IS_DEVELOPMENT = WAF_ENV == "development"
IS_PRODUCTION = not IS_DEVELOPMENT


def _env_flag(name: str, default: bool = False) -> bool:
    value = (os.getenv(name, "") or "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


UNKNOWN_HOST_FALLBACK = _env_flag("WAF_UNKNOWN_HOST_FALLBACK", False)

# Hostnames internos del stack que nunca pueden ser backend de una app.
INTERNAL_HOST_DENYLIST = {
    "localhost",
    "database",
    "ml-engine",
    "waf-dashboard",
    "mysql",
    "vpn",
    "proxy",
    "certbot",
    "waf-db",
    "waf-ml-engine",
    "waf-pyme-db",
    "waf-vpn",
    "waf-proxy",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
}


class UnsafeBackendError(ValueError):
    """backend_url inválida o apunta a una dirección prohibida."""


class DisabledAppError(RuntimeError):
    """La app resuelta por Host está deshabilitada."""

    def __init__(self, app: Dict[str, Any]):
        self.app = app
        super().__init__(f"app deshabilitada: {app.get('slug')}")


class UnknownHostError(RuntimeError):
    """Host no registrado y sin fallback configurado (responde 421)."""

    def __init__(self, host: str):
        self.host = host
        super().__init__(f"host desconocido: {host!r}")


class NoDefaultAppError(RuntimeError):
    """No hay ninguna app habilitada para usar como default (responde 503)."""


@dataclass(frozen=True)
class BackendTarget:
    scheme: str
    host: str
    port: int
    path: str

    def to_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}{self.path}"


@dataclass(frozen=True)
class PinnedBackend:
    url: str
    sni_hostname: Optional[str]


def _parse_ip_literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_blocked_ip(ip) -> bool:
    """Bloquea loopback, link-local, unspecified y multicast.

    Los rangos privados (RFC1918 / redes Docker) SÍ se permiten: los
    backends de las apps protegidas viven en esas redes.
    """
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
    )


def parse_backend_url(raw: Any) -> BackendTarget:
    """Valida y normaliza un backend_url.

    Rechaza esquemas no HTTP(S), credenciales, query string, fragmento,
    hosts internos del stack y literales loopback/link-local/unspecified/
    multicast. Permite hostnames y rangos privados.
    """
    value = str(raw or "").strip().rstrip("/")
    if not value:
        raise UnsafeBackendError("backend_url vacía")

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise UnsafeBackendError(f"backend_url inválida: {exc}") from exc

    if parts.scheme not in ("http", "https"):
        raise UnsafeBackendError("backend_url sólo admite http:// o https://")
    if parts.username or parts.password:
        raise UnsafeBackendError("backend_url no puede incluir credenciales")
    if parts.query or parts.fragment:
        raise UnsafeBackendError("backend_url no puede incluir query string ni fragmento")

    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise UnsafeBackendError("backend_url sin host")
    if host in INTERNAL_HOST_DENYLIST:
        raise UnsafeBackendError(f"backend_url apunta a un servicio interno: {host}")

    literal = _parse_ip_literal(host)
    if literal is not None and _is_blocked_ip(literal):
        raise UnsafeBackendError(
            "backend_url apunta a loopback, link-local, unspecified o multicast"
        )

    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not (1 <= port <= 65535):
        raise UnsafeBackendError("backend_url con puerto inválido")

    path = parts.path.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path

    return BackendTarget(scheme=parts.scheme, host=host, port=port, path=path)


def normalize_host(raw: Any) -> str:
    """Normaliza un header Host: minúsculas, sin puerto y sin punto final."""
    value = str(raw or "").strip().lower()
    if not value:
        return ""
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            value = value[1:end]
        else:
            value = value.lstrip("[")
    elif value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


# Host explícito que puede caer al default aunque no esté en el registro.
WAF_DOMAIN = normalize_host(os.getenv("WAF_DOMAIN", ""))


def normalize_cache_domain(raw: Any) -> Optional[str]:
    """Normaliza un dominio de waf_app_domains; None si es inválido."""
    value = str(raw or "").strip().lower()
    if not value:
        return None
    if "://" in value or "/" in value or ":" in value or " " in value:
        return None
    value = value.rstrip(".")
    if not value or value in INTERNAL_HOST_DENYLIST:
        return None
    for label in value.split("."):
        if not label or len(label) > 63:
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
        if not all(c.isalnum() or c == "-" for c in label):
            return None
    return value


def resolve_backend_connection(
    backend_url: str,
    path_name: str,
    query: str = "",
) -> PinnedBackend:
    """Resuelve el backend y fija la IP de conexión (anti DNS rebinding).

    Se resuelve DNS en cada request. Si CUALQUIER dirección resuelta es
    loopback/link-local/unspecified/multicast se rechaza; si no, se fija la
    primera dirección y se arma la URL con esa IP para que httpx no vuelva a
    resolver el hostname.
    """
    target = parse_backend_url(backend_url)

    try:
        infos = socket.getaddrinfo(
            target.host,
            target.port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise UnsafeBackendError(f"no se pudo resolver {target.host}: {exc}") from exc

    if not infos:
        raise UnsafeBackendError(f"sin direcciones para {target.host}")

    pinned_ip: Optional[str] = None
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        candidate = str(sockaddr[0])
        ip = _parse_ip_literal(candidate)
        if ip is None or _is_blocked_ip(ip):
            raise UnsafeBackendError(
                f"{target.host} resuelve a una dirección prohibida: {candidate}"
            )
        if pinned_ip is None:
            pinned_ip = candidate

    if pinned_ip is None:
        raise UnsafeBackendError(f"sin direcciones válidas para {target.host}")

    path = target.path
    if path_name:
        path = f"{path}/{path_name.lstrip('/')}"
    elif not path:
        path = "/"

    host_for_url = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    url = f"{target.scheme}://{host_for_url}:{target.port}{path}"
    if query:
        url += f"?{query}"

    sni_hostname = target.host if target.scheme == "https" else None
    return PinnedBackend(url=url, sni_hostname=sni_hostname)


def _get_jwt_secret() -> str:
    """Lee JWT_SECRET de la env (mismo patrón lazy/fail-closed que el dashboard)."""
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET no está definido")
    return secret


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def verify_admin_jwt(token: str) -> str:
    """Verifica un JWT (firma HS256 + exp + role admin) contra JWT_SECRET.

    Retorna "ok" o el motivo de rechazo (missing_secret / malformed /
    bad_signature / expired / forbidden_role). Sin librerías de terceros.
    """
    try:
        secret = _get_jwt_secret()
    except RuntimeError:
        print("❌ JWT_SECRET no configurado — reload rechazado (fail-closed)")
        return "missing_secret"

    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return "malformed"

    try:
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "HS256":
            return "bad_signature"

        expected = hmac.new(
            secret.encode("utf-8"),
            f"{header_b64}.{payload_b64}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        received = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, received):
            return "bad_signature"

        payload = json.loads(_b64url_decode(payload_b64))
        exp = payload.get("exp")
        if not exp or time.time() >= exp:
            return "expired"
        if payload.get("role") != "admin":
            return "forbidden_role"
        return "ok"
    except Exception:
        return "malformed"

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
async def reload_model(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: missing Bearer token")

    reason = verify_admin_jwt(auth[len("Bearer "):].strip())
    if reason == "forbidden_role":
        raise HTTPException(status_code=403, detail="Forbidden: Admin role required")
    if reason != "ok":
        raise HTTPException(status_code=401, detail=f"Unauthorized: {reason}")

    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=400, detail=f"Model file not found at {MODEL_PATH}")
        
    try:
        with reload_lock:
            # Carga con el unpickler restringido (SafeNumpyUnpickler sobre el
            # formato numpy_pickle de joblib). Si el bundle referencia un
            # módulo/clase fuera de la whitelist, SecurityError aborta el
            # reload ANTES de actualizar los globals del modelo activo.
            bundle = load_bundle_safe(MODEL_PATH)
            
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
        
    except SecurityError as e:
        print(f"❌ Reload rechazado por whitelist: {e}")
        raise HTTPException(status_code=400, detail=f"Model rejected by security whitelist: {e}")

    except Exception as e:
        err_msg = str(e)
        print(f"❌ Error reloading model: {err_msg}")
        raise HTTPException(status_code=400, detail=f"Failed to reload model: {err_msg}")


@app.post("/reload_apps")
async def reload_apps(request: Request):
    """Recarga la caché de apps/dominios desde la DB (admin JWT)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: missing Bearer token")

    reason = verify_admin_jwt(auth[len("Bearer "):].strip())
    if reason == "forbidden_role":
        raise HTTPException(status_code=403, detail="Forbidden: Admin role required")
    if reason != "ok":
        raise HTTPException(status_code=401, detail=f"Unauthorized: {reason}")

    if not db_pool:
        raise HTTPException(status_code=503, detail="Database unavailable")

    ok = await load_apps_cache(force=True)
    if not ok:
        raise HTTPException(status_code=503, detail="Failed to reload apps cache")

    return {
        "status": "success",
        "apps": len(apps_cache),
        "domains": len(apps_by_domain),
        "default_app_id": default_app_id,
    }

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

# ══════════════════════════════════════════════════════════════════
# MULTI-APP CACHE (waf_apps)
# ══════════════════════════════════════════════════════════════════
apps_cache: Dict[str, Dict[str, Any]] = {}  # key = app_id (uuid string)
apps_by_slug: Dict[str, Dict[str, Any]] = {}  # key = slug
apps_by_domain: Dict[str, Dict[str, Any]] = {}  # key = dominio normalizado
default_app_id: Optional[str] = None
default_app_slug: str = os.environ.get("DEFAULT_APP_SLUG", "default")
_apps_cache_last_refresh = 0.0
_APPS_CACHE_TTL = float(os.environ.get("APPS_CACHE_TTL", "30"))
DEFAULT_APP_SLUG = default_app_slug


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


def _build_apps_cache(app_rows, domain_rows) -> Dict[str, Any]:
    """Construye la caché de apps a partir de filas de DB.

    Revalida backend_url y descarta (con log) las filas inválidas sin
    tumbar el engine. Función pura: no toca globals.
    """
    apps: Dict[str, Dict[str, Any]] = {}
    by_slug: Dict[str, Dict[str, Any]] = {}
    by_domain: Dict[str, Dict[str, Any]] = {}
    default_id: Optional[str] = None

    for row in app_rows:
        app_id = str(_row_get(row, "id", "") or "")
        slug = str(_row_get(row, "slug", "") or "").strip().lower()
        if not app_id or not slug:
            print(f"⚠️ apps_cache: fila sin id/slug descartada: {row!r}")
            continue
        try:
            target = parse_backend_url(_row_get(row, "backend_url"))
        except UnsafeBackendError as exc:
            print(f"⚠️ apps_cache: app '{slug}' descartada: {exc}")
            continue

        legacy_domain = normalize_cache_domain(_row_get(row, "domain"))
        app_info = {
            "id": app_id,
            "slug": slug,
            "domain": legacy_domain,
            "domains": [legacy_domain] if legacy_domain else [],
            "backend_url": target.to_url(),
            "enabled": bool(_row_get(row, "enabled", False)),
        }
        apps[app_id] = app_info
        by_slug[slug] = app_info
        if legacy_domain and legacy_domain not in by_domain:
            by_domain[legacy_domain] = app_info

    for row in domain_rows:
        app_id = str(_row_get(row, "app_id", "") or "")
        app_info = apps.get(app_id)
        if not app_info:
            continue
        domain = normalize_cache_domain(_row_get(row, "domain"))
        if not domain:
            print(f"⚠️ apps_cache: dominio inválido descartado para app '{app_info['slug']}'")
            continue
        existing = by_domain.get(domain)
        if existing and existing["id"] != app_id:
            print(
                f"⚠️ apps_cache: dominio '{domain}' ya asignado a "
                f"'{existing['slug']}'; se ignora para '{app_info['slug']}'"
            )
            continue
        by_domain[domain] = app_info
        if domain not in app_info["domains"]:
            app_info["domains"].append(domain)

    default_app = by_slug.get(DEFAULT_APP_SLUG)
    if default_app and default_app["enabled"]:
        default_id = default_app["id"]
    else:
        for slug in sorted(by_slug):
            candidate = by_slug[slug]
            if candidate["enabled"]:
                default_id = candidate["id"]
                break

    return {
        "apps": apps,
        "by_slug": by_slug,
        "by_domain": by_domain,
        "default_app_id": default_id,
    }


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
        # Cargar cache de apps ANTES de aceptar requests (bloqueante)
        await load_apps_cache(force=True)
        # Lanzar refresh periódico
        asyncio.create_task(refresh_apps_cache_loop())
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



async def load_apps_cache(force: bool = False) -> bool:
    global apps_cache, apps_by_slug, apps_by_domain, default_app_id, _apps_cache_last_refresh
    if not db_pool:
        return False
    now = time.time()
    if not force and _apps_cache_last_refresh and (now - _apps_cache_last_refresh) < _APPS_CACHE_TTL:
        return True
    try:
        async with db_pool.acquire() as conn:
            app_rows = await conn.fetch(
                "SELECT id::text AS id, slug, domain, backend_url, enabled FROM waf_apps"
            )
            try:
                domain_rows = await conn.fetch(
                    "SELECT app_id::text AS app_id, domain FROM waf_app_domains"
                )
            except Exception as domain_err:
                print(
                    f"⚠️ apps_cache: waf_app_domains no disponible ({domain_err}); "
                    "se usa sólo waf_apps.domain"
                )
                domain_rows = []

        built = _build_apps_cache(app_rows, domain_rows)
        # No reemplazar una caché válida por una vacía o sin default: si la DB
        # quedó mal, se conserva la última buena y /reload_apps devuelve 503.
        if not built["apps"] or not built["default_app_id"]:
            if apps_cache and default_app_id:
                print(
                    "⚠️ apps_cache: nueva caché vacía o sin app default; "
                    "se conserva la última caché válida"
                )
            else:
                print(
                    "⚠️ apps_cache: sin apps o sin app default habilitada; "
                    "los requests responderán 503 hasta corregir la DB"
                )
            return False
        # Reemplazar dicts completos (sin mutación in-place)
        apps_cache = built["apps"]
        apps_by_slug = built["by_slug"]
        apps_by_domain = built["by_domain"]
        default_app_id = built["default_app_id"]
        _apps_cache_last_refresh = time.time()
        if default_app_id:
            print(
                f"✅ apps_cache cargado: {len(apps_cache)} apps, "
                f"{len(apps_by_domain)} dominios, default_app_id={default_app_id}"
            )
        else:
            print(f"✅ apps_cache cargado: {len(apps_cache)} apps, sin app default habilitada")
        return True
    except Exception as e:
        print(f"⚠️ Error cargando apps_cache: {e}")
        # Mantener cache anterior si falla
        return False

async def refresh_apps_cache_loop() -> None:
    while True:
        try:
            await asyncio.sleep(_APPS_CACHE_TTL)
            await load_apps_cache(force=True)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"⚠️ Error en refresh_apps_cache_loop: {e}")
            await asyncio.sleep(5)

def lookup_app_by_host(host: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Devuelve (app, estado) con estado ok|disabled|unknown."""
    normalized = normalize_host(host)
    if not normalized:
        return None, "unknown"
    app = apps_by_domain.get(normalized)
    if not app:
        return None, "unknown"
    if not app.get("enabled"):
        return app, "disabled"
    return app, "ok"


def resolve_app_by_host(host: str) -> Optional[Dict[str, Any]]:
    """Devuelve sólo apps habilitadas mapeadas por dominio."""
    app, status = lookup_app_by_host(host)
    return app if status == "ok" else None


def _default_enabled_app() -> Dict[str, Any]:
    """Devuelve la app default habilitada o levanta NoDefaultAppError."""
    if default_app_id and default_app_id in apps_cache:
        candidate = apps_cache[default_app_id]
        if candidate.get("enabled"):
            return candidate
    for candidate in apps_cache.values():
        if candidate.get("enabled"):
            return candidate
    raise NoDefaultAppError("no hay app default habilitada")


def resolve_request_app(
    host: str,
    compat_slug: Optional[str] = None,
    allow_compat: Optional[bool] = None,
) -> Dict[str, Any]:
    """Resuelve la app de un request.

    Orden: Host registrado -> (sólo development) X-App-Slug -> WAF_DOMAIN
    -> fallback explícito. Una app deshabilitada levanta DisabledAppError
    (403); un Host desconocido levanta UnknownHostError (421) salvo que sea
    WAF_DOMAIN o que WAF_UNKNOWN_HOST_FALLBACK esté activo.
    """
    if allow_compat is None:
        allow_compat = IS_DEVELOPMENT

    normalized = normalize_host(host)
    app, status = lookup_app_by_host(normalized)
    if status == "ok":
        return app
    if status == "disabled":
        raise DisabledAppError(app)

    if allow_compat and compat_slug:
        slug = str(compat_slug).strip().lower()
        candidate = apps_by_slug.get(slug)
        if candidate:
            if candidate.get("enabled"):
                return candidate
            raise DisabledAppError(candidate)

    if normalized and WAF_DOMAIN and normalized == WAF_DOMAIN:
        return _default_enabled_app()

    if UNKNOWN_HOST_FALLBACK:
        print(
            f"⚠️ Host desconocido {normalized!r}: "
            "WAF_UNKNOWN_HOST_FALLBACK activo, usando app default"
        )
        return _default_enabled_app()

    raise UnknownHostError(normalized)


# ══════════════════════════════════════════════════════════════════
# 5. ENDPOINT PRINCIPAL (TRES ZONAS)
# ══════════════════════════════════════════════════════════════════

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def waf_core(request: Request, path_name: str):
    start_time = time.time()
    
    original_url = request.headers.get("x-original-uri", "")
    original_method = request.headers.get("x-original-method", request.method)

    # Resolver app por Host (dominio registrado en waf_apps/waf_app_domains).
    # X-Forwarded-Host NO se usa: sólo el Host real del request. En desarrollo
    # se acepta X-App-Slug como compatibilidad; en producción sólo vale Host.
    request_host = request.headers.get("host", "")
    compat_slug = request.headers.get("x-app-slug") or request.headers.get("x-app-id")
    try:
        resolved_app = resolve_request_app(request_host, compat_slug)
    except DisabledAppError as disabled:
        print(f"⛔ App deshabilitada para host={request_host!r}: {disabled.app.get('slug')}")
        return JSONResponse(
            status_code=403,
            content={"detail": "App disabled"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": "0.0"},
        )
    except UnknownHostError as unknown:
        print(f"⛔ Host desconocido: {unknown.host!r}")
        return JSONResponse(
            status_code=421,
            content={"detail": "Misdirected Request: unknown host"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": "0.0"},
        )
    except NoDefaultAppError as no_default:
        print(f"⛔ Sin app default habilitada: {no_default}")
        return JSONResponse(
            status_code=503,
            content={"detail": "App registry unavailable"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": "0.0"},
        )
    except Exception as app_err:
        print(f"⛔ Error resolviendo app: {app_err}")
        return JSONResponse(
            status_code=503,
            content={"detail": "App registry unavailable"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": "0.0"},
        )

    app_id_resolved = resolved_app["id"]

    # Fallback si no viene el header (benchmark directo sin nginx)
    if not original_url:
        original_url = request.url.path
        if request.url.query:
            original_url += "?" + request.url.query

    client_ip     = request.headers.get("x-real-ip", request.client.host)
    is_auth_endpoint = request.url.path.startswith("/api/auth/callback/credentials")

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
        if is_auth_endpoint:
            score = 0.05
            print("⚡ Auth callback — permitido sin scoring ML")
        elif _should_use_fast_path(original_method, f_dict):
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
        if is_auth_endpoint:
            score = 0.05
            print("⚡ Auth callback — permitido sin scoring ML (timeout handler)")
        elif _should_use_fast_path(request.method, f_dict):
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
            f_dict,
            app_id_resolved
        ))

    if action == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={"detail": "Blocked by Hybrid WAF"},
            headers={"X-WAF-Action": "BLOCK", "X-WAF-Score": str(round(float(score), 4))},
        )

    # ── Proxy al backend ──────────────────────────────────────────
    # Si es ALLOW o LOG, reenviar la request al backend real.
    # Sólo se proxya al backend_url exacto de la app resuelta. En producción
    # X-Backend se ignora; en desarrollo queda como compatibilidad legacy.
    backend_url = None
    if resolved_app is not None:
        backend_url = resolved_app["backend_url"]
    elif IS_DEVELOPMENT:
        legacy_backend = _normalize_backend(request.headers.get("X-Backend", DEFAULT_BACKEND))
        if legacy_backend:
            if legacy_backend not in BACKEND_ALLOWLIST:
                print(f"⚠️ X-Backend rechazado por allowlist: {legacy_backend}")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden backend"},
                    headers={"X-WAF-Action": action, "X-WAF-Score": str(round(float(score), 4))},
                )
            backend_url = legacy_backend

    if backend_url:
        try:
            # Resolver DNS en cada request y fijar la IP (anti DNS rebinding).
            pinned = await asyncio.to_thread(
                resolve_backend_connection,
                backend_url,
                path_name,
                request.url.query,
            )
        except UnsafeBackendError as unsafe_err:
            print(f"⚠️ Backend rechazado en conexión: {unsafe_err}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden backend"},
                headers={"X-WAF-Action": action, "X-WAF-Score": str(round(float(score), 4))},
            )

        try:
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

            request_extensions = {}
            if pinned.sni_hostname:
                request_extensions["sni_hostname"] = pinned.sni_hostname

            async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
                backend_resp = await client.request(
                    method=request.method,
                    url=pinned.url,
                    headers=forward_headers,
                    content=body_bytes,
                    follow_redirects=False,
                    extensions=request_extensions or None,
                )

            # Preservar headers duplicados (Set-Cookie) y quitar hop-by-hop
            hop_by_hop = {
                "content-length", "content-encoding", "transfer-encoding",
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "upgrade",
            }
            resp_header_list = [
                (k, v)
                for k, v in backend_resp.headers.multi_items()
                if k.lower() not in hop_by_hop
            ]

            # Reescribir Location si apunta al hostname interno del backend
            external_host = request.headers.get("host", "localhost")
            scheme = request.headers.get("x-forwarded-proto", "http")
            backend_host = backend_url.rstrip("/")

            resp_header_list = [
                (
                    k,
                    v.replace(backend_host, f"{scheme}://{external_host}")
                    if k.lower() == "location" and backend_host in v
                    else v,
                )
                for k, v in resp_header_list
            ]

            resp_header_list.append(("X-WAF-Action", action))
            resp_header_list.append(("X-WAF-Score", str(round(float(score), 4))))
            resp_headers = Headers(
                raw=[
                    (k.lower().encode("latin-1"), v.encode("latin-1"))
                    for k, v in resp_header_list
                ]
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


async def save_to_db(client_ip: str, user_agent: str, method: str, url_inspect: str, payload: str, score: float, verdict: int, action: str, latency: float, f_dict: dict, app_id: str):
    # Validamos que el pool de conexiones exista antes de intentar usarlo
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO waf_events (
                        app_id,
                        ip_origen, user_agent, metodo_http, url, payload,
                        url_length, payload_length, special_char_count, shannon_entropy,
                        score_ml, veredicto, accion, tiempo_inferencia_ms,
                        features_json, cwe_family, waf_version
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                ''', 
                app_id,
                client_ip, 
                user_agent,
                method, 
                url_inspect,
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
                f_dict.get('cwe_family'),  # cwe_family desde features (None = legítimo)
                MODEL_VERSION)
        except Exception as db_e:
            print(f"⚠️ Error al guardar en DB: {db_e}")
