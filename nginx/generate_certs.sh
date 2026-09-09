#!/bin/sh
# ══════════════════════════════════════════════════════════════════
# generate_certs.sh — Generación Zero-Touch de certificados TLS
#                      para el proxy reverso Nginx (WAF-ML).
#
# Comportamiento:
#   - Renderiza default.conf.template → default.conf (envsubst).
#   - Verifica si /etc/nginx/certs/waf.{crt,key} existen.
#   - Si faltan, genera un certificado autofirmado vía OpenSSL
#     en modo NO INTERACTIVO (-subj), sin intervención humana.
#   - Si OpenSSL falla, loguea el error y permite degradación
#     segura (el contenedor reintentará al reiniciar).
#   - Arranca crond (reload periódico tras renovación de certs).
#   - Finaliza con exec para delegar al comando original de Nginx.
# ══════════════════════════════════════════════════════════════════

set -e

# ── Valores por defecto para el template (dev = autofirmado) ─────
# export obligatorio: envsubst es un proceso hijo y solo ve variables
# de entorno exportadas (un default local sin export no llega).
: "${WAF_DOMAIN:=localhost}"
: "${PYME_DOMAIN:=pyme.waf.local}"
: "${ADMIN_DOMAIN:=admin.waf.local}"
: "${CERT_PATH:=/etc/nginx/certs/waf.crt}"
: "${KEY_PATH:=/etc/nginx/certs/waf.key}"
export WAF_DOMAIN PYME_DOMAIN ADMIN_DOMAIN CERT_PATH KEY_PATH

# ── Renderizar la config de Nginx (solo estas vars; las $punteras
#    de nginx como $host/$scheme se preservan) ────────────────────
TEMPLATE_FILE="/etc/nginx/conf.d/default.conf.template"
CONF_FILE="/etc/nginx/conf.d/default.conf"
if [ -f "$TEMPLATE_FILE" ]; then
    echo "[WAF] 📄 Renderizando ${TEMPLATE_FILE} → ${CONF_FILE}"
    envsubst '${WAF_DOMAIN} ${PYME_DOMAIN} ${ADMIN_DOMAIN} ${CERT_PATH} ${KEY_PATH}' \
        < "$TEMPLATE_FILE" > "$CONF_FILE"
else
    echo "[WAF] ⚠️  No se encontró ${TEMPLATE_FILE}; se usa ${CONF_FILE} si existe." >&2
fi

CERTS_DIR="${CERTS_DIR:-/etc/nginx/certs}"
CERT_FILE="${CERTS_DIR}/waf.crt"
KEY_FILE="${CERTS_DIR}/waf.key"
OPENSSL_ERR_LOG="/tmp/openssl_err.log"

# ── Asegurar que el directorio de certificados exista ──────────
mkdir -p "$CERTS_DIR"

# ── Verificar si los certificados ya existen ────────────────────
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[WAF] ✅ Certificados TLS encontrados en ${CERTS_DIR}"
else
    echo "[WAF] 🔑 No se encontraron certificados TLS. Generando certificado autofirmado..."

    # Generación NO INTERACTIVA — flag -subj evita cualquier prompt
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/CN=localhost/O=WAF-Dev/C=PE" \
        2>"$OPENSSL_ERR_LOG"

    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
        echo "[WAF] ❌ ERROR: Falló la generación del certificado SSL (código: ${EXIT_CODE})" >&2
        echo "[WAF] ❌ Detalles del error:" >&2
        cat "$OPENSSL_ERR_LOG" >&2
        echo "[WAF] ⚠️  Degradación segura: el contenedor se reiniciará e intentará de nuevo." >&2
        echo "[WAF] ⚠️  Mientras tanto, el puerto 80 (HTTP plano) sigue operativo." >&2
        exit 1
    fi

    # Permisos estrictos: clave privada solo lectura para el owner
    chmod 644 "$CERT_FILE"
    chmod 600 "$KEY_FILE"

    echo "[WAF] ✅ Certificados TLS generados correctamente en ${CERTS_DIR}"
    echo "[WAF]    - Certificado: ${CERT_FILE}"
    echo "[WAF]    - Clave:       ${KEY_FILE}"
    echo "[WAF]    - Válido por:  365 días"
    echo "[WAF]    - Sujeto:      /CN=localhost/O=WAF-Dev/C=PE"
fi

# ── Verificación POST-mortem de los archivos ────────────────────
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "[WAF] ❌ ERROR CRÍTICO: Los archivos de certificado no existen después de la generación." >&2
    echo "[WAF]    Esperado: ${CERT_FILE} y ${KEY_FILE}" >&2
    echo "[WAF] ⚠️  Degradación: el contenedor continuará SIN SSL en este intento." >&2
    # No salimos con error para evitar crash loop; Nginx arrancará en
    # modo degradado (solo HTTP). La próxima vez que el contenedor
    # se reinicie, reintentará la generación.
fi

# ── Arrancar cron en segundo plano (reload tras renovación ACME) ─
if command -v crond >/dev/null 2>&1; then
    crond -b -l 2 2>/dev/null || true
fi

# ── Delegar a Nginx (o al comando que sea) ─────────────────────
exec "$@"
