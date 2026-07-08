#!/bin/sh
# ══════════════════════════════════════════════════════════════════
# generate_certs.sh — Generación Zero-Touch de certificados TLS
#                      para el proxy reverso Nginx (WAF-ML).
#
# Comportamiento:
#   - Verifica si /etc/nginx/certs/waf.{crt,key} existen.
#   - Si faltan, genera un certificado autofirmado vía OpenSSL
#     en modo NO INTERACTIVO (-subj), sin intervención humana.
#   - Si OpenSSL falla, loguea el error y permite degradación
#     segura (el contenedor reintentará al reiniciar).
#   - Finaliza con exec para delegar al comando original de Nginx.
# ══════════════════════════════════════════════════════════════════

set -e

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

# ── Delegar a Nginx (o al comando que sea) ─────────────────────
exec "$@"
