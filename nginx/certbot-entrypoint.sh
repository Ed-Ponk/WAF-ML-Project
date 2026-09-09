#!/bin/sh
# ══════════════════════════════════════════════════════════════════
# certbot-entrypoint.sh — Sidecar Let's Encrypt (HTTP-01 + webroot).
#
# - Sin ACME_PRIMARY_DOMAIN → modo dev: hace idle (el proxy usa
#   certificados autofirmados de ./certs).
# - Con ACME_PRIMARY_DOMAIN:
#     1. Solicita el certificado si no existe (--keep-until-expiring).
#     2. Loop de renovación cada 12h; el cron del proxy hace el reload.
#
# ACME_EXTRA_DOMAINS opcional: "sub2.example.com sub3.example.com"
# (se lo pasan a certbot como -d adicionales, separados por espacio).
# ══════════════════════════════════════════════════════════════════
set -eu

if [ -z "${ACME_PRIMARY_DOMAIN:-}" ]; then
    echo "[certbot] ACME_PRIMARY_DOMAIN sin definir — modo dev (idle). Se usan autofirmados."
    exec tail -f /dev/null
fi

if [ ! -f "/etc/letsencrypt/live/${ACME_PRIMARY_DOMAIN}/fullchain.pem" ]; then
    : "${ACME_EMAIL:?ACME_EMAIL requerido para solicitar el certificado}"
    echo "[certbot] Solicitando certificado para ${ACME_PRIMARY_DOMAIN} ${ACME_EXTRA_DOMAINS:-}"
    certbot certonly --webroot -w /var/www/certbot \
        --non-interactive --agree-tos --email "${ACME_EMAIL}" \
        -d "${ACME_PRIMARY_DOMAIN}" \
        ${ACME_EXTRA_DOMAINS:+-d ${ACME_EXTRA_DOMAINS}} \
        --keep-until-expiring
else
    echo "[certbot] Certificado existente para ${ACME_PRIMARY_DOMAIN}; pasando a renovación."
fi

echo "[certbot] Iniciando loop de renovación (cada 12h)..."
while :; do
    sleep 12h
    certbot renew --webroot -w /var/www/certbot --non-interactive --quiet || true
done