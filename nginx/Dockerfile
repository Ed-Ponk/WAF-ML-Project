# ══════════════════════════════════════════════════════════════════
# Dockerfile — Proxy Reverso Nginx (Capa 1 del WAF-ML)
#
# Incluye:
#   - TLS termination (certificados autofirmados en dev)
#   - Proxy inverso hacia WAF Engine (FastAPI) y backend PYME
# ══════════════════════════════════════════════════════════════════

FROM nginx:alpine

# Eliminamos la configuración por defecto para que no choque con la tuya
RUN rm /etc/nginx/conf.d/default.conf

# OpenSSL NO viene incluido en nginx:alpine (solo las librerías compartidas).
# Instalamos explícitamente el binario openssl para la generación zero-touch de certificados.
# gettext → envsubst (renderiza default.conf.template con DOMAIN/certs).
# dcron → reload diario del nginx para refrescar certificados Let's Encrypt renovados.
RUN apk add --no-cache openssl gettext dcron

# Script de generación zero-touch de certificados TLS
COPY generate_certs.sh /generate_certs.sh
RUN chmod +x /generate_certs.sh

# Reload periódico (certificados renovados por el sidecar certbot).
# HUP = recarga limpia de config; seguro aunque no haya cambios.
RUN echo "0 3 * * * [ -f /var/run/nginx.pid ] && kill -HUP \$(cat /var/run/nginx.pid) > /dev/null 2>&1" \
    > /etc/crontabs/root

# Configuración personalizada de Nginx (template renderizado por generate_certs.sh)
COPY default.conf.template /etc/nginx/conf.d/default.conf.template

# Páginas de error
COPY 403.html /usr/share/nginx/html/403.html

# Entrypoint personalizado: genera certificados si es necesario,
# luego arranca Nginx. El CMD original se pasa como "$@".
ENTRYPOINT ["/generate_certs.sh"]
CMD ["nginx", "-g", "daemon off;"]
