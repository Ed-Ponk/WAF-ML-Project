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
RUN apk add --no-cache openssl

# Script de generación zero-touch de certificados TLS
COPY generate_certs.sh /generate_certs.sh
RUN chmod +x /generate_certs.sh

# Configuración personalizada de Nginx
COPY default.conf /etc/nginx/conf.d/default.conf

# Páginas de error
COPY 403.html /usr/share/nginx/html/403.html

# Entrypoint personalizado: genera certificados si es necesario,
# luego arranca Nginx. El CMD original se pasa como "$@".
ENTRYPOINT ["/generate_certs.sh"]
CMD ["nginx", "-g", "daemon off;"]
