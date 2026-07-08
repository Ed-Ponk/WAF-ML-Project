# ══════════════════════════════════════════════════════════════════
# Dockerfile — NAXSI (nginx + naxsi module)
#
# Construye nginx con el módulo NAXSI desde fuente,
# usando multi-stage build para mantener la imagen final pequeña.
#
# NAXSI es un WAF de código abierto que analiza las solicitudes
# HTTP usando un sistema de reglas (firmas) basado en puntuación.
# ══════════════════════════════════════════════════════════════════

ARG NGINX_VERSION=1.26.0

# ── Stage 1: Build nginx + naxsi static module ────────────────
FROM alpine:3.19 AS builder

ARG NGINX_VERSION

RUN apk add --no-cache \
    build-base \
    git \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    linux-headers \
    wget

# Descargar fuente de nginx
RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz

# Clonar NAXSI (tag 0.44)
RUN git clone --depth 1 --branch 0.44 https://github.com/nbs-system/naxsi.git /tmp/naxsi

# Parche: NAXSI usa `regex->pcre` pero nginx 1.24+ lo renombró a `regex->code`
RUN sed -i 's/regex->pcre/regex->code/g' /tmp/naxsi/naxsi_src/naxsi_runtime.c

# Compilar nginx completo + módulo dinámico NAXSI
WORKDIR /nginx-${NGINX_VERSION}
RUN ./configure \
    --with-compat \
    --without-pcre2 \
    --with-http_ssl_module \
    --add-module=/tmp/naxsi/naxsi_src \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --with-http_stub_status_module \
    --with-threads \
    --with-file-aio

# Build full nginx (includes dynamic modules)
RUN make -j$(nproc)

# ── Stage 2: Imagen final ───────────────────────────────────────
FROM nginx:${NGINX_VERSION}-alpine

ARG NGINX_VERSION

# PCRE v1 para el binario compilado con NAXSI
RUN apk add --no-cache pcre

# Copiar nginx con NAXSI compilado estáticamente
COPY --from=builder /nginx-${NGINX_VERSION}/objs/nginx /usr/sbin/nginx

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD nginx -t || exit 1
