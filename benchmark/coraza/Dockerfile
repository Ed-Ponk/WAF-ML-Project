# ══════════════════════════════════════════════════════════════════
# Dockerfile — Coraza WAF + Caddy
#
# Construye Caddy con el módulo coraza-caddy usando xcaddy.
# Incluye OWASP CRS embebido a través de coraza-coreruleset.
# ══════════════════════════════════════════════════════════════════

FROM caddy:builder-alpine AS builder

# Build Caddy with coraza-caddy module (includes OWASP CRS support)
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

# ── Imagen final ─────────────────────────────────────────────────
FROM caddy:alpine

# CRS configuration files from coraza-coreruleset are embedded in the binary
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 80

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
