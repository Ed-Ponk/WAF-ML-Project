#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# bootstrap-admin.sh — Crea el administrador inicial del WAF-ML.
#
# - Corre SOLO una vez (si 'admin' ya existe en waf_users, no hace nada).
# - Genera una contraseña aleatoria segura (openssl).
# - La hashea con bcrypt (cost 10, prefijo $2b$) usando bcryptjs en un
#   contenedor EFIMERO node:18-alpine, sin depender de los node_modules
#   de la imagen de producción del dashboard.
# - La contraseña se escribe en un archivo con permisos 600 (umask 077)
#   en ADMIN_CREDS_FILE (default ./secrets/admin_password). stdout solo
#   informa la ruta: la contraseña nunca sale por stdout ni queda en logs.
#
# ¿Por qué efímero? El Dockerfile del dashboard usa `output: standalone`
# de Next.js. bcryptjs queda EMBEBIDO en el bundle webpack del route
# /api/auth (la app loguea bien), pero NO existe como módulo instalado
# en .next/standalone/node_modules, así que `node -e "require('bcryptjs')"`
# falla dentro del contenedor. Hashear en un contenedor desechable hace
# el script robusto ante cualquier imagen.
#
# Uso:
#   scripts/bootstrap-admin.sh
#   ADMIN_CREDS_FILE=/ruta/segura scripts/bootstrap-admin.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

DB_CONTAINER="${DB_CONTAINER:-waf-db}"
DB_USER="${DB_USER:-waf_user}"
DB_NAME="${DB_NAME:-waf_db}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_CREDS_FILE="${ADMIN_CREDS_FILE:-${PROJECT_DIR}/secrets/admin_password}"
NODE_HASH_IMAGE="${NODE_HASH_IMAGE:-node:18-alpine}"

# .env del proyecto: los valores del archivo tienen precedencia sobre los
# defaults (mismo comportamiento que el docker-compose).
if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

# ── Preflight: la DB debe estar alcanzable ─────────────────────────
if ! docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT 1" >/dev/null 2>&1; then
  echo "[bootstrap-admin] ERROR: no puedo consultar '${DB_NAME}' en '${DB_CONTAINER}'. ¿Está levantado el stack?" >&2
  exit 1
fi

# ── Guard idempotente ──────────────────────────────────────────────
EXISTS="$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" \
  -tAc "SELECT count(*) FROM waf_users WHERE username='${ADMIN_USERNAME}'")"

if [ "$EXISTS" != "0" ]; then
  echo "[bootstrap-admin] El usuario '${ADMIN_USERNAME}' ya existe. Nada que hacer."
  exit 0
fi

# ── Contraseña aleatoria ───────────────────────────────────────────
# Solo alfanumérica para evitar problemas de quoting en SQL y JSON.
ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -cd '[:alnum:]' | head -c 20)"

# ── Hash bcrypt (cost 10, prefijo $2b$) en contenedor efímero ─────
# bcryptjs genera $2a$ por defecto; lo re-escribimos a $2b$ (mismo
# algoritmo para contraseñas ASCII sin NUL). El login del dashboard usa
# bcryptjs.compare(), que acepta $2a$/$2b$/$2y$ — por eso verifica igual.
# Self-check interno: generamos, convertimos y comparamos antes de salir.
HASH="$(docker run --rm -i \
  -e PASSWORD_TO_HASH="$ADMIN_PASSWORD" \
  "$NODE_HASH_IMAGE" \
  sh -c 'mkdir -p /tmp/hash && cd /tmp/hash && npm install --no-save --no-audit --no-fund --silent bcryptjs >/dev/null 2>&1 && node -' \
  <<'NODE'
const bcrypt = require("bcryptjs");
const password = process.env.PASSWORD_TO_HASH;
let hash = bcrypt.hashSync(password, 10);
if (hash.slice(0, 4) === "$2a$") {
  hash = "$2b$" + hash.slice(3);
}
if (!bcrypt.compareSync(password, hash)) {
  console.error("[bootstrap-admin] self-check de hash falló");
  process.exit(1);
}
process.stdout.write(hash);
NODE
)"

# ── Insert del admin ───────────────────────────────────────────────
SQL="$(printf "INSERT INTO waf_users (username, password_hash, role) VALUES ('%s', '%s', 'admin') ON CONFLICT (username) DO NOTHING" "$ADMIN_USERNAME" "$HASH")"
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "$SQL" >/dev/null

# ── Guardado seguro de credenciales ────────────────────────────────
# umask 077 garantiza 600 al crear el archivo; chmod lo hace explícito
# aunque el archivo ya existiera con permisos más abiertos.
mkdir -p "$(dirname "$ADMIN_CREDS_FILE")"
{
  echo "usuario=${ADMIN_USERNAME}"
  echo "contrasena=${ADMIN_PASSWORD}"
  echo "generado=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$ADMIN_CREDS_FILE"
chmod 600 "$ADMIN_CREDS_FILE"

echo ""
echo "[bootstrap-admin] ✓ Administrador inicial creado."
echo "[bootstrap-admin] Credenciales guardadas en: ${ADMIN_CREDS_FILE}"
echo "[bootstrap-admin] (permisos 600 — no se imprimen por stdout)"
echo "[bootstrap-admin] Borrá ese archivo cuando hayas guardado la contraseña."
echo ""