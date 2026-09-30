#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# bootstrap-admin.sh — Crea el administrador inicial del WAF-ML.
#
# - Corre SOLO una vez (si 'admin' ya existe en waf_users, no hace nada).
# - Genera una contraseña aleatoria segura (openssl).
# - La hashea con bcrypt (cost 10) usando bcryptjs del contenedor
#   del dashboard (sin dependencias en el host).
# - La contraseña se escribe en un archivo con permisos 600 (umask 077)
#   en ADMIN_CREDS_FILE (default ./secrets/admin_password). stdout solo
#   informa la ruta: la contraseña nunca sale por stdout ni queda en logs.
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
DASHBOARD_CONTAINER="${DASHBOARD_CONTAINER:-waf-dashboard}"
DB_USER="${DB_USER:-waf_user}"
DB_NAME="${DB_NAME:-waf_db}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_CREDS_FILE="${ADMIN_CREDS_FILE:-${PROJECT_DIR}/secrets/admin_password}"

if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

EXISTS="$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" \
  -tAc "SELECT count(*) FROM waf_users WHERE username='${ADMIN_USERNAME}'")"

if [ "$EXISTS" != "0" ]; then
  echo "[bootstrap-admin] El usuario '${ADMIN_USERNAME}' ya existe. Nada que hacer."
  exit 0
fi

if ! docker exec "$DASHBOARD_CONTAINER" node -e "process.exit(0)" >/dev/null 2>&1; then
  echo "[bootstrap-admin] ERROR: el contenedor ${DASHBOARD_CONTAINER} no está corriendo (no puedo hashear con bcryptjs)." >&2
  exit 1
fi

# Contraseña aleatoria: solo alfanumérica para evitar problemas de quoting.
ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -cd '[:alnum:]' | head -c 20)"

HASH="$(docker exec "$DASHBOARD_CONTAINER" node \
  -e "console.log(require('bcryptjs').hashSync(process.argv[1], 10))" "$ADMIN_PASSWORD")"

SQL="$(printf "INSERT INTO waf_users (username, password_hash, role) VALUES ('%s', '%s', 'admin') ON CONFLICT (username) DO NOTHING" "$ADMIN_USERNAME" "$HASH")"
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "$SQL" >/dev/null

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