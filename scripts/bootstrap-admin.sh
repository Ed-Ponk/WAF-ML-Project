#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# bootstrap-admin.sh — Crea el administrador inicial del WAF-ML.
#
# - Corre SOLO una vez (si 'admin' ya existe en waf_users, no hace nada).
# - Genera una contraseña aleatoria segura (openssl).
# - La hashea con bcrypt (cost 10) usando bcryptjs del contenedor
#   del dashboard (sin dependencias en el host).
# - La imprime UNA sola vez por stdout (queda en los logs del deploy).
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-waf-db}"
DASHBOARD_CONTAINER="${DASHBOARD_CONTAINER:-waf-dashboard}"
DB_USER="${DB_USER:-waf_user}"
DB_NAME="${DB_NAME:-waf_db}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

if [ -f "$(dirname "$0")/../.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$(dirname "$0")/../.env"
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

echo ""
echo "──────────────────────────────────────────────────────────────"
echo "  ADMINISTRADOR INICIAL CREADO — guardá estas credenciales"
echo "  (no se volverán a imprimir)"
echo ""
echo "    usuario:   ${ADMIN_USERNAME}"
echo "    contraseña: ${ADMIN_PASSWORD}"
echo "──────────────────────────────────────────────────────────────"
echo ""