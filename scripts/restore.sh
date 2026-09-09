#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# restore.sh — Restaura un backup de PostgreSQL del WAF-ML.
#
# Uso:
#   scripts/restore.sh                    # restaura el backup más reciente
#   scripts/restore.sh backups/waf-db-YYYYMMDD-HHMMSS.sql.gz
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
DB_CONTAINER="${DB_CONTAINER:-waf-db}"
DB_USER="${DB_USER:-waf_user}"
DB_NAME="${DB_NAME:-waf_db}"

if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  TARGET="$(ls -1t "$BACKUP_DIR"/waf-db-*.sql.gz 2>/dev/null | head -n1)"
fi

if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
  echo "[restore] ERROR: no se encontró ningún backup. Uso: scripts/restore.sh [archivo.sql.gz]" >&2
  exit 1
fi

echo "[restore] Archivo: ${TARGET}"
echo "[restore] ⚠️  Esto SOBRESCRIBE la base '${DB_NAME}' del contenedor ${DB_CONTAINER}."
read -r -p "[restore] ¿Continuar? [s/N] " CONFIRM
if [ "$CONFIRM" != "s" ] && [ "$CONFIRM" != "S" ]; then
  echo "[restore] Cancelado."
  exit 0
fi

echo "[restore] Volcando backup en la base (a través de psql)..."
gunzip -c "$TARGET" | docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" >/dev/null
echo "[restore] ✓ Restauración completada."