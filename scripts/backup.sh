#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# backup.sh — Backup comprimido de las bases del WAF-ML.
#
# - waf_db (PostgreSQL, telemetría/WAF)  → backups/waf-db-<ts>.sql.gz
# - bd_atel (MySQL, PYME backend)        → backups/pyme-db-<ts>.sql.gz
# - Rotación: conserva las últimas N copias (BACKUP_KEEP, default 7).
#
# Uso:   scripts/backup.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_DIR}/backups}"
BACKUP_KEEP="${BACKUP_KEEP:-7}"
DB_CONTAINER="${DB_CONTAINER:-waf-db}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-waf-pyme-db}"
DB_USER="${DB_USER:-waf_user}"
DB_NAME="${DB_NAME:-waf_db}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-}"

if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

mkdir -p "$BACKUP_DIR"
TS="$(date +%Y%m%d-%H%M%S)"

backup_postgres() {
  local out="$BACKUP_DIR/waf-db-${TS}.sql.gz"
  echo "[backup] PostgreSQL → ${out}"
  docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$out"
}

backup_mysql() {
  if [ -n "$MYSQL_ROOT_PASSWORD" ]; then
    local out="$BACKUP_DIR/pyme-db-${TS}.sql.gz"
    echo "[backup] MySQL → ${out}"
    docker exec -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD" "$MYSQL_CONTAINER" sh -c \
      'exec mysqldump --no-tablespaces -uroot -p"$MYSQL_ROOT_PASSWORD" bd_atel' 2>/dev/null | gzip > "$out"
  else
    echo "[backup] MYSQL_ROOT_PASSWORD no definido; se omite el backup de la BD PYME."
  fi
}

prune() {
  local pattern="$1"
  ls -1t "$BACKUP_DIR"/$pattern 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)) | while read -r f; do
    echo "[backup] Poda: ${f}"
    rm -f "$f"
  done
}

backup_postgres
backup_mysql
prune 'waf-db-*.sql.gz'
prune 'pyme-db-*.sql.gz'

echo "[backup] Listo. Contenido de ${BACKUP_DIR}:"
ls -lah "$BACKUP_DIR"