#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# backup.sh — Backup comprimido de las bases del WAF-ML.
#
# - waf_db (PostgreSQL, telemetría/WAF)  → backups/waf-db-<ts>.sql.gz
# - bd_atel (MySQL, PYME backend)        → backups/pyme-db-<ts>.sql.gz
# - Rotación: conserva las últimas N copias (BACKUP_KEEP, default 7).
#
# Cada dump se escribe primero a <archivo>.partial y solo se publica con
# mv cuando el comando terminó bien, el .gz pasa gzip -t y el contenido
# tiene la línea de cierre del dump. Un .partial nunca cuenta como copia
# válida ni entra en la poda.
#
# La contraseña de MySQL viaja por MYSQL_PWD (entorno) y nunca por -p,
# para no quedar expuesta en la lista de argumentos del proceso.
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

# Valida <archivo>.partial y lo publica con mv solo si el dump está
# completo. Elimina el .partial ante cualquier fallo.
finalize_dump() {
  local partial="$1" out="$2" sentinel="$3" cola
  if ! gzip -t "$partial"; then
    echo "[backup] ERROR: el .gz no pasa gzip -t (dump corrupto): ${partial}" >&2
    rm -f "$partial"
    return 1
  fi
  # No se usa 'gzip -cd | grep -qF': grep -q sale en cuanto encuentra el
  # texto y, si queda salida pendiente, gzip muere por SIGPIPE. Bajo
  # set -o pipefail eso convierte el pipeline en exit 141 y hace
  # finalize_dump reporta un dump válido como corrupto (y lo borra).
  # 'tail -n 5' consume todo el input, así que no hay salida temprana, y
  # el match se hace en memoria contra las líneas de cierre.
  cola="$(gzip -cd "$partial" | tail -n 5)"
  case "$cola" in
    *"$sentinel"*) ;;
    *)
      echo "[backup] ERROR: el dump no cierra con '${sentinel}': ${partial}" >&2
      rm -f "$partial"
      return 1
      ;;
  esac
  mv "$partial" "$out"
  echo "[backup] OK → ${out} ($(du -h "$out" | cut -f1))"
}

backup_postgres() {
  local out="$BACKUP_DIR/waf-db-${TS}.sql.gz"
  local partial="${out}.partial"
  echo "[backup] PostgreSQL → ${out}"
  if ! docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$partial"; then
    echo "[backup] ERROR: pg_dump falló para ${DB_NAME}. No se publica nada." >&2
    rm -f "$partial"
    return 1
  fi
  finalize_dump "$partial" "$out" "PostgreSQL database dump complete"
}

backup_mysql() {
  local out="$BACKUP_DIR/pyme-db-${TS}.sql.gz"
  local partial="${out}.partial"
  if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    echo "[backup] MYSQL_ROOT_PASSWORD no definido; se omite el backup de la BD PYME."
    return 0
  fi
  echo "[backup] MySQL → ${out}"
  if ! MYSQL_PWD="$MYSQL_ROOT_PASSWORD" docker exec -e MYSQL_PWD "$MYSQL_CONTAINER" \
      mysqldump --no-tablespaces -uroot bd_atel | gzip > "$partial"; then
    echo "[backup] ERROR: mysqldump falló para bd_atel. No se publica nada." >&2
    rm -f "$partial"
    return 1
  fi
  finalize_dump "$partial" "$out" "-- Dump completed on"
}

prune() {
  local pattern="$1"
  # Solo archivos ya publicados (sin .partial).
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