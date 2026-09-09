#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# reset.sh — Reinicia el stack WAF-ML desde cero (DESTRUCTIVO).
#
# 1. Pide confirmación explícita (nunca automático).
# 2. docker compose down (elimina contenedores y redes).
# 3. Opcionalmente ELIMINA los volúmenes (waf_db_data, pyme_mysql_data)
#    para que init.sql vuelva a correr limpio.
# 4. Opcionalmente restaura el backup más reciente de PostgreSQL.
#
# Uso:
#   scripts/reset.sh            # down + up limpio, KEEPING volúmenes
#   scripts/reset.sh --wipe     # down + elimina volúmenes + up limpio
#   scripts/reset.sh --restore  # como --wipe y además restaura el último backup
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:-}"

case "$MODE" in
  --wipe|--restore) ;;
  "") MODE="" ;;
  *) echo "[reset] Modo inválido: ${MODE}. Usá --wipe o --restore." >&2; exit 1 ;;
esac

echo "[reset] ⚠️  Este comando reinicia el stack WAF-ML completo."
if [ "$MODE" = "--wipe" ] || [ "$MODE" = "--restore" ]; then
  echo "[reset] ⚠️  En modo ${MODE} se ELIMINARÁN los volúmenes (datos de waf_db y pyme DB)."
fi
read -r -p "[reset] ¿Continuar? [s/N] " CONFIRM
if [ "$CONFIRM" != "s" ] && [ "$CONFIRM" != "S" ]; then
  echo "[reset] Cancelado."
  exit 0
fi

cd "$PROJECT_DIR"

echo "[reset] Abajo el stack..."
docker compose down

if [ "$MODE" = "--wipe" ] || [ "$MODE" = "--restore" ]; then
  echo "[reset] Eliminando volúmenes de datos..."
  docker volume rm -f waf-ml-project_waf_db_data waf-ml-project_pyme_mysql_data 2>/dev/null \
    || docker volume ls -q --filter "name=waf" | xargs -r docker volume rm -f
fi

echo "[reset] Levantando el stack limpio..."
docker compose up -d

echo "[reset] Esperando bases de datos saludables..."
docker compose exec -T database pg_isready -U "${DB_USER:-waf_user}" -d "${DB_NAME:-waf_db}" >/dev/null 2>&1 \
  || sleep 5

if [ "$MODE" = "--restore" ]; then
  echo "[reset] Restaurando el último backup... (podés cancelar y correr scripts/restore.sh si preferís elegirlo)"
  "${SCRIPT_DIR}/restore.sh"
fi

echo ""
echo "[reset] ✓ Stack reiniciado. Siguiente paso requerido:"
echo "[reset]     scripts/bootstrap-admin.sh   (crear el admin inicial aleatorio)"
echo ""