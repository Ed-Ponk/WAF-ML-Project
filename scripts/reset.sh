#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# reset.sh — Reinicia el stack WAF-ML desde cero (DESTRUCTIVO).
#
# 1. Resuelve los volúmenes de DATOS por etiqueta de compose y los
#    muestra uno por uno ANTES de pedir confirmación.
# 2. Pide confirmación explícita (nunca automático).
# 3. docker compose down (elimina contenedores y redes).
# 4. Con --wipe o --restore, ELIMINA los volúmenes de datos para que
#    init.sql vuelva a correr limpio.
# 5. Opcionalmente restaura el backup más reciente de PostgreSQL.
#
# Los volúmenes de certificados (certbot-etc, certbot-webroot) no se
# tocan nunca: no están en DATA_VOLUMES y no se resuelven.
#
# Uso:
#   scripts/reset.sh            # down + up limpio, CONSERVANDO volúmenes
#   scripts/reset.sh --wipe     # down + elimina volúmenes de datos + up
#   scripts/reset.sh --restore  # como --wipe y además restaura el backup
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MODE="${1:-}"

# Allowlist explícita de volúmenes lógicos de datos. Cualquier otro
# volumen del proyecto queda fuera por construcción, no por filtro.
DATA_VOLUMES=(waf_db_data pyme_mysql_data)

case "$MODE" in
  --wipe|--restore) ;;
  "") MODE="" ;;
  *) echo "[reset] Modo inválido: ${MODE}. Usá --wipe o --restore." >&2; exit 1 ;;
esac

cd "$PROJECT_DIR"

compose_project() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  docker compose config --format json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])'
}

resolve_volume() {
  docker volume ls -q \
    --filter "label=com.docker.compose.project=${PROJECT}" \
    --filter "label=com.docker.compose.volume=$1"
}

PROJECT="$(compose_project)"
TARGET_VOLUMES=()

echo "[reset] ⚠️  Este comando reinicia el stack WAF-ML completo."

if [ "$MODE" = "--wipe" ] || [ "$MODE" = "--restore" ]; then
  for logical in "${DATA_VOLUMES[@]}"; do
    mapfile -t found < <(resolve_volume "$logical")
    if [ "${#found[@]}" -eq 0 ]; then
      echo "[reset] ERROR: no se encontró el volumen '${logical}' del proyecto '${PROJECT}'." >&2
      exit 1
    fi
    TARGET_VOLUMES+=("${found[@]}")
  done

  echo "[reset] ⚠️  En modo ${MODE} se ELIMINARÁN estos volúmenes (proyecto '${PROJECT}'):"
  for v in "${TARGET_VOLUMES[@]}"; do
    echo "[reset]     - ${v}"
  done
else
  echo "[reset] Modo '${MODE:-normal}': los volúmenes de datos se conservan."
fi

read -r -p "[reset] ¿Continuar? [s/N] " CONFIRM
if [ "$CONFIRM" != "s" ] && [ "$CONFIRM" != "S" ]; then
  echo "[reset] Cancelado."
  exit 0
fi

echo "[reset] Abajo el stack..."
docker compose down

if [ "${#TARGET_VOLUMES[@]}" -gt 0 ]; then
  echo "[reset] Eliminando volúmenes de datos (${#TARGET_VOLUMES[@]})..."
  docker volume rm "${TARGET_VOLUMES[@]}"
  echo "[reset] Volúmenes eliminados."
fi

echo "[reset] Levantando el stack limpio..."
docker compose up -d

echo "[reset] Esperando bases de datos saludables..."
docker compose exec -T database pg_isready -U "${DB_USER:-waf_user}" -d "${DB_NAME:-waf_db}" >/dev/null 2>&1 \
  || sleep 5

if [ "$MODE" = "--restore" ]; then
  echo "[reset] Restaurando el último backup..."
  "${SCRIPT_DIR}/restore.sh"
fi

echo ""
echo "[reset] ✓ Stack reiniciado. Siguiente paso requerido:"
echo "[reset]     scripts/bootstrap-admin.sh   (crear el admin inicial aleatorio)"
echo ""