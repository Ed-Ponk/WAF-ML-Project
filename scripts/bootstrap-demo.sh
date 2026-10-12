#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# bootstrap-demo.sh — Deja la PYME (bd_atel) funcional con data demo.
#
# - Importa SOLO atel_demo_erp.sql (con FK checks off) y completa el
#   esquema con las migraciones faltantes del repo (migrate --force).
# - Ejecuta SOLO contra una base vacía: si la tabla users ya tiene
#   filas, no hace nada (guard idempotente). Sin backup previo.
# - Scrub de tablas OAuth + regeneración del personal access client
#   (el dump trae el secret placeholder REGENERAR_CON_PASSPORT_INSTALL).
# - Genera una contraseña ALEATORIA para los usuarios demo (openssl),
#   escrita en ./secrets/pyme_demo_password (umask 077 + chmod 600).
#   La contraseña NUNCA sale por stdout.
# - Emails @zizehost.com se reemplazan por @example.test al importar
#   (dominio real, no podemos garantizar que los buzones sean ficticios).
# - Los admins del dump (DNI/nombres que parecen reales) se reemplazan
#   por identidades ficticias (99000001/99000002, DEMO ADMIN) con UPDATEs
#   explícitos tras el import; la verificación final grepea un mysqldump
#   en memoria y no deja ningún DNI/nombre original en ninguna tabla.
#
# Usa SOLO `docker compose exec` con los servicios del compose de
# WAF-ML-Project (mysql, pyme-php-backend). Credenciales de MySQL se
# leen dentro del contenedor desde $MYSQL_ROOT_PASSWORD (nunca un
# literal -p<password> en la línea de comandos).
#
# Uso:
#   scripts/bootstrap-demo.sh
#   ATEL_DUMP=/ruta/atel_demo_erp.sql scripts/bootstrap-demo.sh
#   PYME_DB_NAME=bd_atel scripts/bootstrap-demo.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Servicios del docker-compose.yml de WAF-ML-Project (no contenedores).
MYSQL_SERVICE="${MYSQL_SERVICE:-mysql}"
BACKEND_SERVICE="${BACKEND_SERVICE:-pyme-php-backend}"
# Ruta del dump: layout del monorepo (misma relativización que los build
# context del compose: ../../atel-upload/atel-back).
ATEL_DUMP="${ATEL_DUMP:-${PROJECT_DIR}/../../atel-upload/atel-back/atel_demo_erp.sql}"
PYME_DB_NAME="${PYME_DB_NAME:-bd_atel}"
ADMIN_CREDS_FILE="${ADMIN_CREDS_FILE:-${PROJECT_DIR}/secrets/pyme_demo_password}"

# cxc: docker compose exec -T (sin TTY) desde el dir del compose, para
# que tome .env y posibles override files igual que el stack real.
cxc() {
  ( cd "$PROJECT_DIR" && docker compose exec -T "$@" )
}

# Preflight: el stack debe estar corriendo.
if ! ( cd "$PROJECT_DIR" && docker compose ps --status running -q "$MYSQL_SERVICE" 2>/dev/null | grep -q . ); then
  echo "[bootstrap-demo] ERROR: el servicio '${MYSQL_SERVICE}' no está corriendo en '$PROJECT_DIR'." >&2
  exit 1
fi
if ! ( cd "$PROJECT_DIR" && docker compose ps --status running -q "$BACKEND_SERVICE" 2>/dev/null | grep -q . ); then
  echo "[bootstrap-demo] ERROR: el servicio '${BACKEND_SERVICE}' no está corriendo en '$PROJECT_DIR'." >&2
  exit 1
fi

# Nombre real de la DB: el que tiene el backend en su env (fuente de verdad).
BACKEND_DB="$(cxc "$BACKEND_SERVICE" sh -c 'printf "%s" "$DB_DATABASE"' 2>/dev/null || true)"
if [ -n "$BACKEND_DB" ]; then
  PYME_DB_NAME="$BACKEND_DB"
fi

# Si la importación/migración queda a medias, la base ya tiene filas y el
# guard idempotente bloquearía el reintento. Instrucciones de reset.
show_reset_hint() {
  cat >&2 <<EOF
[bootstrap-demo] La base quedó a medio importar. Para reintentar desde cero:
[bootstrap-demo]   1) Recreá la base para que el guard la vea vacía:
[bootstrap-demo]      cd "$PROJECT_DIR"
[bootstrap-demo]      docker compose exec -T "$MYSQL_SERVICE" sh -c 'MYSQL_PWD="\$MYSQL_ROOT_PASSWORD" mysql -uroot -e "DROP DATABASE IF EXISTS ${PYME_DB_NAME}; CREATE DATABASE ${PYME_DB_NAME}"'
[bootstrap-demo]   2) Volvé a correr: scripts/bootstrap-demo.sh
EOF
}

# ── Guard idempotente ──────────────────────────────────────────────
# Una base recién creada puede no tener tablas (caso VPS): un SELECT a
# users fallaría y, con set -e, cortaría en silencio. "Tabla inexistente"
# se trata como 0 usuarios vía information_schema.
USERS="0"
USERS_TABLE="$(cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=\"$PYME_DB_NAME\" AND table_name=\"users\""' 2>/dev/null || true)"

if [ "$USERS_TABLE" = "1" ]; then
  USERS="$(cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "SELECT COUNT(*) FROM \`$PYME_DB_NAME\`.users"' 2>/dev/null || true)"
  USERS="${USERS:-0}"
fi

if [ "$USERS" != "0" ]; then
  echo "[bootstrap-demo] La base '$PYME_DB_NAME' ya tiene ${USERS} usuarios. Nada que hacer."
  exit 0
fi

if [ ! -f "$ATEL_DUMP" ]; then
  echo "[bootstrap-demo] ERROR: no encuentro el dump en '$ATEL_DUMP'. Pasalo con ATEL_DUMP=..." >&2
  exit 1
fi

# ── Contraseña demo aleatoria ──────────────────────────────────────
# Solo alfanumérica para evitar problemas de quoting en JSON.
PYME_PASSWORD="$(openssl rand -base64 24 | tr -cd '[:alnum:]' | head -c 20)"

# ── 1) Import de atel_demo_erp.sql (solo data demo) ───────────────
# FK checks off durante el import; emails @zizehost.com → @example.test
# en el MISMO paso (dominio real, buzones no verificados).
if ! { echo "SET FOREIGN_KEY_CHECKS=0;"; sed -E 's/@zizehost\.com/@example.test/g' "$ATEL_DUMP"; echo "SET FOREIGN_KEY_CHECKS=1;"; } | cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot "$PYME_DB_NAME"'; then
  echo "[bootstrap-demo] ERROR: la importación del dump falló." >&2
  show_reset_hint
  exit 1
fi
echo "[bootstrap-demo] ✓ Dump importado (emails @zizehost.com → @example.test)."

# ── 2) Identidades ficticias para los admins demo ─────────────────
# El dump trae DNI y nombres que parecen reales (72681032/76150742,
# 'GUILLERMO SANTISTEBAN', 'JOSE DIAZ') en users y persons. Con UPDATEs
# explícitos (revisables) se reemplazan por identidades obviamente
# falsas, manteniendo la relación users.model_id → persons.id. El email
# se anonimiza también (el local-part 'guillermo.santisteban' sigue
# llevando el nombre original si solo se cambia el dominio).
cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot "$PYME_DB_NAME"' <<'SQL'
UPDATE users   SET document_number = '99000001' WHERE document_number = '72681032';
UPDATE users   SET document_number = '99000002' WHERE document_number = '76150742';
UPDATE users   SET email = 'demo.admin.uno@example.test' WHERE document_number = '99000001';
UPDATE users   SET email = 'demo.admin.dos@example.test' WHERE document_number = '99000002';
UPDATE persons SET document_number = '99000001' WHERE document_number = '72681032';
UPDATE persons SET document_number = '99000002' WHERE document_number = '76150742';
UPDATE persons SET names = 'DEMO ADMIN', father_last_name = 'UNO', mother_last_name = '' WHERE document_number = '99000001';
UPDATE persons SET names = 'DEMO ADMIN', father_last_name = 'DOS', mother_last_name = '' WHERE document_number = '99000002';
SQL
echo "[bootstrap-demo] ✓ Admins demo → identidades ficticias (99000001/99000002, DEMO ADMIN, emails anonimizados)."

# ── 3) Migraciones faltantes del repo (el dump es de 2025-06-30) ──
if ! MIGRATE_OUT="$(cxc "$BACKEND_SERVICE" php artisan migrate --force --no-interaction 2>&1)"; then
  echo "[bootstrap-demo] ERROR en migrate --force:" >&2
  echo "$MIGRATE_OUT" >&2
  show_reset_hint
  exit 1
fi
echo "[bootstrap-demo] ✓ Migraciones aplicadas (migrate --force)."

# ── 4) Scrub de tablas OAuth (deja fuera el secret placeholder) ───
cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot "$PYME_DB_NAME"' <<'SQL'
SET FOREIGN_KEY_CHECKS=0;
TRUNCATE TABLE oauth_access_tokens;
TRUNCATE TABLE oauth_refresh_tokens;
TRUNCATE TABLE oauth_auth_codes;
TRUNCATE TABLE oauth_clients;
TRUNCATE TABLE oauth_personal_access_clients;
TRUNCATE TABLE personal_access_tokens;
SET FOREIGN_KEY_CHECKS=1;
SQL
echo "[bootstrap-demo] ✓ Tablas OAuth limpiadas."

# ── 5) Regenerar personal access client (secret aleatorio real) ───
PASSPORT_OUT="$(cxc "$BACKEND_SERVICE" php artisan passport:client \
  --personal --name="Pyme Personal Access Client" --no-interaction 2>&1 || true)"
if ! echo "$PASSPORT_OUT" | grep -qi "created"; then
  echo "[bootstrap-demo] ERROR regenerando el client personal:" >&2
  echo "$PASSPORT_OUT" >&2
  exit 1
fi
echo "[bootstrap-demo] ✓ Personal Access Client regenerado (secret no se imprime)."

# ── 6) Password demo para los usuarios (via env, no en argv) ─────
TINKER_OUT="$(cxc -e "PYME_DEMO_PASSWORD=$PYME_PASSWORD" "$BACKEND_SERVICE" \
  php artisan tinker --execute='\App\Models\User::query()->update(["password" => \Illuminate\Support\Facades\Hash::make(getenv("PYME_DEMO_PASSWORD"))]);' 2>&1)" \
  || { echo "[bootstrap-demo] ERROR seteando password:" >&2; echo "$TINKER_OUT" >&2; exit 1; }
echo "[bootstrap-demo] ✓ Password demo aplicada a los usuarios."

cxc "$BACKEND_SERVICE" php artisan config:clear >/dev/null
echo "[bootstrap-demo] ✓ config:clear."

# ── 7) Guardado seguro de la credencial demo ──────────────────────
DEMO_USER="$(cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "SELECT document_number FROM \`$PYME_DB_NAME\`.users ORDER BY id LIMIT 1"')"
mkdir -p "$(dirname "$ADMIN_CREDS_FILE")"
{
  echo "usuario=${DEMO_USER}"
  echo "database=${PYME_DB_NAME}"
  echo "contrasena=${PYME_PASSWORD}"
  echo "generado=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$ADMIN_CREDS_FILE"
chmod 600 "$ADMIN_CREDS_FILE"

# ── 8) Verificacion ───────────────────────────────────────────────
SUMMARY="$(cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -N -e "
    SELECT \"users\", COUNT(*) FROM \`$PYME_DB_NAME\`.users
    UNION ALL SELECT \"sales\", COUNT(*) FROM \`$PYME_DB_NAME\`.sales
    UNION ALL SELECT \"products\", COUNT(*) FROM \`$PYME_DB_NAME\`.products
    UNION ALL SELECT \"oauth_clients\", COUNT(*) FROM \`$PYME_DB_NAME\`.oauth_clients
    UNION ALL SELECT \"oauth_secret_placeholder\", COUNT(*) FROM \`$PYME_DB_NAME\`.oauth_clients WHERE secret LIKE \"REGENERAR%\"
    UNION ALL SELECT \"emails_zizehost_restantes\", COUNT(*) FROM \`$PYME_DB_NAME\`.users WHERE email LIKE \"%@zizehost.com%\"
  "')"

echo ""
echo "[bootstrap-demo] Resumen de la base '${PYME_DB_NAME}':"
echo "$SUMMARY" | sed 's/^/  /'

if echo "$SUMMARY" | grep -q "oauth_secret_placeholder	[1-9]"; then
  echo "[bootstrap-demo] ERROR: quedó el secret placeholder en oauth_clients." >&2
  exit 1
fi

# Verificación: ni DNI ni nombres originales de los admins deben quedar
# en NINGUNA tabla. El dump se hace a una variable en memoria (nunca se
# escribe a disco) y se grepea por cada token original. 'JOSE' suelto no
# vale (hay 'JOSE MARIA ARGUEDAS', 'SAN JOSE...' en ubigeos): se usa el
# par exacto 'JOSE', 'DIAZ' con el formato de fila de mysqldump.
DUMP_CHECK="$(cxc -e "PYME_DB_NAME=$PYME_DB_NAME" "$MYSQL_SERVICE" sh -c \
  'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --no-tablespaces --skip-comments --skip-add-locks "$PYME_DB_NAME"' 2>/dev/null || true)"

if [ -z "$DUMP_CHECK" ]; then
  echo "[bootstrap-demo] ERROR: el mysqldump de verificación salió vacío (¿falló el mysqldump?)." >&2
  exit 1
fi

LEFTOVER_TOKENS=('72681032' '76150742' 'GUILLERMO' 'SANTISTEBAN' 'GUERRERO' 'MARTINEZ' "'JOSE', 'DIAZ'")
LEFTOVERS=""
for token in "${LEFTOVER_TOKENS[@]}"; do
  if printf '%s' "$DUMP_CHECK" | grep -qiF -- "$token"; then
    LEFTOVERS="${LEFTOVERS:+$LEFTOVERS }$token"
  fi
done

if [ -n "$LEFTOVERS" ]; then
  echo "[bootstrap-demo] ERROR: quedó data de los admins originales en alguna tabla: ${LEFTOVERS}" >&2
  exit 1
fi
echo "[bootstrap-demo] ✓ Sin DNI ni nombres originales de los admins (mysqldump temporal en memoria)."

LOGIN_OUT="$(cxc -e "PYME_DEMO_PASSWORD=$PYME_PASSWORD" "$BACKEND_SERVICE" sh -c \
  'curl -sS -X POST http://127.0.0.1/api/v1/auth/login \
      -H "Content-Type: application/json" -H "Accept: application/json" \
      -d "{\"user\":\"'"$DEMO_USER"'\",\"password\":\"$PYME_DEMO_PASSWORD\"}"' || true)"

if echo "$LOGIN_OUT" | grep -q '"access_token"'; then
  echo "[bootstrap-demo] ✓ Login por API correcto (usuario ${DEMO_USER})."
else
  echo "[bootstrap-demo] ERROR: el login por API falló. Respuesta:" >&2
  echo "$LOGIN_OUT" >&2
  exit 1
fi

echo "[bootstrap-demo] Credenciales demo guardadas en: ${ADMIN_CREDS_FILE} (600, no se imprimen)."
echo "[bootstrap-demo] Login: usuario '${DEMO_USER}' (o email @example.test) + password del archivo."
echo ""