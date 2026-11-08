#!/usr/bin/env sh
# Aplica las migraciones de database/migrations en orden alfabético.
# Usa schema_migrations como tabla de control: cada archivo se aplica una sola
# vez y las migraciones siguen siendo idempotentes por si se re-ejecutan.
#
# Uso local (host):
#   ./scripts/apply-migrations.sh
#
# Uso en contenedor one-shot (docker-compose):
#   MIGRATE_MODE=container PGHOST=database PGUSER=... PGPASSWORD=... PGDATABASE=... \
#     MIGRATIONS_DIR=/database/migrations ./scripts/apply-migrations.sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR/.."

MIGRATIONS_DIR="${MIGRATIONS_DIR:-database/migrations}"
DB_SERVICE="${DB_SERVICE:-database}"
MIGRATE_MODE="${MIGRATE_MODE:-}"

if [ -z "$MIGRATE_MODE" ]; then
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    MIGRATE_MODE=host
  elif command -v psql >/dev/null 2>&1; then
    MIGRATE_MODE=container
  else
    echo "Falta docker/psql para aplicar migraciones" >&2
    exit 1
  fi
fi

[ -d "$MIGRATIONS_DIR" ] || {
  echo "No existe $MIGRATIONS_DIR" >&2
  exit 1
}

if [ "$MIGRATE_MODE" = "host" ]; then
  DB_USER="$(docker compose exec -T "$DB_SERVICE" printenv POSTGRES_USER | tr -d '\r')"
  DB_NAME="$(docker compose exec -T "$DB_SERVICE" printenv POSTGRES_DB | tr -d '\r')"

  if [ -z "$DB_USER" ] || [ -z "$DB_NAME" ]; then
    echo "No pude leer POSTGRES_USER/POSTGRES_DB del servicio $DB_SERVICE" >&2
    exit 1
  fi
fi

run_psql() {
  if [ "$MIGRATE_MODE" = "host" ]; then
    docker compose exec -T "$DB_SERVICE" \
      psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME" "$@"
  else
    psql -v ON_ERROR_STOP=1 "$@"
  fi
}

# En un volumen nuevo, init.sql corre antes que este servicio. Esperamos a que
# la tabla base exista para no competir con la inicialización de PostgreSQL.
wait_for_base_schema() {
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    if [ "$(run_psql -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'waf_events' LIMIT 1" 2>/dev/null | tr -d '[:space:]')" = "1" ]; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "Timeout esperando PostgreSQL/waf_events (init.sql)" >&2
  return 1
}

wait_for_base_schema

run_psql -c "CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);"

found=0
for f in "$MIGRATIONS_DIR"/*.sql; do
  [ -e "$f" ] || continue
  found=1
  version=$(basename "$f" .sql)
  applied=$(run_psql -tAc "SELECT 1 FROM schema_migrations WHERE version = '$version' LIMIT 1" | tr -d '[:space:]')

  if [ "$applied" = "1" ]; then
    echo "→ Omitiendo $version (ya aplicada)"
    continue
  fi

  echo "→ Aplicando $version"
  run_psql < "$f"
  run_psql -c "INSERT INTO schema_migrations (version) VALUES ('$version') ON CONFLICT (version) DO NOTHING;"
done

if [ "$found" -eq 0 ]; then
  echo "No hay migraciones en $MIGRATIONS_DIR" >&2
  exit 1
fi

echo "✔ Migraciones aplicadas"
run_psql -c "SELECT version, applied_at FROM schema_migrations ORDER BY version;"
run_psql -c "SELECT (SELECT count(*) FROM waf_apps) AS apps, (SELECT count(*) FROM waf_app_domains) AS domains;"
