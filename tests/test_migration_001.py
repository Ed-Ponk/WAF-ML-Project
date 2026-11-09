"""Regression: migration 001 backfills a populated waf_events table.

Runs against the local docker compose database service and skips when it is not
running. Creates a throwaway database, loads the pre-migration waf_events schema
with rows, applies migration 001 twice, and verifies the backfill.
"""

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).parent.parent
MIGRATION = PROJECT_DIR / "database" / "migrations" / "20261027_001_waf_apps_and_events.sql"

LEGACY_SCHEMA = """
CREATE TABLE waf_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    fecha           TIMESTAMPTZ NOT NULL    DEFAULT NOW(),
    ip_origen       INET        NOT NULL,
    user_agent      TEXT,
    metodo_http     VARCHAR(10) NOT NULL,
    url             TEXT        NOT NULL,
    payload         TEXT,
    url_length          INTEGER,
    payload_length      INTEGER,
    special_char_count  INTEGER,
    shannon_entropy     NUMERIC(8,6),
    features_json       JSONB,
    cwe_family          VARCHAR(20),
    score_ml        NUMERIC(6,4) NOT NULL CHECK (score_ml BETWEEN 0 AND 1),
    veredicto       SMALLINT     NOT NULL CHECK (veredicto IN (0,1)),
    etiqueta_real   SMALLINT,
    accion          VARCHAR(5)   NOT NULL CHECK (accion IN ('BLOCK','ALLOW','LOG')),
    tiempo_inferencia_ms  NUMERIC(8,3),
    waf_version           VARCHAR(20) DEFAULT '1.0'
);

INSERT INTO waf_events (ip_origen, metodo_http, url, score_ml, veredicto, accion)
VALUES
    ('10.0.0.1', 'GET',  '/a', 0.1000, 0, 'ALLOW'),
    ('10.0.0.2', 'POST', '/b', 0.9000, 1, 'BLOCK'),
    ('10.0.0.3', 'GET',  '/c', 0.4000, 0, 'LOG');
"""


def _compose(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=PROJECT_DIR,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _database_ready() -> bool:
    if not shutil.which("docker"):
        return False
    proc = _compose("ps", "--services", "--filter", "status=running")
    return proc.returncode == 0 and "database" in proc.stdout.split()


def _credentials() -> tuple[str, str]:
    user = _compose("exec", "-T", "database", "printenv", "POSTGRES_USER").stdout.strip()
    name = _compose("exec", "-T", "database", "printenv", "POSTGRES_DB").stdout.strip()
    assert user and name, "no se pudieron leer las credenciales de la DB"
    return user, name


def _psql(db: str, user: str, sql: str) -> str:
    proc = _compose(
        "exec", "-T", "database", "psql",
        "-U", user, "-d", db, "-v", "ON_ERROR_STOP=1", "-tA",
        input_text=sql,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


def test_migration_001_backfills_populated_events():
    if not _database_ready():
        pytest.skip("docker compose database no está corriendo")

    user, maintenance_db = _credentials()
    tmp_db = f"waf_migration_001_{uuid.uuid4().hex[:8]}"

    try:
        _psql(maintenance_db, user, f'CREATE DATABASE "{tmp_db}";')
        _psql(tmp_db, user, LEGACY_SCHEMA)

        migration_sql = MIGRATION.read_text()
        _psql(tmp_db, user, migration_sql)
        _psql(tmp_db, user, migration_sql)

        assert _psql(tmp_db, user, "SELECT count(*) FROM waf_events;") == "3"
        assert _psql(tmp_db, user, "SELECT count(app_id) FROM waf_events;") == "3"
        assert _psql(tmp_db, user, "SELECT count(DISTINCT app_id) FROM waf_events;") == "1"
        assert _psql(
            tmp_db,
            user,
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name = 'waf_events' AND column_name = 'app_id';",
        ) == "NO"
        assert _psql(
            tmp_db,
            user,
            "SELECT count(*) FROM pg_indexes "
            "WHERE tablename = 'waf_events' AND indexname = 'idx_waf_events_app_fecha';",
        ) == "1"
        assert _psql(
            tmp_db,
            user,
            "SELECT slug || '|' || domain || '|' || backend_url FROM waf_apps;",
        ) == "default|pyme.waf.local|http://pyme-php-backend:80"
    finally:
        _compose(
            "exec", "-T", "database", "psql",
            "-U", user, "-d", maintenance_db, "-v", "ON_ERROR_STOP=1",
            "-c", f'DROP DATABASE IF EXISTS "{tmp_db}";',
        )
