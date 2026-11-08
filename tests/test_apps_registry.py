"""Tests for the DB-driven app registry (Phase 2.1).

These tests validate:
  - Multi-domain migration is idempotent and backfills waf_apps.domain.
  - Dashboard apps API is admin-only, audited, and does not physically delete.
  - Dashboard validation includes SSRF guards.
  - Apps page/component and navigation entry exist.
  - Migration runner exists and fails fast.
"""

from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
MIGRATION = PROJECT_DIR / "database" / "migrations" / "20261108_004_waf_app_domains.sql"
APPS_API = PROJECT_DIR / "dashboard" / "app" / "api" / "apps" / "route.ts"
APPS_ID_API = PROJECT_DIR / "dashboard" / "app" / "api" / "apps" / "[id]" / "route.ts"
APPS_LIB = PROJECT_DIR / "dashboard" / "lib" / "apps.ts"
APPS_PAGE = PROJECT_DIR / "dashboard" / "app" / "admin" / "apps" / "page.tsx"
APPS_COMPONENT = PROJECT_DIR / "dashboard" / "components" / "dashboard" / "AppManagement.tsx"
ADMIN_LAYOUT = PROJECT_DIR / "dashboard" / "app" / "admin" / "layout.tsx"
MIGRATION_RUNNER = PROJECT_DIR / "scripts" / "apply-migrations.sh"


def test_multi_domain_migration_is_idempotent_and_backfills():
    assert MIGRATION.exists(), "Multi-domain migration is missing"
    sql = MIGRATION.read_text()

    assert "CREATE TABLE IF NOT EXISTS waf_app_domains" in sql
    assert "fk_waf_app_domains_app" in sql
    assert "waf_app_domains_domain_key" in sql
    assert "waf_app_domains_domain_check" in sql
    assert "SELECT id, domain FROM waf_apps" in sql
    assert "ON CONFLICT (domain) DO NOTHING" in sql
    assert "CREATE TRIGGER trg_waf_apps_updated_at" in sql
    assert "DROP COLUMN" not in sql
    assert "ALTER TABLE waf_apps DROP" not in sql


def test_apps_api_is_admin_only_and_audited():
    assert APPS_API.exists(), "apps/route.ts is missing"
    assert APPS_ID_API.exists(), "apps/[id]/route.ts is missing"

    list_api = APPS_API.read_text()
    item_api = APPS_ID_API.read_text()

    for content in (list_api, item_api):
        assert "authenticate(request, { requireAdmin: true })" in content
        assert "logAuditEvent" in content
        assert "waf_app_domains" in content
        assert "export async function DELETE" not in content

    assert "app.create" in list_api
    assert "app.update" in item_api
    assert "app.disable" in item_api
    assert "validateSlugUpdate" in item_api
    assert "validateDisableAllowed" in item_api
    assert "slug = $2" not in item_api
    assert "FOR UPDATE" in item_api
    assert "slug_immutable" in item_api
    assert "last_enabled_app" in item_api


def test_apps_validation_has_ssrf_guards():
    assert APPS_LIB.exists(), "lib/apps.ts is missing"
    source = APPS_LIB.read_text()

    assert "INTERNAL_HOST_DENYLIST" in source
    assert '"localhost"' in source
    assert '"database"' in source
    assert '"ml-engine"' in source
    assert '"waf-dashboard"' in source
    assert '"mysql"' in source
    assert '"vpn"' in source

    assert "url.username" in source
    assert "url.password" in source
    assert "127" in source
    assert "169" in source
    assert "172" in source
    assert "192" in source
    assert "fe80:" in source
    assert ":ffff:" in source
    assert 'startsWith("::")' in source

    assert "normalizeDomain" in source
    assert "normalizeSlug" in source
    assert "validateBackendUrl" in source


def test_apps_page_component_and_menu_exist():
    assert APPS_PAGE.exists(), "apps page is missing"
    assert APPS_COMPONENT.exists(), "AppManagement component is missing"

    page = APPS_PAGE.read_text()
    component = APPS_COMPONENT.read_text()
    layout = ADMIN_LAYOUT.read_text()

    assert "AppManagement" in page
    assert "Aplicaciones" in page
    assert "/dashboard/api/apps" in component
    assert "aplicaciones activas" in component
    assert 'placeholder="pyme.waf.local, localhost"' not in component
    assert "if (!editingId)" in component
    assert "payload.slug" in component
    assert "disabled={Boolean(editingId)}" in component
    assert "No se puede deshabilitar la última aplicación activa" in component
    assert 'href: "/dashboard/admin/apps"' in layout


def test_migration_runner_fails_fast():
    assert MIGRATION_RUNNER.exists(), "apply-migrations.sh is missing"
    script = MIGRATION_RUNNER.read_text()

    assert "ON_ERROR_STOP=1" in script
    assert "database/migrations" in script
    assert "docker compose exec" in script


def test_migrate_service_and_control_table():
    compose = (PROJECT_DIR / "docker-compose.yml").read_text()
    script = MIGRATION_RUNNER.read_text()

    assert "migrate:" in compose
    assert "service_completed_successfully" in compose
    assert "schema_migrations" in script
    assert "MIGRATE_MODE" in script
    assert "wait_for_base_schema" in script


def test_tests_are_versioned_and_pytest_is_dev_dependency():
    gitignore = (PROJECT_DIR / ".gitignore").read_text().splitlines()
    assert "tests/" not in [line.strip() for line in gitignore]

    requirements = (PROJECT_DIR / "requirements-dev.txt").read_text()
    assert "pytest" in requirements
