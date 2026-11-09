"""Phase 2.2 tests: domain->app resolution and SSRF-safe proxy in ml-engine.

The helpers live in ml-engine/app.py, which imports pandas/httpx/asyncpg.
The runtime cases therefore run inside the real ml-engine image.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).parent.parent
APP = PROJECT_DIR / "ml-engine" / "app.py"
COMPOSE = PROJECT_DIR / "docker-compose.yml"
CASES = Path(__file__).parent / "ml_engine_apps_cases.py"


def test_app_registry_wiring_is_present():
    source = APP.read_text()
    for token in (
        "waf_app_domains",
        "apps_by_domain",
        "def _build_apps_cache",
        "def parse_backend_url",
        "def resolve_backend_connection",
        "def resolve_app_by_host",
        "def resolve_request_app",
        '@app.post("/reload_apps")',
        "sni_hostname",
        "follow_redirects=False",
        "trust_env=False",
        "IS_DEVELOPMENT",
        "IS_PRODUCTION",
        "WAF_DOMAIN",
        "WAF_UNKNOWN_HOST_FALLBACK",
        "UnknownHostError",
        "NoDefaultAppError",
    ):
        assert token in source, token

    assert "x-forwarded-host" not in source
    assert "verify=False" not in source

    compose = COMPOSE.read_text()
    ml_engine_block = compose.split("\n  ml-engine:\n", 1)[1].split("\n  proxy:\n", 1)[0]
    assert "WAF_ENV=${WAF_ENV:-production}" in ml_engine_block
    assert "WAF_DOMAIN=${WAF_DOMAIN:-localhost}" in ml_engine_block
    assert "WAF_UNKNOWN_HOST_FALLBACK=${WAF_UNKNOWN_HOST_FALLBACK:-false}" in ml_engine_block


def test_dashboard_reloads_apps_cache_after_writes():
    apps_api = PROJECT_DIR / "dashboard" / "app" / "api" / "apps"
    post = (apps_api / "route.ts").read_text()
    patch = (apps_api / "[id]" / "route.ts").read_text()
    auth = (PROJECT_DIR / "dashboard" / "lib" / "auth.ts").read_text()

    assert "reloadAppsCache(auth.token)" in post
    assert "reloadAppsCache(auth.token)" in patch
    assert 'logAuditEvent("app.reload", "failure"' in post
    assert 'logAuditEvent("app.reload", "failure"' in patch
    assert "token: string" in auth


def _ml_engine_running() -> bool:
    if not shutil.which("docker"):
        return False
    proc = subprocess.run(
        ["docker", "compose", "ps", "-q", "ml-engine"],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode == 0 and bool(proc.stdout.strip())


def test_ml_engine_apps_cases_in_container():
    if not _ml_engine_running():
        pytest.skip("ml-engine no está corriendo; se omite el runtime test")

    proc = subprocess.run(
        [
            "docker", "compose", "run", "--rm", "--no-deps",
            "-v", f"{CASES}:/tests/ml_engine_apps_cases.py:ro",
            "ml-engine", "python", "/tests/ml_engine_apps_cases.py",
        ],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
