"""Integration test for the apps API alias conflict.

Runs against the local docker compose stack and skips when it is not running.
Creates two temporary apps and removes them afterwards.
"""

import base64
import hashlib
import hmac
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).parent.parent
BASE_URL = "http://127.0.0.1/dashboard/api/apps"
HEALTH_URL = "http://127.0.0.1/dashboard/api/health"
HOST_HEADER = "admin.waf.local"
ACTOR = "test-admin"


def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _stack_ready() -> bool:
    if not shutil.which("docker"):
        return False
    proc = _compose("ps", "--services", "--filter", "status=running")
    if proc.returncode != 0:
        return False
    services = set(proc.stdout.split())
    return {"waf-dashboard", "database"}.issubset(services)


def _api_ready() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _admin_token() -> str:
    proc = _compose("exec", "-T", "waf-dashboard", "printenv", "JWT_SECRET")
    assert proc.returncode == 0, proc.stderr
    secret = proc.stdout.strip()

    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "userid": ACTOR,
        "username": ACTOR,
        "role": "admin",
        "iat": now,
        "exp": now + 300,
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, payload)
    )
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def _request(method: str, token: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE_URL, data=data, method=method)
    req.add_header("Host", HOST_HEADER)
    req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _db_credentials() -> tuple[str, str]:
    user = _compose("exec", "-T", "database", "printenv", "POSTGRES_USER").stdout.strip()
    name = _compose("exec", "-T", "database", "printenv", "POSTGRES_DB").stdout.strip()
    return user, name


def _cleanup(slugs: list[str]) -> None:
    if not slugs:
        return
    quoted = ",".join(f"'{slug}'" for slug in slugs)
    sql = (
        f"DELETE FROM waf_audit_log WHERE username = '{ACTOR}';"
        f"DELETE FROM waf_apps WHERE slug IN ({quoted});"
    )
    user, name = _db_credentials()
    _compose(
        "exec", "-T", "database", "psql",
        "-U", user, "-d", name, "-c", sql,
    )


def test_create_app_rejects_domain_used_as_alias():
    if not _stack_ready() or not _api_ready():
        pytest.skip("docker compose stack no está corriendo")

    token = _admin_token()
    suffix = uuid.uuid4().hex[:8]
    primary = f"alias-primary-{suffix}.waf.local"
    alias = f"alias-shared-{suffix}.waf.local"
    slug_a = f"alias-a-{suffix}"
    slug_b = f"alias-b-{suffix}"

    try:
        status, body = _request(
            "POST",
            token,
            {
                "slug": slug_a,
                "name": "Alias A",
                "domains": [primary, alias],
                "backend_url": "http://maderera-app:3000",
            },
        )
        assert status == 201, body

        status, body = _request(
            "POST",
            token,
            {
                "slug": slug_b,
                "name": "Alias B",
                "domains": [alias],
                "backend_url": "http://maderera-app:3000",
            },
        )
        assert status == 409, body
        assert "dominios" in body.get("error", "").lower()
    finally:
        _cleanup([slug_a, slug_b])
