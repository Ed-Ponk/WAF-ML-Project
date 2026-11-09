"""Runtime cases for Phase 2.2 app resolution and SSRF-safe proxying.

Run inside the ml-engine container (it owns the pandas/httpx/asyncpg deps):

    docker compose run --rm --no-deps \
      -v "$PWD/tests:/tests:ro" \
      ml-engine python /tests/ml_engine_apps_cases.py
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.environ.get("ML_ENGINE_DIR", "/app"))

import app as waf


failures = []


def check(name, fn):
    try:
        fn()
        print(f"ok - {name}")
    except Exception as exc:  # noqa: BLE001 - report every case
        failures.append((name, exc))
        print(f"FAIL - {name}: {exc}")


def expect_unsafe(url):
    try:
        waf.parse_backend_url(url)
    except waf.UnsafeBackendError:
        return
    raise AssertionError(f"se aceptó un backend prohibido: {url}")


def expect_allowed(url, expected_host):
    target = waf.parse_backend_url(url)
    assert target.host == expected_host, (url, target)


class cache_ctx:
    def __init__(self, built):
        self.built = built

    def __enter__(self):
        self.previous = (
            waf.apps_cache,
            waf.apps_by_slug,
            waf.apps_by_domain,
            waf.default_app_id,
        )
        waf.apps_cache = self.built["apps"]
        waf.apps_by_slug = self.built["by_slug"]
        waf.apps_by_domain = self.built["by_domain"]
        waf.default_app_id = self.built["default_app_id"]

    def __exit__(self, *exc):
        (
            waf.apps_cache,
            waf.apps_by_slug,
            waf.apps_by_domain,
            waf.default_app_id,
        ) = self.previous


def sample_cache():
    app_rows = [
        {
            "id": "a1",
            "slug": "default",
            "domain": "pyme.waf.local",
            "backend_url": "http://pyme-php-backend:80",
            "enabled": True,
        },
        {
            "id": "a2",
            "slug": "maderera",
            "domain": "maderera.waf.local",
            "backend_url": "http://maderera-app:3000",
            "enabled": True,
        },
        {
            "id": "a3",
            "slug": "off",
            "domain": "off.local",
            "backend_url": "http://off-app:80",
            "enabled": False,
        },
        {
            "id": "bad",
            "slug": "bad",
            "domain": "bad.local",
            "backend_url": "http://127.0.0.1:80",
            "enabled": True,
        },
    ]
    domain_rows = [
        {"app_id": "a1", "domain": "www.pyme.waf.local"},
        {"app_id": "a2", "domain": "MADERERA.waf.local."},
        {"app_id": "a2", "domain": "maderera.waf.local:3000"},
        {"app_id": "a2", "domain": "api.maderera.waf.local"},
        {"app_id": "bad", "domain": "bad.local"},
    ]
    return waf._build_apps_cache(app_rows, domain_rows)


def test_parse_backend_url_allows_private_networks():
    expect_allowed("http://pyme-php-backend:80", "pyme-php-backend")
    expect_allowed("http://10.0.0.5:8080", "10.0.0.5")
    expect_allowed("http://172.18.0.5:3000", "172.18.0.5")
    expect_allowed("http://192.168.1.10", "192.168.1.10")
    assert waf.parse_backend_url("http://172.18.0.5:3000/").to_url() == "http://172.18.0.5:3000"


def test_parse_backend_url_rejects_blocked_targets():
    for url in (
        "http://127.0.0.1:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/latest/meta-data",
        "http://224.0.0.1:80",
        "http://[::1]:80",
        "http://[fe80::1]:80",
        "http://database:5432",
        "http://DATABASE.:5432",
        "http://localhost:80",
        "http://user:pass@example.com",
        "http://example.com/?q=1",
        "http://example.com/#frag",
        "ftp://example.com",
        "http://example.com:99999",
        "",
    ):
        expect_unsafe(url)


def test_normalize_host_strips_port_case_and_trailing_dot():
    assert waf.normalize_host("MADERERA.WAF.LOCAL.:3000") == "maderera.waf.local"
    assert waf.normalize_host("example.com") == "example.com"
    assert waf.normalize_host("[::1]:8080") == "::1"
    assert waf.normalize_host("") == ""


def test_normalize_cache_domain_rejects_ports_and_schemes():
    assert waf.normalize_cache_domain("Example.COM.") == "example.com"
    for raw in ("example.com:3000", "http://example.com", "example.com/x", "database", ""):
        assert waf.normalize_cache_domain(raw) is None, raw


def test_build_cache_aliases_disabled_and_discards():
    built = sample_cache()

    assert "bad" not in built["apps"], "backend loopback no se descartó"
    assert built["by_domain"]["pyme.waf.local"]["id"] == "a1"
    assert built["by_domain"]["www.pyme.waf.local"]["id"] == "a1"
    assert built["by_domain"]["maderera.waf.local"]["id"] == "a2"
    assert built["by_domain"]["api.maderera.waf.local"]["id"] == "a2"
    assert "maderera.waf.local:3000" not in built["by_domain"]
    assert built["by_slug"]["maderera"]["domains"] == [
        "maderera.waf.local",
        "api.maderera.waf.local",
    ]
    assert built["default_app_id"] == "a1"


def test_resolve_by_host_alias_port_uppercase_unknown():
    with cache_ctx(sample_cache()):
        assert waf.resolve_app_by_host("pyme.waf.local")["slug"] == "default"
        assert waf.resolve_app_by_host("MADERERA.WAF.LOCAL.:3000")["slug"] == "maderera"
        assert waf.resolve_app_by_host("api.maderera.waf.local")["slug"] == "maderera"
        assert waf.resolve_app_by_host("unknown.local") is None
        try:
            waf.resolve_request_app("unknown.local")
        except waf.UnknownHostError:
            pass
        else:
            raise AssertionError("un Host desconocido no fue rechazado")


def test_disabled_app_is_rejected():
    with cache_ctx(sample_cache()):
        assert waf.resolve_app_by_host("off.local") is None
        try:
            waf.resolve_request_app("off.local")
        except waf.DisabledAppError:
            return
        raise AssertionError("una app deshabilitada no fue rechazada")


def test_compat_slug_only_when_enabled():
    with cache_ctx(sample_cache()):
        app = waf.resolve_request_app("unknown.local", "maderera", allow_compat=True)
        assert app["slug"] == "maderera"
        try:
            waf.resolve_request_app("unknown.local", "maderera", allow_compat=False)
        except waf.UnknownHostError:
            pass
        else:
            raise AssertionError("allow_compat=False no rechazó el slug")


def test_unknown_host_waf_domain_and_fallback():
    with cache_ctx(sample_cache()):
        original_domain = waf.WAF_DOMAIN
        original_fallback = waf.UNKNOWN_HOST_FALLBACK
        try:
            waf.WAF_DOMAIN = "waf.local"
            waf.UNKNOWN_HOST_FALLBACK = False

            assert waf.resolve_request_app("waf.local")["slug"] == "default"
            try:
                waf.resolve_request_app("unknown.local")
            except waf.UnknownHostError:
                pass
            else:
                raise AssertionError("Host desconocido no levantó UnknownHostError")

            waf.UNKNOWN_HOST_FALLBACK = True
            assert waf.resolve_request_app("unknown.local")["slug"] == "default"
        finally:
            waf.WAF_DOMAIN = original_domain
            waf.UNKNOWN_HOST_FALLBACK = original_fallback


class _FakeConn:
    def __init__(self, app_rows, domain_rows):
        self.app_rows = app_rows
        self.domain_rows = domain_rows

    async def fetch(self, sql, *args):
        if "waf_app_domains" in sql:
            return self.domain_rows
        return self.app_rows


class _FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _FakeAcquire(self.conn)


def test_load_apps_cache_keeps_last_valid_on_empty_or_no_default():
    built = sample_cache()
    with cache_ctx(built):
        original_pool = waf.db_pool
        original_refresh = waf._apps_cache_last_refresh
        try:
            waf._apps_cache_last_refresh = 0.0

            waf.db_pool = _FakePool(_FakeConn([], []))
            ok = asyncio.run(waf.load_apps_cache(force=True))
            assert ok is False
            assert waf.apps_cache is built["apps"]
            assert waf.default_app_id == built["default_app_id"]

            disabled_rows = [
                {
                    "id": "z1",
                    "slug": "default",
                    "domain": "x.local",
                    "backend_url": "http://x-app:80",
                    "enabled": False,
                }
            ]
            waf.db_pool = _FakePool(_FakeConn(disabled_rows, []))
            ok = asyncio.run(waf.load_apps_cache(force=True))
            assert ok is False
            assert waf.apps_cache is built["apps"]
            assert waf.default_app_id == built["default_app_id"]
        finally:
            waf.db_pool = original_pool
            waf._apps_cache_last_refresh = original_refresh


def test_load_apps_cache_replaces_with_valid_data():
    built = sample_cache()
    with cache_ctx(built):
        original_pool = waf.db_pool
        original_refresh = waf._apps_cache_last_refresh
        try:
            waf._apps_cache_last_refresh = 0.0
            rows = [
                {
                    "id": "n1",
                    "slug": "default",
                    "domain": "new.local",
                    "backend_url": "http://new-app:80",
                    "enabled": True,
                }
            ]
            waf.db_pool = _FakePool(_FakeConn(rows, []))
            ok = asyncio.run(waf.load_apps_cache(force=True))
            assert ok is True
            assert waf.default_app_id == "n1"
            assert waf.apps_by_domain["new.local"]["id"] == "n1"
        finally:
            waf.db_pool = original_pool
            waf._apps_cache_last_refresh = original_refresh


def test_resolve_backend_pins_ip_and_preserves_port_path_query():
    original = waf.socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        return [(waf.socket.AF_INET, waf.socket.SOCK_STREAM, 6, "", ("172.18.0.5", port))]

    waf.socket.getaddrinfo = fake
    try:
        pinned = waf.resolve_backend_connection(
            "http://maderera-app:3000", "api/items", "page=1"
        )
        assert pinned.url == "http://172.18.0.5:3000/api/items?page=1", pinned.url
        assert pinned.sni_hostname is None

        pinned_https = waf.resolve_backend_connection(
            "https://pyme.example.com:8443/base", "", ""
        )
        assert pinned_https.url == "https://172.18.0.5:8443/base", pinned_https.url
        assert pinned_https.sni_hostname == "pyme.example.com"
    finally:
        waf.socket.getaddrinfo = original


def test_dns_rebinding_is_blocked_on_each_resolution():
    original = waf.socket.getaddrinfo
    calls = {"n": 0}

    def fake(host, port, *args, **kwargs):
        calls["n"] += 1
        ip = "172.18.0.5" if calls["n"] == 1 else "127.0.0.1"
        return [(waf.socket.AF_INET, waf.socket.SOCK_STREAM, 6, "", (ip, port))]

    waf.socket.getaddrinfo = fake
    try:
        pinned = waf.resolve_backend_connection("http://maderera-app:3000", "x")
        assert pinned.url.startswith("http://172.18.0.5:3000/")
        try:
            waf.resolve_backend_connection("http://maderera-app:3000", "x")
        except waf.UnsafeBackendError:
            return
        raise AssertionError("la segunda resolución a loopback no fue bloqueada")
    finally:
        waf.socket.getaddrinfo = original


def test_reload_apps_requires_admin_jwt():
    from fastapi.testclient import TestClient

    client = TestClient(waf.app)
    assert client.post("/reload_apps").status_code == 401

    malformed = client.post(
        "/reload_apps", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert malformed.status_code == 401, malformed.text

    secret = waf._get_jwt_secret()

    def make_token(role):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"role": role, "exp": int(time.time()) + 60}

        def enc(value):
            raw = json.dumps(value, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        unsigned = f"{enc(header)}.{enc(payload)}"
        sig = hmac.new(secret.encode(), unsigned.encode(), hashlib.sha256).digest()
        return f"{unsigned}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

    forbidden = client.post(
        "/reload_apps",
        headers={"Authorization": f"Bearer {make_token('user')}"},
    )
    assert forbidden.status_code == 403, forbidden.text


if __name__ == "__main__":
    check("parse_backend_url permite redes privadas", test_parse_backend_url_allows_private_networks)
    check("parse_backend_url rechaza destinos prohibidos", test_parse_backend_url_rejects_blocked_targets)
    check("normalize_host", test_normalize_host_strips_port_case_and_trailing_dot)
    check("normalize_cache_domain", test_normalize_cache_domain_rejects_ports_and_schemes)
    check("cache con alias/deshabilitada/descarte", test_build_cache_aliases_disabled_and_discards)
    check("resolución por Host/alias/puerto/mayúsculas/desconocido", test_resolve_by_host_alias_port_uppercase_unknown)
    check("app deshabilitada", test_disabled_app_is_rejected)
    check("compat X-App-Slug sólo development", test_compat_slug_only_when_enabled)
    check("Host desconocido: WAF_DOMAIN y fallback", test_unknown_host_waf_domain_and_fallback)
    check("cache conserva última válida", test_load_apps_cache_keeps_last_valid_on_empty_or_no_default)
    check("cache reemplaza con datos válidos", test_load_apps_cache_replaces_with_valid_data)
    check("pin de IP con puerto/path/query y SNI", test_resolve_backend_pins_ip_and_preserves_port_path_query)
    check("DNS rebinding", test_dns_rebinding_is_blocked_on_each_resolution)
    check("auth de /reload_apps", test_reload_apps_requires_admin_jwt)

    if failures:
        print(f"\n{len(failures)} caso(s) fallaron")
        sys.exit(1)
    print("\nTodos los casos de apps/ml-engine pasaron")
