"""Multipart upload body exemption and DB payload sanitization.

These tests run against ml-engine/app.py directly (no container required).
"""

import asyncio
import os
import sys
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "ml-engine"))
# Keep the same test model path as test_safe_unpickler.py so import order
# cannot leave app.MODEL_PATH pointing at a different file.
os.environ.setdefault("MODEL_PATH", "test_waf_ensemble_final.pkl")

import app as waf  # noqa: E402


def _fake_features(method, url, payload, include_extras=True):
    return pd.DataFrame(
        [
            {
                "url_path_len": len(url),
                "payload_len": len(payload),
                "payload_entropy": 0.0,
                "count_special_chars": 0,
                "has_any_injection": 0,
                "has_evasion_encoding": 0,
                "has_sql": 0,
                "has_xss": 0,
            }
        ]
    )


def test_parse_upload_paths_is_scoped_by_slug():
    parsed = waf._parse_upload_paths(
        "maderera=/api/uploads|/api/upload/;otro=/x"
    )
    assert parsed == {
        "maderera": ("/api/uploads", "/api/upload"),
        "otro": ("/x",),
    }


def test_multipart_exemption_is_scoped_and_size_limited(monkeypatch):
    monkeypatch.setattr(waf, "UPLOAD_PATHS_BY_SLUG", {"maderera": ("/api/uploads",)})
    monkeypatch.setattr(waf, "MULTIPART_MAX_BYTES", 1024)

    app = {"slug": "maderera"}
    content_type = "multipart/form-data; boundary=abc"

    assert waf._should_exempt_multipart_body(app, "/api/uploads", content_type, 10)
    assert waf._should_exempt_multipart_body(app, "/api/uploads/extra", content_type, 10)
    assert not waf._should_exempt_multipart_body(app, "/api/other", content_type, 10)
    assert not waf._should_exempt_multipart_body(
        {"slug": "otra"}, "/api/uploads", content_type, 10
    )
    assert not waf._should_exempt_multipart_body(
        app, "/api/uploads", "application/json", 10
    )
    assert not waf._should_exempt_multipart_body(app, "/api/uploads", content_type, 2048)


def test_multipart_with_nul_uses_marker_and_does_not_block(monkeypatch):
    built = waf._build_apps_cache(
        [
            {
                "id": "a2",
                "slug": "maderera",
                "domain": "maderera.waf.local",
                "backend_url": "http://maderera-app:3000",
                "enabled": True,
            }
        ],
        [],
    )
    # Sin backend para evitar proxy real: waf_core devuelve el veredicto JSON.
    built["apps"]["a2"]["backend_url"] = ""

    monkeypatch.setattr(waf, "apps_cache", built["apps"])
    monkeypatch.setattr(waf, "apps_by_slug", built["by_slug"])
    monkeypatch.setattr(waf, "apps_by_domain", built["by_domain"])
    monkeypatch.setattr(waf, "default_app_id", built["default_app_id"])
    monkeypatch.setattr(waf, "UPLOAD_PATHS_BY_SLUG", {"maderera": ("/api/uploads",)})
    monkeypatch.setattr(waf, "MULTIPART_MAX_BYTES", 1024)
    monkeypatch.setattr(waf, "db_pool", None)

    captured = {}

    def fake_extract(method, url, payload, include_extras=True):
        captured["payload"] = payload
        return _fake_features(method, url, payload, include_extras)

    async def fake_score(df_raw):
        return 0.05

    monkeypatch.setattr(waf, "extract_features_df", fake_extract)
    monkeypatch.setattr(waf, "get_ensemble_score", fake_score)

    boundary = "----waf-test-boundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="foto.webp"\r\n'
        "Content-Type: image/webp\r\n\r\n"
    ).encode("utf-8") + b"\x00\x01\x02binary" + f"\r\n--{boundary}--\r\n".encode("utf-8")

    client = TestClient(waf.app)
    response = client.post(
        "/api/uploads?target=contenido",
        content=body,
        headers={
            "Host": "maderera.waf.local",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Original-URI": "/api/uploads?target=contenido",
        },
    )

    assert response.status_code == 200, response.text
    assert response.headers["X-WAF-Action"] != "BLOCK"
    assert captured["payload"] == f"[multipart {len(body)} bytes]"
    assert "\x00" not in captured["payload"]


class _FakeConn:
    def __init__(self):
        self.args = None

    async def execute(self, sql, *args):
        stored_payload = args[5]
        if "\x00" in stored_payload:
            raise ValueError('invalid byte sequence for encoding "UTF8": 0x00')
        self.args = args


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


def test_save_to_db_registers_blocked_event_with_nul_payload(monkeypatch):
    conn = _FakeConn()
    monkeypatch.setattr(waf, "db_pool", _FakePool(conn))
    monkeypatch.setattr(waf, "MAX_DB_PAYLOAD_CHARS", 24)

    payload = "inicio\x00" + "x" * 100
    asyncio.run(
        waf.save_to_db(
            "127.0.0.1",
            "ua\x00test",
            "POST",
            "/api/uploads?target=contenido",
            payload,
            0.99,
            1,
            "BLOCK",
            1.0,
            {"url_path_len": 10},
            "a2",
        )
    )

    assert conn.args is not None, "el evento bloqueado no se persistió"
    stored_payload = conn.args[5]
    assert "\x00" not in stored_payload
    assert stored_payload.endswith("...[truncated]")
    assert len(stored_payload) == 24 + len("...[truncated]")
    assert "\x00" not in conn.args[2]  # user_agent
