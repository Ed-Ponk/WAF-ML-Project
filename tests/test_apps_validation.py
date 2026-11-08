"""Runtime tests for the dashboard app validator and PATCH guards.

Runs the real TypeScript module through Node's type stripping so the tests
exercise the same code the API uses, not a copy.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).parent.parent
HARNESS = Path(__file__).parent / "ssrf_cases.mjs"


def _run_harness() -> dict:
    node = shutil.which("node")
    if not node:
        pytest.skip("node no está disponible")

    proc = subprocess.run(
        [node, "--experimental-strip-types", "--no-warnings", str(HARNESS)],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0 and "bad option" in proc.stderr:
        pytest.skip("node no soporta --experimental-strip-types")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def results() -> dict:
    return _run_harness()


def test_ssrf_literal_evasions_are_rejected(results):
    for item in results["rejectedUrls"]:
        assert item["result"]["ok"] is False, f"no se bloqueó {item['url']}"


def test_legitimate_backends_are_allowed(results):
    for item in results["allowedUrls"]:
        assert item["result"]["ok"] is True, f"se bloqueó {item['url']}: {item['result']}"


def test_fc_and_ff_prefixed_hostnames_are_valid(results):
    by_input = {item["input"]: item for item in results["domainCases"]}
    for host in ("fcm.example.com", "ffmpeg.example.com"):
        assert by_input[host]["result"] == {"ok": True, "value": host}

    allowed = {item["url"]: item for item in results["allowedUrls"]}
    for url in ("http://fcm.example.com", "http://ffmpeg.example.com"):
        assert allowed[url]["result"]["ok"] is True


def test_domains_normalize_trailing_dot_and_reject_internal_names(results):
    by_input = {item["input"]: item for item in results["domainCases"]}

    example = by_input["EXAMPLE.COM."]
    assert example["normalized"] == "example.com"
    assert example["result"] == {"ok": True, "value": "example.com"}

    for internal in ("database.", "localhost."):
        assert by_input[internal]["result"]["ok"] is False


def test_slug_cannot_change_on_update(results):
    by_next = {item["next"]: item for item in results["slugCases"]}

    assert by_next[None]["result"]["ok"] is True
    assert by_next["default"]["result"]["ok"] is True
    assert by_next["other"]["result"]["ok"] is False
    assert by_next["other"]["result"]["error"] == "El slug no se puede modificar"


def test_last_enabled_app_cannot_be_disabled(results):
    cases = {(item["current"], item["count"]): item for item in results["disableCases"]}

    assert cases[(True, 2)]["result"]["ok"] is True
    assert cases[(True, 1)]["result"]["ok"] is False
    assert cases[(False, 1)]["result"]["ok"] is True
    assert (
        cases[(True, 1)]["result"]["error"]
        == "No se puede deshabilitar la última aplicación activa"
    )
