#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  WAF Benchmark Suite — Evaluación comparativa de 4 WAFs        ║
║                                                                ║
║  Compara WAF-ML (propio) vs ModSecurity+CRS / Coraza / NAXSI  ║
║  con casos de ataque OWASP A05:2025 y tráfico legítimo.       ║
║                                                                ║
║  Tesis: "WAF open source basado en ML para detección de       ║
║  ataques de inyección OWASP A05:2025 en entornos PYMES"       ║
║  USAT, Perú 2026 — Fernandez Alva, E.                         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import csv
import json
import os
import sys
import time
import statistics
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: Se requiere la librería 'requests'.")
    print("  pip install requests")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# 1. CONFIGURACIÓN DE WAFs
# ══════════════════════════════════════════════════════════════════

@dataclass
class WAFConfig:
    """Representa un WAF a evaluar."""
    name: str
    url: str
    description: str
    port: int


# Cada WAF corre en un puerto diferente del host.
# WAF-ML ya está en :80 desde docker-compose.yml principal.
# Los otros 3 se levantan con docker-compose.benchmark.yml.
WAFS = [
    WAFConfig("WAF-ML",        "http://localhost:8000", "Propio — Ensemble LGBM+MLP",               8000),
    WAFConfig("ModSecurity",   "http://localhost:8081", "OWASP CRS Paranoia Level 1",               8081),
    WAFConfig("Coraza",        "http://localhost:8082", "Coraza WAF + Caddy + CRS",                 8082),
    WAFConfig("NAXSI",         "http://localhost:8083", "nginx + NAXSI module (nbs-system)",        8083),
]


# ══════════════════════════════════════════════════════════════════
# 2. CASOS DE PRUEBA
# ══════════════════════════════════════════════════════════════════

@dataclass
class TestCase:
    """Un caso de prueba individual."""
    id: str
    cwe: str                # CWE identifier or "CLEAN"
    description: str        # Human-readable description
    method: str             # HTTP method: GET or POST
    path: str               # URL path
    expected: str           # "BLOCK" for attacks, "ALLOW" for clean
    params: Optional[dict] = None  # Query parameters (GET)
    data: Optional[dict] = None    # Form/JSON data (POST)
    json_body: Optional[dict] = None  # JSON body (POST with Content-Type: application/json)
    headers: Optional[dict] = None  # Custom headers (User-Agent, Content-Type, etc.)


def build_test_cases() -> list[TestCase]:
    """Construye todos los casos de prueba."""
    cases = []

    # ── SQL Injection clásico — CWE-89 (5 casos) ──────────────
    cases.extend([
        TestCase("SQLI_01", "CWE-89", "SQLi OR tautology — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "' OR '1'='1", "password": "x"}),
        TestCase("SQLI_02", "CWE-89", "SQLi DROP TABLE — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "'; DROP TABLE users;--", "password": "x"}),
        TestCase("SQLI_03", "CWE-89", "SQLi UNION SELECT — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "' UNION SELECT null,email,password FROM users--", "password": "x"}),
        TestCase("SQLI_04", "CWE-89", "SQLi comment close — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "admin'--", "password": "x"}),
        TestCase("SQLI_05", "CWE-89", "SQLi OR true — GET products filter", "GET",
                 "/api/v1/products", "BLOCK", {"search": "' OR '1'='1"}, None),
    ])

    # ── SQL Injection ORM — CWE-564 (2 casos) ─────────────────
    cases.extend([
        TestCase("SQLI_ORM_01", "CWE-564", "SQLi ORM hex encoding — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "0x61646d696e2740", "password": "x"}),
        TestCase("SQLI_ORM_02", "CWE-564", "SQLi ORM comment block — GET clients", "GET",
                 "/api/v1/clients", "BLOCK", {"search": "' OR/**/1=1--"}, None),
    ])

    # ── XSS Reflejado — CWE-79 (3 casos) ─────────────────────
    cases.extend([
        TestCase("XSS_REF_01", "CWE-79", "XSS script tag — GET clients", "GET",
                 "/api/v1/clients", "BLOCK", {"search": "<script>alert('xss')</script>"}, None),
        TestCase("XSS_REF_02", "CWE-79", "XSS img onerror — GET products", "GET",
                 "/api/v1/products", "BLOCK", {"search": "<img src=x onerror=alert(1)>"}, None),
        TestCase("XSS_REF_03", "CWE-79", "XSS javascript URI — GET clients", "GET",
                 "/api/v1/clients", "BLOCK", {"search": "javascript:alert(document.cookie)"}, None),
    ])

    # ── XSS en atributos — CWE-83 (2 casos) ──────────────────
    cases.extend([
        TestCase("XSS_ATTR_01", "CWE-83", "XSS attr onerror — GET products", "GET",
                 "/api/v1/products", "BLOCK", {"search": "\" onerror=\"alert(1)\""}, None),
        TestCase("XSS_ATTR_02", "CWE-83", "XSS body with onmouseover — POST clients", "POST",
                 "/api/v1/clients", "BLOCK", None, {"name": "x\" onmouseover=\"alert(1)\""}),
    ])

    # ── XSS Basic — CWE-80 (1 caso extra) ─────────────────────
    cases.append(
        TestCase("XSS_SVG_01", "CWE-80", "XSS svg onload — GET products", "GET",
                 "/api/v1/products", "BLOCK", {"search": "<svg onload=alert(1)>"}, None),
    )

    # ── Command Injection genérico — CWE-77 (2 casos) ────────
    cases.extend([
        TestCase("CMD_01", "CWE-77", "CMD pipe in document — GET persons", "GET",
                 "/api/v1/persons/find", "BLOCK", {"document": "12345678 | ls -la"}, None),
        TestCase("CMD_02", "CWE-77", "CMD backtick — GET clients", "GET",
                 "/api/v1/clients", "BLOCK", {"search": "`id`"}, None),
    ])

    # ── OS Command Injection — CWE-78 (2 casos) ──────────────
    cases.extend([
        TestCase("CMD_OS_01", "CWE-78", "CMD subshell whoami — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "$(whoami)@test.com", "password": "x"}),
        TestCase("CMD_OS_02", "CWE-78", "CMD exec php — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "test@test.com; phpinfo()", "password": "x"}),
    ])

    # ── Path Traversal — CWE-98 (2 casos) ─────────────────────
    cases.extend([
        TestCase("PATH_01", "CWE-98", "Path traversal passwd — GET repo", "GET",
                 "/api/v1/repository/getForClient/1", "BLOCK", {"path": "../../../../etc/passwd"}, None),
        TestCase("PATH_02", "CWE-98", "Path traversal upload — POST repo", "POST",
                 "/api/v1/repository/upload-file", "BLOCK", None, {"filename": "../../etc/passwd; ls"}),
    ])

    # ── CRLF Injection — CWE-93 (2 casos) ────────────────────
    cases.extend([
        TestCase("CRLF_01", "CWE-93", "CRLF header injection — GET clients", "GET",
                 "/api/v1/clients", "BLOCK", {"search": "test%0d%0aX-Injected: malicious"}, None),
        TestCase("CRLF_02", "CWE-93", "CRLF Set-Cookie — POST login", "POST",
                 "/api/v1/auth/login", "BLOCK", None, {"email": "test@t.com\r\nSet-Cookie: session=hacked", "password": "x"}),
    ])

    # ── Tráfico legítimo — CLEAN (10 casos) ──────────────────
    # Incluye los 5 casos requeridos por el usuario
    cases.extend([
        # R1: Login POST con contraseña que contenga caracteres especiales (!@#)
        TestCase("CLEAN_01", "CLEAN", "Login with special chars in password", "POST",
                 "/api/v1/auth/login", "ALLOW", None,
                 {"email": "admin@atel.com", "password": "P@ss!w0rd#2026!"}),
        # R2: Búsqueda GET con apóstrofe
        TestCase("CLEAN_02", "CLEAN", "Search with apostrophe in value", "GET",
                 "/api/v1/products", "ALLOW", {"q": "zapatos d'italia"}, None),
        # R3: GET con parámetros numéricos
        TestCase("CLEAN_03", "CLEAN", "Numeric params pagination", "GET",
                 "/api/v1/products", "ALLOW", {"id": "123", "pagina": "2", "orden": "precio"}, None),
        # R4: POST con Content-Type: application/json
        TestCase("CLEAN_04", "CLEAN", "JSON body POST", "POST",
                 "/api/v1/auth/login", "ALLOW", None, None,
                 json_body={"email": "user@test.com", "password": "test123"}),
        # R5: Request con User-Agent de Chrome moderno
        TestCase("CLEAN_05", "CLEAN", "Chrome User-Agent header", "GET",
                 "/api/v1/products", "ALLOW", {"limit": "10"}, None,
                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"}),
        # Más casos normales
        TestCase("CLEAN_06", "CLEAN", "GET products list (no params)", "GET",
                 "/api/v1/products", "ALLOW", None, None),
        TestCase("CLEAN_07", "CLEAN", "GET clients list (no params)", "GET",
                 "/api/v1/clients", "ALLOW", None, None),
        TestCase("CLEAN_08", "CLEAN", "GET products search (normal word)", "GET",
                 "/api/v1/products", "ALLOW", {"search": "laptop"}, None),
        TestCase("CLEAN_09", "CLEAN", "GET persons find (numeric doc)", "GET",
                 "/api/v1/persons/find", "ALLOW", {"document": "42345678"}, None),
        TestCase("CLEAN_10", "CLEAN", "GET brands list", "GET",
                 "/api/v1/brands", "ALLOW", None, None),
    ])

    return cases


# ══════════════════════════════════════════════════════════════════
# 3. EJECUTOR DE PRUEBAS
# ══════════════════════════════════════════════════════════════════

@dataclass
class TestResult:
    """Resultado de un caso de prueba en un WAF específico."""
    waf_name: str
    test_id: str
    cwe: str
    description: str
    method: str
    path: str
    expected: str              # "BLOCK" or "ALLOW"
    status_code: int           # HTTP response status code
    actual: str                # "BLOCK" if 403, "ALLOW" otherwise
    classification: str        # "TP", "TN", "FP", or "FN"
    waf_action: Optional[str] = None  # WAF-ML: "BLOCK", "LOG", or "ALLOW"
    latency_ms: float = 0.0   # Response time in milliseconds
    error: Optional[str] = None  # Connection error, timeout, etc.


def run_test(waf: WAFConfig, test: TestCase) -> TestResult:
    """
    Ejecuta un caso de prueba contra un WAF.
    Retorna el resultado con métricas.
    """
    url = f"{waf.url}{test.path}"
    headers = {}

    # Headers por defecto
    if test.headers:
        headers.update(test.headers)

    # Si es JSON body, forzar Content-Type
    if test.json_body:
        headers.setdefault("Content-Type", "application/json")
    else:
        headers.setdefault("Accept", "application/json")

    # Timeout generoso para evitar falsos positivos por latencia
    timeout = 15.0

    start = time.time()
    error = None
    status = 0
    try:
        if test.json_body:
            r = requests.request(
                test.method, url,
                params=test.params,
                json=test.json_body,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            r = requests.request(
                test.method, url,
                params=test.params,
                data=test.data,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        status = r.status_code
        waf_action = r.headers.get("X-WAF-Action")
    except requests.exceptions.ConnectionError:
        status = 502
        error = "Connection refused"
        waf_action = None
    except requests.exceptions.Timeout:
        status = 504
        error = "Timeout"
        waf_action = None
    except Exception as e:
        status = 599
        error = str(e)
        waf_action = None

    elapsed_ms = round((time.time() - start) * 1000, 2)

    # Clasificar resultado
    # Para WAFs con tres zonas (como WAF-ML), usamos X-WAF-Action:
    #   LOG → el modelo detectó el ataque pero no bloqueó (umbral medio)
    #   BLOCK → el modelo bloqueó
    #   ALLOW → el modelo no detectó nada
    #
    # Para WAFs tradicionales (ModSec, Coraza, NAXSI):
    #   403 = BLOCK, cualquier otro = ALLOW
    is_blocked = status == 403
    is_logged = waf_action == "LOG"
    expects_block = test.expected == "BLOCK"

    if is_blocked and expects_block:
        classification = "TP"
    elif is_logged and expects_block:
        classification = "TP"  # Detectado aunque no bloqueado (zona LOG)
    elif not is_blocked and not is_logged and not expects_block:
        classification = "TN"
    elif (is_blocked or is_logged) and not expects_block:
        classification = "FP"
    elif not is_blocked and not is_logged and expects_block:
        classification = "FN"
    else:
        classification = "FN"

    if waf_action:
        actual_action = waf_action
    else:
        actual_action = "BLOCK" if is_blocked else "ALLOW"

    return TestResult(
        waf_name=waf.name,
        test_id=test.id,
        cwe=test.cwe,
        description=test.description,
        method=test.method,
        path=test.path,
        expected=test.expected,
        status_code=status,
        actual=actual_action,
        latency_ms=elapsed_ms,
        classification=classification,
        waf_action=waf_action,
        error=error,
    )


# ══════════════════════════════════════════════════════════════════
# 4. MÉTRICAS Y REPORTES
# ══════════════════════════════════════════════════════════════════

@dataclass
class Metrics:
    """Métricas calculadas para un WAF."""
    waf_name: str
    # Métricas combinadas (BLOCK + LOG cuentan como detección)
    tp: int
    tn: int
    fp: int
    fn: int
    total: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    fpr: float
    # Métricas de bloqueo estricto (solo 403 cuenta como BLOCK)
    block_tp: int
    block_fn: int
    block_recall: float
    block_accuracy: float
    # Latencia
    avg_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    latency_samples: int
    attack_accuracy: float    # Detección solo en ataques
    clean_accuracy: float     # Acierto solo en tráfico limpio


def compute_metrics(waf_name: str, results: list[TestResult]) -> Metrics:
    """Calcula todas las métricas para un WAF."""
    waf_results = [r for r in results if r.waf_name == waf_name]
    attack_results = [r for r in waf_results if r.cwe != "CLEAN"]
    clean_results = [r for r in waf_results if r.cwe == "CLEAN"]

    tp = sum(1 for r in waf_results if r.classification == "TP")
    tn = sum(1 for r in waf_results if r.classification == "TN")
    fp = sum(1 for r in waf_results if r.classification == "FP")
    fn = sum(1 for r in waf_results if r.classification == "FN")
    total = len(waf_results)

    # Métricas de bloqueo estricto (solo HTTP 403)
    block_tp = sum(1 for r in attack_results if r.status_code == 403)
    block_fn = len(attack_results) - block_tp

    attack_tp = sum(1 for r in attack_results if r.classification == "TP")
    attack_fn = sum(1 for r in attack_results if r.classification == "FN")
    clean_tn = sum(1 for r in clean_results if r.classification == "TN")
    clean_fp = sum(1 for r in clean_results if r.classification == "FP")

    # Latencia
    latencies = [r.latency_ms for r in waf_results if r.error is None]
    if latencies:
        avg_lat = round(statistics.mean(latencies), 2)
        sorted_lat = sorted(latencies)
        idx95 = max(0, int(len(sorted_lat) * 0.95) - 1)
        p95 = sorted_lat[idx95]
        min_lat = min(latencies)
        max_lat = max(latencies)
    else:
        avg_lat = p95 = min_lat = max_lat = 0.0

    # Métricas con protección de división por cero
    def safe_div(a, b):
        return round(a / b * 100, 2) if b else 0.0

    accuracy = safe_div(tp + tn, total)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) > 0 else 0.0
    fpr = safe_div(fp, fp + tn)
    attack_acc = safe_div(attack_tp, attack_tp + attack_fn)
    clean_acc = safe_div(clean_tn, clean_tn + clean_fp)

    block_recall_val = safe_div(block_tp, block_tp + block_fn)
    block_accuracy_val = safe_div(block_tp + clean_tn, total)

    return Metrics(
        waf_name=waf_name,
        tp=tp, tn=tn, fp=fp, fn=fn,
        total=total,
        accuracy=accuracy, precision=precision,
        recall=recall, f1_score=f1, fpr=fpr,
        block_tp=block_tp, block_fn=block_fn,
        block_recall=block_recall_val,
        block_accuracy=block_accuracy_val,
        avg_latency_ms=avg_lat, p95_latency_ms=p95,
        min_latency_ms=min_lat, max_latency_ms=max_lat,
        latency_samples=len(latencies),
        attack_accuracy=attack_acc,
        clean_accuracy=clean_acc,
    )


# ══════════════════════════════════════════════════════════════════
# 5. SALIDA DE RESULTADOS
# ══════════════════════════════════════════════════════════════════

def print_table_header():
    """Imprime encabezado de tabla comparativa."""
    print()
    print(f"{'WAF':<15} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} "
          f"{'DetAcc%':>7} {'BlkAcc%':>7} {'Rec%':>6} {'FPR%':>6} "
          f"{'μLat':>6}")
    print("─" * 72)


def print_table_row(m: Metrics):
    """Imprime una fila de la tabla."""
    print(f"{m.waf_name:<15} {m.tp:>4} {m.tn:>4} {m.fp:>4} {m.fn:>4} "
          f"{m.accuracy:>6.1f}% {m.block_accuracy:>6.1f}% {m.recall:>5.1f}% {m.fpr:>5.1f}% "
          f"{m.avg_latency_ms:>6.1f}")


def print_detailed_report(results: list[TestResult]):
    """Imprime reporte detallado por WAF y categoría CWE."""
    for waf in WAFS:
        waf_results = [r for r in results if r.waf_name == waf.name]
        if not waf_results:
            continue

        misclassified = [r for r in waf_results
                         if r.classification in ("FP", "FN")]
        if not misclassified:
            continue

        print(f"\n  ⚠️  {waf.name} — Casos incorrectos:")
        for r in misclassified:
            icon = "✗ FN" if r.classification == "FN" else "✗ FP"
            print(f"    {icon}  {r.test_id:12s}  {r.description:45s}  "
                  f"[{r.expected}→{r.actual}] HTTP {r.status_code}"
                  + (f" ({r.error})" if r.error else ""))


def export_csv(results: list[TestResult], metrics: list[Metrics], output_dir: str):
    """Exporta resultados detallados a CSV."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV detallado
    path = os.path.join(output_dir, f"resultados_detalle_{ts}.csv")
    fieldnames = ["waf_name", "test_id", "cwe", "description", "method", "path",
                  "expected", "actual", "status_code", "latency_ms", "classification", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = asdict(r)
            row = {k: v for k, v in row.items() if k in fieldnames}
            writer.writerow(row)
    print(f"\n  📄 CSV detallado → {path}")

    # CSV resumen por WAF
    path2 = os.path.join(output_dir, f"resumen_wafs_{ts}.csv")
    met_fields = ["waf_name", "tp", "tn", "fp", "fn", "total",
                  "accuracy", "precision", "recall", "f1_score", "fpr",
                  "avg_latency_ms", "p95_latency_ms",
                  "attack_accuracy", "clean_accuracy"]
    with open(path2, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=met_fields)
        writer.writeheader()
        for m in metrics:
            row = {k: v for k, v in asdict(m).items() if k in met_fields}
            writer.writerow(row)
    print(f"  📄 CSV resumen   → {path2}")


def export_json(results: list[TestResult], metrics: list[Metrics], output_dir: str):
    """Exporta resultados completos a JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"reporte_completo_{ts}.json")

    # Agrupar resultados por WAF
    by_waf = {}
    for waf in WAFS:
        waf_results = [r for r in results if r.waf_name == waf.name]
        by_waf[waf.name] = {
            "config": asdict(waf),
            "results": [asdict(r) for r in waf_results],
        }

    report = {
        "metadata": {
            "titulo": "Benchmark de Web Application Firewalls — OWASP A05:2025",
            "tesis": "WAF open source basado en ML para detección de ataques de inyección",
            "autor": "Fernandez Alva, E.",
            "universidad": "USAT - Perú",
            "fecha": datetime.now().isoformat(),
            "total_wafs": len(WAFS),
            "total_casos": len(results) // len(WAFS) if results else 0,
        },
        "wafs": by_waf,
        "metricas": [asdict(m) for m in metrics],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"  📄 JSON completo → {path}")


def print_hypothesis_evaluation(metrics: list[Metrics]):
    """Evalúa la hipótesis de la tesis."""
    waf_ml = next((m for m in metrics if m.waf_name == "WAF-ML"), None)
    modsec = next((m for m in metrics if m.waf_name == "ModSecurity"), None)

    if not waf_ml or not modsec:
        return

    print(f"\n{'═' * 60}")
    print(f"  📐 EVALUACIÓN DE HIPÓTESIS")
    print(f"{'═' * 60}")

    # Hipótesis 1: FPR reducción ≥ 30%
    if modsec.fpr > 0:
        fpr_reduction = round((modsec.fpr - waf_ml.fpr) / modsec.fpr * 100, 2)
        passes_fpr = fpr_reduction >= 30
        print(f"\n  H1: Reducción de FPR ≥ 30% vs ModSecurity")
        print(f"      ModSecurity FPR: {modsec.fpr:.2f}%")
        print(f"      WAF-ML FPR:      {waf_ml.fpr:.2f}%")
        print(f"      Reducción:       {fpr_reduction:.2f}%")
        print(f"      ✓ VERIFICADA" if passes_fpr else f"      ✗ NO VERIFICADA (objetivo: ≥30%)")
    else:
        print(f"\n  H1: No es posible calcular — ModSecurity FPR = 0%")
        print(f"      (Ambos WAFs tienen FPR=0% — hipótesis no aplica)")

    # Hipótesis 2: Latencia promedio < 50ms
    passes_lat = waf_ml.avg_latency_ms < 50
    print(f"\n  H2: Latencia promedio < 50ms")
    print(f"      WAF-ML latencia promedio: {waf_ml.avg_latency_ms:.2f}ms")
    print(f"      ✓ VERIFICADA" if passes_lat else f"      ✗ NO VERIFICADA (excede 50ms)")

    p95_pass = waf_ml.p95_latency_ms < 100
    print(f"\n  H2b: P95 de latencia < 100ms (sobrecarga aceptable)")
    print(f"      WAF-ML P95: {waf_ml.p95_latency_ms:.2f}ms")
    print(f"      ✓ VERIFICADA" if p95_pass else f"      ✗ NO VERIFICADA")


# ══════════════════════════════════════════════════════════════════
# 6. FUNCIÓN PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def check_waf_health() -> dict[str, bool]:
    """Verifica que todos los WAFs respondan antes del benchmark."""
    health = {}
    for waf in WAFS:
        try:
            r = requests.get(f"{waf.url}/health", timeout=5)
            health[waf.name] = r.status_code in (200, 404)
        except Exception:
            health[waf.name] = False
    return health


def main():
    print(f"\n{'═' * 70}")
    print(f"  🔬 WAF BENCHMARK SUITE — OWASP A05:2025")
    print(f"  Tesis: WAF open source basado en ML para la detección")
    print(f"         de ataques de inyección en entornos PYMES simulados")
    print(f"  Autor: Fernandez Alva, E. — USAT, Perú 2026")
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 70}")

    # ── Verificar conectividad ──────────────────────────────────
    print(f"\n  🔍 Verificando conectividad de WAFs...")
    health = check_waf_health()
    all_healthy = True
    for name, ok in health.items():
        status = "✅" if ok else "❌"
        status_txt = "RESPONDE" if ok else "SIN RESPUESTA"
        waf = next(w for w in WAFS if w.name == name)
        print(f"    {status} {name:<15s} → {waf.url:<25s} {status_txt}")
        if not ok:
            all_healthy = False

    if not all_healthy:
        print(f"\n  ⚠️  Algunos WAFs no responden. Verifica que estén corriendo:")
        print(f"     docker compose -f benchmark/docker-compose.benchmark.yml up -d")
        proceed = input(f"\n  ¿Continuar de todas formas? (s/N): ").strip().lower()
        if proceed != "s":
            print("  Benchmark cancelado.")
            return

    # ── Construir casos de prueba ───────────────────────────────
    test_cases = build_test_cases()
    attack_cases = [t for t in test_cases if t.expected == "BLOCK"]
    clean_cases = [t for t in test_cases if t.expected == "ALLOW"]

    print(f"\n  📋 Resumen de casos de prueba:")
    print(f"     Ataques:        {len(attack_cases)} casos")
    print(f"     Tráfico limpio: {len(clean_cases)} casos")
    print(f"     Total:          {len(test_cases)} casos × {len(WAFS)} WAFs = {len(test_cases) * len(WAFS)} pruebas")
    print(f"\n  ▶️  Ejecutando benchmark (esto puede tomar varios minutos)...")

    # ── Ejecutar pruebas ────────────────────────────────────────
    all_results: list[TestResult] = []
    total_tests = len(test_cases) * len(WAFS)
    completed = 0

    for i, test in enumerate(test_cases):
        for waf in WAFS:
            result = run_test(waf, test)
            all_results.append(result)
            completed += 1

            # Progreso
            pct = completed / total_tests * 100
            if result.classification in ("FP", "FN"):
                marker = "✗" if result.classification == "FN" else "⚠"
                print(f"    [{completed:>3}/{total_tests}] {marker} {waf.name:<12s} {test.id:<12s} "
                      f"→ {result.classification} (HTTP {result.status_code}, {result.latency_ms:.0f}ms)"
                      + (f" {result.error}" if result.error else ""))

        # Barra de progreso cada 5 casos
        if (i + 1) % 5 == 0:
            pct = completed / total_tests * 100
            bar = "█" * int(pct // 5) + "░" * (20 - int(pct // 5))
            print(f"    [{bar}] {completed}/{total_tests} ({pct:.0f}%)")

    print(f"    [{'█' * 20}] {completed}/{total_tests} (100%) — COMPLETADO")

    # ── Calcular métricas ──────────────────────────────────────
    metrics_list = [compute_metrics(waf.name, all_results) for waf in WAFS]

    # ── Tabla comparativa ──────────────────────────────────────
    print(f"\n{'═' * 70}")
    print(f"  📊 TABLA COMPARATIVA — RESULTADOS DEL BENCHMARK")
    print(f"{'═' * 70}")
    print_table_header()
    for m in metrics_list:
        print_table_row(m)
    print("─" * 70)

    # ── Reporte detallado ──────────────────────────────────────
    print_detailed_report(all_results)

    # ── Evaluación de hipótesis ────────────────────────────────
    print_hypothesis_evaluation(metrics_list)

    # ── Exportar resultados ────────────────────────────────────
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(output_dir, exist_ok=True)

    export_csv(all_results, metrics_list, output_dir)
    export_json(all_results, metrics_list, output_dir)

    print(f"\n{'═' * 70}")
    print(f"  ✅ BENCHMARK COMPLETADO")
    print(f"  Resultados guardados en: {output_dir}")
    print(f"{'═' * 70}")
    print()


if __name__ == "__main__":
    main()
