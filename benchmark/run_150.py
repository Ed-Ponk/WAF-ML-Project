#!/usr/bin/env python3
"""
benchmark/run_150.py — Ejecuta los 150 payloads de inyección contra WAF-ML y otros WAFs.

Uso:
  python3 benchmark/run_150.py                     # Todos los WAFs
  python3 benchmark/run_150.py --waf waf-ml        # Solo WAF-ML
  python3 benchmark/run_150.py --waf all           # Todos (default)
"""

import re
import os
import sys
import json
import time
import csv
import statistics
from datetime import datetime
from urllib.parse import urlencode

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN DE WAFs
# ══════════════════════════════════════════════════════════════════

WAFS = {
    "waf-ml": {
        "name": "WAF-ML",
        "url": "http://localhost:8000",
        "desc": "Propio — Ensemble LGBM+MLP",
    },
    "modsecurity": {
        "name": "ModSecurity",
        "url": "http://localhost:8081",
        "desc": "OWASP CRS Paranoia Level 1",
    },
    "coraza": {
        "name": "Coraza",
        "url": "http://localhost:8082",
        "desc": "Coraza WAF + Caddy + CRS",
    },
    "naxsi": {
        "name": "NAXSI",
        "url": "http://localhost:8083",
        "desc": "nginx + NAXSI module",
    },
}

# ══════════════════════════════════════════════════════════════════
# PARSEADOR DE PAYLOADS
# ══════════════════════════════════════════════════════════════════


def parse_payloads(path: str) -> list[dict]:
    """Parsea el markdown de payloads y devuelve una lista de casos."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    cases = []
    current_cwe = None
    current_count = 0
    lines = text.split("\n")

    i = 0
    while i < len(lines):
        line = lines[i]

        # Detectar CWE header: ## CWE-XXX — Name
        m = re.match(r"^## (CWE-[\d/]+)\s*[—–-]\s*(.+)", line)
        if m:
            current_cwe = f"{m.group(1)} — {m.group(2).strip()}"

        # Detectar línea de payload: 1. `content`
        m = re.match(r"^\d+\.\s+`(.+)`", line)
        if m:
            raw_payload = m.group(1)
            method = "GET"
            endpoint = "/"
            explanation = ""
            cwe = current_cwe or "Unknown"

            # Leer siguientes líneas (indentadas con -)
            j = i + 1
            while j < len(lines):
                sub = lines[j].strip()
                if not sub or sub.startswith("```"):
                    j += 1
                    continue
                mm = re.match(r"^- Método:\s*(GET|POST)", sub, re.IGNORECASE)
                if mm:
                    method = mm.group(1).upper()
                mm = re.match(r"^- Endpoint:\s*(.+)", sub)
                if mm:
                    endpoint = mm.group(1).strip()
                mm = re.match(r"^- Explicación.*:\s*(.+)", sub)
                if mm:
                    explanation = mm.group(1).strip()
                # Dejar de leer cuando encontremos otra línea sin guión
                # o un nuevo payload
                if re.match(r"^\d+\.", sub) or (sub.startswith("#") and not sub.startswith("-")):
                    break
                j += 1

            # Determinar si es JSON body
            is_json = False
            json_payload = None
            try:
                json_payload = json.loads(raw_payload)
                is_json = True
            except (json.JSONDecodeError, ValueError):
                pass

            cases.append({
                "cwe": cwe,
                "cwe_short": current_cwe.split(" — ")[0] if current_cwe and " — " in current_cwe else current_cwe,
                "method": method,
                "endpoint": endpoint,
                "payload": raw_payload,
                "is_json": is_json,
                "json_payload": json_payload,
                "explanation": explanation,
                "expected": "BLOCK",  # Todos los ataques
            })

    return cases


# ══════════════════════════════════════════════════════════════════
# EJECUTOR DE PRUEBAS
# ══════════════════════════════════════════════════════════════════


def test_waf(waf: dict, case: dict, idx: int) -> dict:
    """
    Ejecuta un payload contra un WAF.
    Retorna dict con resultados.
    """
    waf_url = waf["url"]
    method = case["method"]
    endpoint = case["endpoint"]
    payload = case["payload"]
    is_json = case["is_json"]
    timeout = 15.0

    start = time.time()
    error = None
    status = 0
    waf_action = None
    waf_score = None

    try:
        if method == "GET":
            # Construir URL completa: endpoint?query_string
            # Para GET, la payload es la query string
            full_url = f"{waf_url}{endpoint}?{payload}"
            r = requests.get(full_url, timeout=timeout, allow_redirects=False, 
                             headers={"Accept": "application/json"})
        else:
            # POST
            if is_json:
                # JSON body
                full_url = f"{waf_url}{endpoint}"
                r = requests.post(full_url, json=case["json_payload"], timeout=timeout,
                                  allow_redirects=False)
            else:
                # Form data como raw string para preservar encoding
                full_url = f"{waf_url}{endpoint}"
                r = requests.post(full_url, data=payload, timeout=timeout,
                                  allow_redirects=False,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})

        status = r.status_code
        waf_action = r.headers.get("X-WAF-Action")
        score_header = r.headers.get("X-WAF-Score")
        if score_header:
            try:
                waf_score = float(score_header)
            except ValueError:
                waf_score = None

    except requests.exceptions.ConnectionError:
        status = 502
        error = "Connection refused"
    except requests.exceptions.Timeout:
        status = 504
        error = "Timeout"
    except Exception as e:
        status = 599
        error = str(e)

    elapsed_ms = round((time.time() - start) * 1000, 2)

    # Clasificar
    is_blocked = status == 403
    expects_block = case["expected"] == "BLOCK"

    if is_blocked:
        classification = "TP (BLOCK)"
    elif waf_action == "LOG":
        classification = "TP (LOG)"  # Detectado aunque no bloqueado
    else:
        classification = "FN"

    return {
        "id": f"PAYLOAD_{idx:03d}",
        "cwe": case["cwe_short"],
        "description": case["explanation"] or payload[:60],
        "method": method,
        "endpoint": endpoint,
        "payload": payload[:100],
        "status": status,
        "waf_action": waf_action or ("BLOCK" if is_blocked else "ALLOW"),
        "waf_score": waf_score,
        "classification": classification,
        "latency_ms": elapsed_ms,
        "error": error,
    }


# ══════════════════════════════════════════════════════════════════
# REPORTE
# ══════════════════════════════════════════════════════════════════


def print_summary(all_results: dict):
    """Imprime resumen por WAF."""
    print("\n" + "═" * 70)
    print("  📊 RESUMEN — 150 Payloads vs WAFs")
    print("═" * 70)

    for waf_key, results in all_results.items():
        total = len(results)
        blocked = sum(1 for r in results if r["classification"] == "TP (BLOCK)")
        logged = sum(1 for r in results if r["classification"] == "TP (LOG)")
        fn = sum(1 for r in results if r["classification"] == "FN")
        errors = sum(1 for r in results if r["error"])

        latencies = [r["latency_ms"] for r in results if r["latency_ms"] > 0]
        avg_lat = round(statistics.mean(latencies), 2) if latencies else 0
        p95_lat = round(sorted(latencies)[int(len(latencies) * 0.95)], 2) if len(latencies) > 10 else avg_lat

        det_acc = round((blocked + logged) / total * 100, 1) if total else 0

        print(f"\n  {WAFS[waf_key]['name']:15s}")
        print(f"  {'─' * 40}")
        print(f"  BLOCK:    {blocked:3d} / {total} ({round(blocked/total*100, 1)}%)")
        print(f"  LOG:      {logged:3d} / {total} ({round(logged/total*100, 1)}%)")
        print(f"  FN:       {fn:3d} / {total}")
        print(f"  DetAcc:   {det_acc}%")
        print(f"  μLat:     {avg_lat}ms  (P95: {p95_lat}ms)")
        if errors:
            print(f"  ⚠ Errors:  {errors}")

    # Resumen por CWE para WAF-ML
    waf_results = all_results.get("waf-ml", [])
    if waf_results:
        print("\n" + "═" * 70)
        print("  📋 Detalle por CWE — WAF-ML")
        print("═" * 70)
        by_cwe = {}
        for r in waf_results:
            cwe = r["cwe"].split(" —")[0] if " —" in r["cwe"] else r["cwe"]
            by_cwe.setdefault(cwe, {"total": 0, "blocked": 0, "logged": 0, "fn": 0})
            by_cwe[cwe]["total"] += 1
            if r["classification"] == "TP (BLOCK)":
                by_cwe[cwe]["blocked"] += 1
            elif r["classification"] == "TP (LOG)":
                by_cwe[cwe]["logged"] += 1
            else:
                by_cwe[cwe]["fn"] += 1

        for cwe in sorted(by_cwe.keys()):
            d = by_cwe[cwe]
            det = round((d["blocked"] + d["logged"]) / d["total"] * 100, 1)
            print(f"  {cwe:25s}  {d['total']:3d} payloads  →  "
                  f"BLOCK={d['blocked']:3d}  LOG={d['logged']:2d}  "
                  f"FN={d['fn']:2d}  DetAcc={det}%")


def save_results(all_results: dict, output_dir: str):
    """Guarda resultados en CSV y JSON."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON completo
    json_path = os.path.join(output_dir, f"resultado_150_{ts}.json")
    with open(json_path, "w") as f:
        # Convertir a serializable
        serializable = {}
        for waf_key, results in all_results.items():
            serializable[waf_key] = {
                "waf_name": WAFS[waf_key]["name"],
                "results": results,
            }
        json.dump(serializable, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 JSON → {json_path}")

    # CSV detallado
    csv_path = os.path.join(output_dir, f"resultado_150_detalle_{ts}.csv")
    fieldnames = ["id", "cwe", "method", "endpoint", "payload", "status",
                  "waf_action", "waf_score", "classification", "latency_ms", "error"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for waf_key, results in all_results.items():
            for r in results:
                r["waf"] = WAFS[waf_key]["name"]
                writer.writerow(r)
    print(f"  📄 CSV → {csv_path}")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════


def main():
    args = sys.argv[1:]
    selected = "all"
    if args and args[0].startswith("--waf="):
        selected = args[0].split("=", 1)[1]
    elif args and args[0] == "--waf" and len(args) > 1:
        selected = args[1]

    # Parsear payloads
    payload_file = os.path.join(os.path.dirname(__file__), "payloads_150.md")
    if not os.path.exists(payload_file):
        print(f"ERROR: No se encuentra {payload_file}")
        sys.exit(1)

    cases = parse_payloads(payload_file)
    total = len(cases)
    print(f"\n  📦 {total} payloads parseados desde payloads_150.md")
    print(f"  🎯 WAFs seleccionados: {selected}")

    # Verificar conectividad
    waf_keys = list(WAFS.keys()) if selected == "all" else [selected]
    print("\n  🔍 Verificando conectividad de WAFs...")
    for key in waf_keys:
        url = WAFS[key]["url"]
        try:
            r = requests.get(f"{url}/health" if "8000" in url else url,
                             timeout=5, allow_redirects=False)
            print(f"    ✅ {WAFS[key]['name']:15s} → {url}  RESPONDE")
        except Exception as e:
            print(f"    ❌ {WAFS[key]['name']:15s} → {url}  NO RESPONDE ({e})")

    # Ejecutar pruebas
    all_results = {}
    for key in waf_keys:
        waf = WAFS[key]
        print(f"\n  ▶️  Probando {waf['name']} ({total} payloads)...")
        results = []
        for idx, case in enumerate(cases):
            result = test_waf(waf, case, idx + 1)
            results.append(result)

            # Progress bar simple
            progress = (idx + 1) / total
            bar_len = 30
            filled = int(bar_len * progress)
            bar = "█" * filled + "░" * (bar_len - filled)
            if (idx + 1) % 10 == 0 or idx == total - 1:
                b = result["classification"]
                print(f"\r    [{bar}] {idx+1}/{total}  →  {b:12s}  {waf['name']}", end="", flush=True)

        print()
        all_results[key] = results

    # Reportes
    print_summary(all_results)
    save_results(all_results, os.path.join(os.path.dirname(__file__), "results"))


if __name__ == "__main__":
    main()
