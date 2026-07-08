#!/usr/bin/env python3
"""
benchmark/run_150_local.py — Tests offline ejecutando extract_features + modelo directo.
No requiere Docker — ideal para iteración rápida.
"""

import re, os, sys, json, time, statistics, csv
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ml-engine"))

try:
    import joblib
    import pandas as pd
    from extract_features import extract_features
except ImportError as e:
    print(f"ERROR: {e}. Asegúrate de tener joblib, pandas, sklearn instalados.")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# CARGAR MODELO
# ══════════════════════════════════════════════════════════════════

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml-engine", "waf_ensemble_final.pkl")
if not os.path.exists(MODEL_PATH):
    # Intentar dentro del proyecto
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml-engine", "waf_ensemble_final.pkl")
    if not os.path.exists(MODEL_PATH):
        MODEL_PATH = "waf_ensemble_final.pkl"

print(f"📦 Cargando modelo: {MODEL_PATH}")
bundle = joblib.load(MODEL_PATH)
lgbm_model = bundle["lgbm_model"]
mlp_model  = bundle["mlp_model"]
mlp_scaler = bundle["mlp_scaler"]
lgbm_cols  = bundle["lgbm_features"]
mlp_cols   = bundle["mlp_features"]
weights    = bundle["weights"]
th_allow   = bundle.get("thresholds", {}).get("allow", 0.40)
th_block   = bundle.get("thresholds", {}).get("block", 0.70)


def predict(url_raw: str, payload: str, method: str = "GET") -> dict:
    """Ejecuta extract_features + ensemble y devuelve resultado."""
    f = extract_features(method, url_raw, payload)
    df = pd.DataFrame([f])

    # LGBM
    df_lgbm = df.reindex(columns=lgbm_cols, fill_value=0)
    prob_lgbm = lgbm_model.predict(df_lgbm.values)[0]

    # MLP
    df_mlp = df.reindex(columns=mlp_cols, fill_value=0)
    prob_mlp = mlp_model.predict_proba(mlp_scaler.transform(df_mlp.values))[0, 1]

    weighted = (weights["lgbm"] * prob_lgbm + weights["mlp"] * prob_mlp) / (weights["lgbm"] + weights["mlp"])

    if weighted >= th_block:
        action = "BLOCK"
    elif weighted >= th_allow:
        action = "LOG"
    else:
        action = "ALLOW"

    return {
        "score": round(float(weighted), 4),
        "lgbm": round(float(prob_lgbm), 4),
        "mlp": round(float(prob_mlp), 4),
        "action": action,
    }


# ══════════════════════════════════════════════════════════════════
# PARSEAR PAYLOADS
# ══════════════════════════════════════════════════════════════════


def parse_payloads(path: str) -> list[dict]:
    """Parsea el markdown de payloads y devuelve una lista de casos."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    cases = []
    current_cwe = None

    # Split por líneas de payload (## CWE o 1. `backtick`)
    # Procesamos línea por línea
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]

        # CWE header
        m = re.match(r"^## (CWE-[\d/]+)\s*[—–-]\s*(.+)", line)
        if m:
            current_cwe = f"{m.group(1)} — {m.group(2).strip()}"

        # Payload: número + backtick
        m = re.match(r"^\s*(\d+)\.\s+`(.+)`", line)
        if m:
            raw_payload = m.group(2)
            method = "GET"
            endpoint = "/"
            explanation = ""

            # Leer siguientes líneas con guión
            j = i + 1
            while j < len(lines):
                sub = lines[j].strip()
                if sub.startswith("- ") or sub.startswith("— "):
                    mm = re.match(r"^- Método:\s*(GET|POST)", sub, re.IGNORECASE)
                    if mm:
                        method = mm.group(1).upper()
                    mm = re.match(r"^- Endpoint:\s*(.+)", sub)
                    if mm:
                        endpoint = mm.group(1).strip()
                    mm = re.match(r"^- Explicación.*:\s*(.+)", sub)
                    if mm:
                        explanation = mm.group(1).strip()
                else:
                    # Si no empieza con guión, terminamos
                    break
                j += 1

            cases.append({
                "cwe": current_cwe or "Unknown",
                "cwe_short": (current_cwe.split(" — ")[0] if current_cwe and " — " in current_cwe else current_cwe or "Unknown"),
                "method": method,
                "endpoint": endpoint,
                "payload_raw": raw_payload,
                "explanation": explanation,
            })

        i += 1

    return cases


# ══════════════════════════════════════════════════════════════════
# EJECUTAR
# ══════════════════════════════════════════════════════════════════


def main():
    payload_file = os.path.join(os.path.dirname(__file__), "payloads_150.md")
    if not os.path.exists(payload_file):
        print(f"ERROR: No se encuentra {payload_file}")
        sys.exit(1)

    cases = parse_payloads(payload_file)
    total = len(cases)
    print(f"  📦 {total} payloads cargados")

    results = []
    errors = []

    for idx, case in enumerate(cases):
        method = case["method"]
        endpoint = case["endpoint"]
        raw = case["payload_raw"]

        # Construir URL completa
        if method == "GET":
            # La payload es query string: key=value...
            url_raw = f"{endpoint}?{raw}"
            payload_body = ""
        else:
            # POST: endpoint + payload como body
            url_raw = endpoint
            payload_body = raw

        try:
            t0 = time.time()
            result = predict(url_raw, payload_body, method)
            elapsed_ms = round((time.time() - t0) * 1000, 2)

            classification = "TP" if result["action"] in ("BLOCK", "LOG") else "FN"

            results.append({
                "id": f"P{idx+1:03d}",
                "cwe": case["cwe_short"],
                "method": method,
                "endpoint": endpoint,
                "payload": raw[:120],
                "score": result["score"],
                "lgbm": result["lgbm"],
                "mlp": result["mlp"],
                "action": result["action"],
                "classification": classification,
                "latency_ms": elapsed_ms,
                "explanation": case["explanation"],
            })

            # Progress
            if (idx + 1) % 10 == 0 or idx == total - 1:
                bar_len = 25
                filled = int(bar_len * (idx + 1) / total)
                bar = "█" * filled + "░" * (bar_len - filled)
                act = result["action"]
                clf = classification
                print(f"\r    [{bar}] {idx+1}/{total}  {clf:4s} {act:7s}  score={result['score']:.4f}  {raw[:50]:50s}", end="", flush=True)

        except Exception as e:
            errors.append((idx + 1, str(e)))
            results.append({
                "id": f"P{idx+1:03d}",
                "cwe": case["cwe_short"],
                "method": method,
                "endpoint": endpoint,
                "payload": raw[:120],
                "score": 0,
                "action": "ERROR",
                "classification": "ERROR",
                "latency_ms": 0,
                "explanation": str(e),
            })

    print("\n")

    # ═══════════════════════════════════════════════════════════
    # REPORTE
    # ═══════════════════════════════════════════════════════════

    total = len(results)
    blocked = sum(1 for r in results if r["action"] == "BLOCK")
    logged  = sum(1 for r in results if r["action"] == "LOG")
    allowed = sum(1 for r in results if r["action"] == "ALLOW")
    fn      = sum(1 for r in results if r["classification"] == "FN")

    latencies = [r["latency_ms"] for r in results if r["latency_ms"] > 0]
    avg_lat = round(statistics.mean(latencies), 2) if latencies else 0
    p95_lat = round(sorted(latencies)[int(len(latencies) * 0.95)], 2) if len(latencies) > 10 else avg_lat

    det_acc = round((blocked + logged) / total * 100, 1) if total else 0
    blk_acc = round(blocked / total * 100, 1) if total else 0

    print("═" * 70)
    print("  📊 RESULTADO — 150 Payloads vs WAF-ML v3 (offline)")
    print("═" * 70)
    print(f"  BLOCK:      {blocked:3d} / {total}  ({blk_acc}%)")
    print(f"  LOG:        {logged:3d} / {total}  ({round(logged/total*100, 1)}%)")
    print(f"  ALLOW (FN): {allowed:3d} / {total}")
    print(f"  DetAcc:     {det_acc}%")
    print(f"  BlkAcc:     {blk_acc}%")
    print(f"  μLat:       {avg_lat}ms  (P95: {p95_lat}ms)")
    print(f"  Thresholds: ALLOW<{th_allow}  LOG<{th_block}  BLOCK≥{th_block}")

    # Por CWE
    print("\n" + "─" * 70)
    print("  📋 Detalle por CWE")
    print("─" * 70)
    by_cwe = {}
    for r in results:
        cwe = r["cwe"].split(" —")[0] if " —" in r["cwe"] else r["cwe"]
        by_cwe.setdefault(cwe, {"total": 0, "blocked": 0, "logged": 0, "allowed": 0})
        by_cwe[cwe]["total"] += 1
        if r["action"] == "BLOCK":
            by_cwe[cwe]["blocked"] += 1
        elif r["action"] == "LOG":
            by_cwe[cwe]["logged"] += 1
        else:
            by_cwe[cwe]["allowed"] += 1

    for cwe in sorted(by_cwe.keys()):
        d = by_cwe[cwe]
        det = round((d["blocked"] + d["logged"]) / d["total"] * 100, 1)
        print(f"  {cwe:30s}  {d['total']:3d}  →  BLOCK={d['blocked']:3d}  "
              f"LOG={d['logged']:2d}  FN={d['allowed']:2d}  DetAcc={det}%")

    # Errores
    if errors:
        print(f"\n  ⚠️  {len(errors)} errores:")
        for num, err in errors[:5]:
            print(f"     Payload {num}: {err}")

    # Guardar resultados
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(output_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(output_dir, f"resultado_150_offline_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": ts,
            "model": os.path.basename(MODEL_PATH),
            "thresholds": {"allow": th_allow, "block": th_block},
            "summary": {
                "total": total,
                "blocked": blocked,
                "logged": logged,
                "allowed": allowed,
                "det_acc": det_acc,
                "blk_acc": blk_acc,
                "avg_latency_ms": avg_lat,
                "p95_latency_ms": p95_lat,
            },
            "by_cwe": by_cwe,
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 JSON → {json_path}")

    # CSV
    csv_path = os.path.join(output_dir, f"resultado_150_offline_detalle_{ts}.csv")
    fieldnames = ["id", "cwe", "method", "endpoint", "payload", "action", "classification",
                  "score", "lgbm", "mlp", "latency_ms", "explanation"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)
    print(f"  📄 CSV → {csv_path}")


if __name__ == "__main__":
    main()
