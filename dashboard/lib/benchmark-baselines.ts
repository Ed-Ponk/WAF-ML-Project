/**
 * ══════════════════════════════════════════════════════════════════
 * Benchmark Baselines — WAF-ML Engine v2.0
 *
 * Fuente: docs/benchmark-resultados.md (Fase 2)
 * Benchmark ejecutado con 224 casos (92 ataques + 132 limpios)
 * contra 8+ CWEs OWASP A05:2025.
 *
 * Valor metodológico: todos los WAFs se evaluaron sobre el MISMO
 * conjunto de 224 casos, en el mismo entorno, con la misma métrica.
 * NO mezclar con datos de producción en vivo para comparación directa.
 * ══════════════════════════════════════════════════════════════════
 */

export interface BaselineEntry {
  name: string;
  source: "benchmark" | "live";
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  fpr_pct: number;
  recall_pct: number;
  detacc_pct: number;
}

/** Fecha de ejecución del benchmark (docs/benchmark-resultados.md) */
export const BENCHMARK_DATE = "2026-06 (Fase 2 — 224 casos)";

/** Total de casos evaluados en el benchmark */
export const BENCHMARK_TOTAL_CASES = 224;

/** Casos de ataque en el benchmark */
export const BENCHMARK_ATTACK_CASES = 92;

/** Casos legítimos en el benchmark */
export const BENCHMARK_CLEAN_CASES = 132;

// ── WAF-ML (propio) ──────────────────────────────────────────────
export const WAF_ML_BENCHMARK: BaselineEntry = {
  name: "WAF-ML (LGBM+MLP)",
  source: "benchmark",
  true_positives: 91,
  false_positives: 0,
  true_negatives: 132,
  false_negatives: 1,
  fpr_pct: 0.0,
  recall_pct: 98.9,
  detacc_pct: 99.6,
};

// ── Baselines externos (mismos 224 casos, mismo entorno) ────────
export const BASELINES: BaselineEntry[] = [
  {
    name: "ModSecurity + OWASP CRS",
    source: "benchmark",
    true_positives: 79,
    false_positives: 0,
    true_negatives: 132,
    false_negatives: 13,
    fpr_pct: 0.0,
    recall_pct: 85.9,
    detacc_pct: 94.2,
  },
  {
    name: "Coraza + CRS",
    source: "benchmark",
    true_positives: 79,
    false_positives: 0,
    true_negatives: 132,
    false_negatives: 13,
    fpr_pct: 0.0,
    recall_pct: 85.9,
    detacc_pct: 94.2,
  },
  {
    name: "NAXSI",
    source: "benchmark",
    true_positives: 84,
    false_positives: 0,
    true_negatives: 132,
    false_negatives: 8,
    fpr_pct: 0.0,
    recall_pct: 91.3,
    detacc_pct: 96.4,
  },
];

/** Límite superior del IC de Wilson (95%) para FPR=0 con n=132 */
export const WILSON_CI_UPPER_PCT = 2.76;
