import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { generatePDF } from "@/lib/reports";
import {
  BENCHMARK_DATE, BENCHMARK_TOTAL_CASES,
  BENCHMARK_ATTACK_CASES, BENCHMARK_CLEAN_CASES,
  WAF_ML_BENCHMARK, BASELINES, WILSON_CI_UPPER_PCT,
} from "@/lib/benchmark-baselines";
import { authenticate } from "@/lib/auth";

// ---------------------------------------------------------------------------
// CONSTANTES
// ---------------------------------------------------------------------------

/** Referencia del benchmark para cálculos de desviación (WAF-ML) */
const BENCHMARK = {
  true_positives: WAF_ML_BENCHMARK.true_positives,
  false_positives: WAF_ML_BENCHMARK.false_positives,
  true_negatives: WAF_ML_BENCHMARK.true_negatives,
  false_negatives: WAF_ML_BENCHMARK.false_negatives,
  total_cases: BENCHMARK_TOTAL_CASES,
  fpr_pct: WAF_ML_BENCHMARK.fpr_pct,
  recall_pct: WAF_ML_BENCHMARK.recall_pct,
  detacc_pct: WAF_ML_BENCHMARK.detacc_pct,
  wilson_ci_upper_pct: WILSON_CI_UPPER_PCT,
};

/** Umbral de desviación relativa: si FPR real supera 1.5x el FPR del benchmark */
const FPR_DEVIATION_THRESHOLD = 1.5;
/** Umbral de crecimiento de zona LOG para recomendar reentrenamiento */
const LOG_TREND_THRESHOLD_PCT = 20;

/**
 * Mapeo de features → categorías CWE para el reporte.
 *
 * NOTA: Los features del ensemble no distinguen subcategorías (ej. CWE-79 vs CWE-80),
 * por lo que algunas se agrupan. El desglose exacto por CWE solo es posible
 * con el dataset etiquetado del benchmark, no con features_json en producción.
 */
const CWE_MAP: Array<{
  cwe: string;
  nombre: string;
  feature_key: string;
  benchmark_recall_pct: number;
}> = [
  { cwe: "CWE-89",  nombre: "SQL Injection",                feature_key: "has_sql",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-564", nombre: "SQLi ORM",                     feature_key: "has_sql",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-79",  nombre: "XSS Reflejado",                feature_key: "has_xss",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-80",  nombre: "XSS Básico",                   feature_key: "has_xss",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-83",  nombre: "XSS Atributo",                 feature_key: "has_xss",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-93",  nombre: "CRLF Injection",               feature_key: "has_crlf",    benchmark_recall_pct: 90.0 },
  { cwe: "CWE-77",  nombre: "CMD Injection",                feature_key: "has_rce",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-78",  nombre: "OS Command Injection",         feature_key: "has_rce",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-22",  nombre: "Path Traversal",               feature_key: "has_path",    benchmark_recall_pct: 100.0 },
  { cwe: "CWE-90",  nombre: "LDAP Injection",               feature_key: "has_ldap",    benchmark_recall_pct: 100.0 },
  { cwe: "CWE-611", nombre: "XXE",                          feature_key: "has_xxe",     benchmark_recall_pct: 100.0 },
  { cwe: "CWE-601", nombre: "Open Redirect",                feature_key: "has_open_redirect", benchmark_recall_pct: 100.0 },
];

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

function parseWindow(window?: string | null): { days: number; label: string } {
  if (window === "30d") return { days: 30, label: "30d" };
  return { days: 7, label: "7d" }; // default
}

function computeDateRange(days: number): { since: Date; until: Date } {
  const until = new Date();
  const since = new Date(until.getTime() - days * 86_400_000);
  return { since, until };
}

interface ScoreBucket {
  bucket: string;
  count: number;
  percentage: number;
}

function buildScoreBuckets(scores: number[], total: number): ScoreBucket[] {
  const buckets: Record<string, number> = {};
  for (let i = 0; i < 10; i++) {
    const lo = (i / 10).toFixed(1);
    const hi = ((i + 1) / 10).toFixed(1);
    buckets[`${lo}-${hi}`] = 0;
  }

  for (const s of scores) {
    const idx = Math.min(Math.floor(s * 10), 9);
    const lo = (idx / 10).toFixed(1);
    const hi = ((idx + 1) / 10).toFixed(1);
    buckets[`${lo}-${hi}`] = (buckets[`${lo}-${hi}`] || 0) + 1;
  }

  return Object.entries(buckets).map(([bucket, count]) => ({
    bucket,
    count,
    percentage: total > 0 ? parseFloat(((count / total) * 100).toFixed(2)) : 0,
  }));
}

interface ZoneDay {
  dia: string;
  allow_pct: number;
  log_pct: number;
  block_pct: number;
}

/**
 * Calcula tendencia lineal simple (pendiente) de una serie de valores.
 * Retorna el cambio porcentual relativo entre el inicio y el final estimado.
 */
function computeTrendPct(values: number[]): number | null {
  if (values.length < 2) return null;
  const n = values.length;
  const indices = values.map((_, i) => i);
  const meanX = (n - 1) / 2;
  const meanY = values.reduce((a, b) => a + b, 0) / n;

  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    const dx = i - meanX;
    const dy = values[i] - meanY;
    num += dx * dy;
    den += dx * dx;
  }

  if (den === 0) return null;
  const slope = num / den; // cambio absoluto por día
  // Cambio relativo sobre todo el periodo
  const startEst = meanY - slope * meanX;
  if (startEst === 0) return null;
  return parseFloat(((slope * (n - 1)) / startEst * 100).toFixed(2));
}

// ---------------------------------------------------------------------------
// ROUTE HANDLER
// ---------------------------------------------------------------------------

export async function GET(request: NextRequest) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;

  try {
    const { searchParams } = new URL(request.url);
    const format = searchParams.get("format") || "pdf";
    const windowRaw = searchParams.get("window");
    const { days, label: windowLabel } = parseWindow(windowRaw);
    const { since, until } = computeDateRange(days);

    const sinceStr = since.toISOString();
    const untilStr = until.toISOString();

    // =====================================================================
    // 1. SCORE DISTRIBUTION
    // =====================================================================
    const scoreRes = await query(
      `SELECT score_ml
       FROM waf_events
       WHERE fecha >= $1::timestamptz AND fecha <= $2::timestamptz
       ORDER BY score_ml`,
      [sinceStr, untilStr]
    );
    const allScores = scoreRes.rows.map((r: any) => Number(r.score_ml ?? 0));
    const totalEvents = allScores.length;
    const scoreBuckets = buildScoreBuckets(allScores, totalEvents);

    // =====================================================================
    // 2. EVENTS + ZONE DISTRIBUTION BY DAY
    // =====================================================================
    const zoneRes = await query(
      `SELECT DATE(fecha) as dia,
              COUNT(*) as total,
              COUNT(*) FILTER (WHERE accion = 'ALLOW') as allowed,
              COUNT(*) FILTER (WHERE accion = 'LOG') as logged,
              COUNT(*) FILTER (WHERE accion = 'BLOCK') as blocked
       FROM waf_events
       WHERE fecha >= $1::timestamptz AND fecha <= $2::timestamptz
       GROUP BY DATE(fecha)
       ORDER BY dia`,
      [sinceStr, untilStr]
    );

    const zoneByDay: ZoneDay[] = zoneRes.rows.map((r: any) => {
      const t = Number(r.total || 1);
      return {
        dia: r.dia,
        allow_pct: parseFloat(((Number(r.allowed || 0) / t) * 100).toFixed(2)),
        log_pct: parseFloat(((Number(r.logged || 0) / t) * 100).toFixed(2)),
        block_pct: parseFloat(((Number(r.blocked || 0) / t) * 100).toFixed(2)),
      };
    });

    const logPcts = zoneByDay.map((d) => d.log_pct);
    const logTrendPct = computeTrendPct(logPcts);
    const logTrendDirection =
      logTrendPct !== null
        ? logTrendPct > 0
          ? "increasing"
          : logTrendPct < 0
            ? "decreasing"
            : "stable"
        : "insufficient_data";

    // Aggregate zone totals
    const zoneAgg = zoneRes.rows.reduce(
      (acc: any, r: any) => {
        acc.allowed += Number(r.allowed || 0);
        acc.logged += Number(r.logged || 0);
        acc.blocked += Number(r.blocked || 0);
        return acc;
      },
      { allowed: 0, logged: 0, blocked: 0 }
    );
    const zoneTotal = zoneAgg.allowed + zoneAgg.logged + zoneAgg.blocked || 1;

    // =====================================================================
    // 3. GROUND TRUTH (etiqueta_real) — si existe en la ventana
    // =====================================================================
    const gtRes = await query(
      `SELECT veredicto, accion, etiqueta_real, features_json
       FROM waf_events
       WHERE fecha >= $1::timestamptz
         AND fecha <= $2::timestamptz
         AND etiqueta_real IS NOT NULL`,
      [sinceStr, untilStr]
    );

    const hasGroundTruth = gtRes.rows.length > 0;

    let fprComputed: number | null = null;
    let recallComputed: number | null = null;
    let fprDeviation: number | null = null;
    let recallDeviation: number | null = null;
    let desviacionDetectada = false;

    if (hasGroundTruth) {
      let TP = 0, FP = 0, TN = 0, FN = 0;
      for (const row of gtRes.rows) {
        const real = Number(row.etiqueta_real);
        const verdict = Number(row.veredicto);
        if (real === 1 && verdict === 1) TP++;
        else if (real === 0 && verdict === 1) FP++;
        else if (real === 0 && verdict === 0) TN++;
        else if (real === 1 && verdict === 0) FN++;
      }

      // FPR = FP / (FP + TN)
      // Recall = TP / (TP + FN)
      const fprDen = FP + TN;
      const recallDen = TP + FN;
      fprComputed = fprDen > 0
        ? parseFloat(((FP / fprDen) * 100).toFixed(4))
        : 0;
      recallComputed = recallDen > 0
        ? parseFloat(((TP / recallDen) * 100).toFixed(2))
        : null;

      // Desviación contra benchmark
      if (fprComputed !== null) {
        if (BENCHMARK.fpr_pct > 0) {
          // FPR ratio contra benchmark (ej. 2.5 = 2.5x el FPR del benchmark)
          fprDeviation = parseFloat((fprComputed / BENCHMARK.fpr_pct).toFixed(2));
          if (fprComputed > BENCHMARK.fpr_pct * FPR_DEVIATION_THRESHOLD) {
            desviacionDetectada = true;
          }
        } else if (fprComputed > BENCHMARK.wilson_ci_upper_pct) {
          // Benchmark tiene FPR=0.0% — comparamos contra Wilson CI upper bound
          fprDeviation = parseFloat((fprComputed / Math.max(BENCHMARK.wilson_ci_upper_pct, 0.01)).toFixed(2));
          if (fprComputed > BENCHMARK.wilson_ci_upper_pct * FPR_DEVIATION_THRESHOLD) {
            desviacionDetectada = true;
          }
        }
      }
      if (recallComputed !== null && BENCHMARK.recall_pct > 0) {
        recallDeviation = parseFloat(((recallComputed - BENCHMARK.recall_pct) / BENCHMARK.recall_pct * 100).toFixed(2));
      }
    }

    // =====================================================================
    // 4. RECALL POR CWE (solo si hay ground truth)
    // =====================================================================
    interface CWERecall {
      cwe: string;
      nombre: string;
      benchmark_recall_pct: number;
      total_muestras: number;
      blocked: number;
      recall_pct: number | null;
      muestra_insuficiente: boolean;
    }

    let cweRecall: CWERecall[] = [];

    if (hasGroundTruth) {
      // Construir un mapa: para cada evento con ground truth, determinar su CWE
      // y contar TP/FN por CWE
      const cweCounts: Record<string, { total: number; blocked: number }> = {};

      for (const row of gtRes.rows) {
        const real = Number(row.etiqueta_real);
        if (real !== 1) continue; // solo nos interesan ataques reales para recall
        const features = typeof row.features_json === "string"
          ? JSON.parse(row.features_json)
          : row.features_json || {};

        // Determinar CWE desde features
        const matchedCwe = CWE_MAP.find((c) => features[c.feature_key] === 1);
        const cweKey = matchedCwe?.cwe || "OTRO";
        if (!cweCounts[cweKey]) cweCounts[cweKey] = { total: 0, blocked: 0 };
        cweCounts[cweKey].total++;
        if (row.accion === "BLOCK") cweCounts[cweKey].blocked++;
      }

      cweRecall = CWE_MAP.map((c) => {
        const data = cweCounts[c.cwe];
        if (!data || data.total < 5) {
          return {
            cwe: c.cwe,
            nombre: c.nombre,
            benchmark_recall_pct: c.benchmark_recall_pct,
            total_muestras: data?.total || 0,
            blocked: data?.blocked || 0,
            recall_pct: null,
            muestra_insuficiente: true,
          };
        }
        const recall = parseFloat(((data.blocked / data.total) * 100).toFixed(2));
        return {
          cwe: c.cwe,
          nombre: c.nombre,
          benchmark_recall_pct: c.benchmark_recall_pct,
          total_muestras: data.total,
          blocked: data.blocked,
          recall_pct: recall,
          muestra_insuficiente: false,
        };
      });

      // Agregar "OTRO" si hay casos sin mapeo
      if (cweCounts["OTRO"]) {
        cweRecall.push({
          cwe: "OTRO",
          nombre: "Otras categorías (sin feature de ataque específico)",
          benchmark_recall_pct: 100.0,
          total_muestras: cweCounts["OTRO"].total,
          blocked: cweCounts["OTRO"].blocked,
          recall_pct: cweCounts["OTRO"].total >= 5
            ? parseFloat(((cweCounts["OTRO"].blocked / cweCounts["OTRO"].total) * 100).toFixed(2))
            : null,
          muestra_insuficiente: cweCounts["OTRO"].total < 5,
        });
      }
    } else {
      // Sin ground truth → todas marca "sin_etiquetas_reales"
      cweRecall = CWE_MAP.map((c) => ({
        cwe: c.cwe,
        nombre: c.nombre,
        benchmark_recall_pct: c.benchmark_recall_pct,
        total_muestras: 0,
        blocked: 0,
        recall_pct: null,
        muestra_insuficiente: true,
      }));
    }

    // =====================================================================
    // 5. RECOMENDACIÓN DE REENTRENAMIENTO
    // =====================================================================
    let recomendarReentrenar = false;
    let motivoReentreno: string | null = null;

    if (hasGroundTruth && desviacionDetectada) {
      recomendarReentrenar = true;
      motivoReentreno = `FPR de la ventana supera ${FPR_DEVIATION_THRESHOLD}x el FPR del benchmark ` +
        `(${fprComputed?.toFixed(2)}% vs ${BENCHMARK.fpr_pct}%).`;
    }

    if (logTrendPct !== null && logTrendPct > LOG_TREND_THRESHOLD_PCT) {
      if (recomendarReentrenar) {
        motivoReentreno += ` Además, la zona LOG creció un ${logTrendPct.toFixed(1)}% en la ventana.`;
      } else {
        recomendarReentrenar = true;
        motivoReentreno = `La zona LOG creció un ${logTrendPct.toFixed(1)}% en la ventana ` +
          `(umbral: ${LOG_TREND_THRESHOLD_PCT}%). Señal de incertidumbre creciente del modelo.`;
      }
    }

    // =====================================================================
    // LIVE METRICS (desde vw_confusion_matrix — datos reales de producción)
    // =====================================================================
    let liveWafMl = null;
    try {
      const vwRes = await query("SELECT * FROM vw_confusion_matrix");
      const vw = vwRes.rows[0] || null;
      if (vw) {
        const tp = Number(vw.true_positive);
        const fp = Number(vw.false_positive);
        const tn = Number(vw.true_negative);
        const fn = Number(vw.false_negative);
        const total = tp + fp + tn + fn;
        liveWafMl = {
          name: "WAF-ML (en vivo)",
          source: "live" as const,
          true_positives: tp,
          false_positives: fp,
          true_negatives: tn,
          false_negatives: fn,
          fpr_pct: Number(vw.false_positive_rate_pct),
          recall_pct: Number(vw.recall_pct),
          detacc_pct: total > 0 ? parseFloat((((tp + tn) / total) * 100).toFixed(1)) : 0,
        };
      }
    } catch (e) {
      console.warn("No se pudo leer vw_confusion_matrix para live_metrics:", e);
    }

    // =====================================================================
    // BUILD RESPONSE PAYLOAD
    // =====================================================================
    const payload = {
      report_type: "model-health",
      window: windowLabel,
      window_days: days,
      generated_at: new Date().toISOString(),
      period: {
        since: sinceStr,
        until: untilStr,
      },
      benchmark: {
        fpr_pct: BENCHMARK.fpr_pct,
        recall_pct: BENCHMARK.recall_pct,
        detacc_pct: BENCHMARK.detacc_pct,
        total_cases: BENCHMARK.total_cases,
        wilson_ci_upper_pct: BENCHMARK.wilson_ci_upper_pct,
        source: "benchmark_224_cases_8_cwes",
        date: BENCHMARK_DATE,
      },
      production: {
        total_events: totalEvents,
        ground_truth_available: hasGroundTruth,
        ground_truth_count: gtRes.rows.length,
        scores_distribution: scoreBuckets,
        zone_distribution: {
          allow_pct: parseFloat(((zoneAgg.allowed / zoneTotal) * 100).toFixed(2)),
          log_pct: parseFloat(((zoneAgg.logged / zoneTotal) * 100).toFixed(2)),
          block_pct: parseFloat(((zoneAgg.blocked / zoneTotal) * 100).toFixed(2)),
        },
        zone_by_day: zoneByDay,
        zone_trend: {
          log_trend_pct_change: logTrendPct,
          log_trend_direction: logTrendDirection,
        },
        fpr_computed: fprComputed,
        recall_computed: recallComputed,
        fpr_deviation_ratio: fprDeviation,
        recall_deviation_pct: recallDeviation,
        fpr_computable: hasGroundTruth,
        recall_computable: hasGroundTruth,
        fpr_ground_truth_missing: !hasGroundTruth,
        fpr_ground_truth_explanation: hasGroundTruth
          ? null
          : "No hay eventos con etiqueta_real (ground truth) en la ventana seleccionada. " +
            "etiqueta_real solo se popula durante ejecuciones en modo benchmark. " +
            "En producción, el WAF no conoce la etiqueta real de cada request. " +
            "Para obtener FPR/Recall reales, ejecute el benchmark o implemente " +
            "un pipeline de etiquetado post-hoc.",
      },
      cwe_recall: cweRecall,
      live_metrics: liveWafMl,
      benchmark_baselines: [
        { ...WAF_ML_BENCHMARK },
        ...BASELINES.map((b) => ({ ...b })),
      ],
      deviation_detected: desviacionDetectada,
      retrain: {
        recommended: recomendarReentrenar,
        motivo: motivoReentreno,
        fpr_threshold: FPR_DEVIATION_THRESHOLD,
        log_trend_threshold_pct: LOG_TREND_THRESHOLD_PCT,
      },
    };

    // =====================================================================
    // FORMAT: JSON
    // =====================================================================
    if (format === "json") {
      return NextResponse.json(payload, {
        headers: {
          "Content-Disposition": `inline; filename="model-health-${windowLabel}.json"`,
        },
      });
    }

    // =====================================================================
    // FORMAT: PDF
    // =====================================================================

    // Preparar tabla de score distribution
    const scoreTableRows = scoreBuckets.map((b) => [
      b.bucket,
      String(b.count),
      `${b.percentage}%`,
    ]);

    // Preparar tabla de zonas por día
    const zoneTableHeaders = ["Día", "ALLOW %", "LOG %", "BLOCK %"];
    const zoneTableRows = zoneByDay.map((d) => [
      d.dia,
      `${d.allow_pct}%`,
      `${d.log_pct}%`,
      `${d.block_pct}%`,
    ]);

    // Preparar tabla CWE
    const cweTableHeaders = ["CWE", "Categoría", "Muestras", "Bloqueados", "Recall", "Benchmark"];
    const cweTableRows = cweRecall.map((c) => [
      c.cwe,
      c.nombre,
      String(c.total_muestras),
      String(c.blocked),
      c.muestra_insuficiente ? "— (muestra < 5)" : `${c.recall_pct}%`,
      `${c.benchmark_recall_pct}%`,
    ]);

    const buf = await generatePDF(`Salud del Modelo — WAF-ML (${windowLabel})`, [
      {
        heading: "Resumen Ejecutivo",
        content:
          `Reporte de salud del modelo ensemble LGBM+MLP para la ventana de ` +
          `${days} días (${since.toLocaleDateString("es-PE")} — ${until.toLocaleDateString("es-PE")}).\n\n` +
          `Eventos analizados: ${totalEvents}.\n` +
          `Datos con etiqueta real: ${hasGroundTruth ? `${gtRes.rows.length} eventos` : "NO DISPONIBLE"}.\n` +
          `Reentrenamiento recomendado: ${recomendarReentrenar ? "SÍ" : "No"}${motivoReentreno ? `.\nMotivo: ${motivoReentreno}` : "."}`,
      },
      {
        heading: "1. Distribución de Scores",
        content:
          `Histograma de scores del ensemble en la ventana. ` +
          `Idealmente los scores se concentran en los extremos (< 0.30 ALLOW, >= 0.70 BLOCK). ` +
          `Acumulación cerca de 0.30 o 0.70 es señal temprana de drift.`,
        table: {
          headers: ["Bucket", "Count", "%"],
          rows: scoreTableRows,
        },
      },
      {
        heading: "2. FPR / Recall — Ventana vs Benchmark",
        content:
          hasGroundTruth
            ? `FPR computado: ${fprComputed !== null ? `${fprComputed}%` : "N/A"} ` +
              `| Recall computado: ${recallComputed !== null ? `${recallComputed}%` : "N/A"}\n` +
              `Benchmark de referencia: FPR=${BENCHMARK.fpr_pct}% | Recall=${BENCHMARK.recall_pct}% ` +
              `(224 casos, 8 CWEs)\n` +
              `Desviación detectada: ${desviacionDetectada ? "SÍ" : "No"}`
            : `No hay eventos con etiqueta real (ground truth) en la ventana. ` +
              `La columna etiqueta_real de waf_events solo se popula en modo benchmark. ` +
              `Sin ground truth no es posible calcular FPR/Recall reales de producción.\n\n` +
              `Benchmark de referencia: FPR=${BENCHMARK.fpr_pct}% | Recall=${BENCHMARK.recall_pct}% ` +
              `(224 casos, 8 CWEs).\n` +
              `Para obtener FPR/Recall reales: ejecute el benchmark o implemente un pipeline ` +
              `de etiquetado post-hoc.`,
      },
      {
        heading: "3. Recall por Categoría CWE",
        content:
          hasGroundTruth
            ? `Desglose de recall por categoría CWE usando datos con etiqueta real ` +
              `de la ventana. Categorías con < 5 muestras se marcan como muestra_insuficiente.`
            : `No hay datos con etiqueta real en la ventana. ` +
              `El recall por CWE solo puede calcularse con ground truth. ` +
              `Esta sección refleja los valores del benchmark como referencia.`,
        table: {
          headers: cweTableHeaders,
          rows: cweTableRows,
          colWidths: [65, 140, 60, 65, 95, 70],
        },
      },
      {
        heading: "4. Tendencia de Zonas ALLOW / LOG / BLOCK",
        content:
          `Distribución porcentual diaria. La tendencia de la zona LOG es el indicador ` +
          `más temprano de drift: si crece de forma sostenida, el modelo está cada vez ` +
          `más inseguro de sus decisiones.\n\n` +
          `Tendencia de zona LOG: ${logTrendPct !== null ? `${logTrendPct}%` : "insuficiente"} ` +
          `(${logTrendDirection}).\n` +
          `Distribución agregada: ALLOW ${payload.production.zone_distribution.allow_pct}% ` +
          `| LOG ${payload.production.zone_distribution.log_pct}% ` +
          `| BLOCK ${payload.production.zone_distribution.block_pct}%`,
        table: {
          headers: zoneTableHeaders,
          rows: zoneTableRows,
        },
      },
      {
        heading: "5. Recomendación de Reentrenamiento",
        content:
          `Recomendación: ${recomendarReentrenar ? "SÍ — se recomienda reentrenar el modelo" : "No — el modelo opera dentro de parámetros esperados"}.\n\n` +
          (motivoReentreno
            ? `Motivo: ${motivoReentreno}`
            : "Ninguna métrica superó los umbrales de desviación configurados.") +
          `\n\nUmbrales aplicados:\n` +
          `• FPR desviación > ${FPR_DEVIATION_THRESHOLD}x el FPR del benchmark\n` +
          `• Tendencia de zona LOG > ${LOG_TREND_THRESHOLD_PCT}% en la ventana`,
      },
    ]);

    return new NextResponse(buf as BodyInit, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="model-health-${windowLabel}-${new Date().toISOString().split("T")[0]}.pdf"`,
      },
    });
  } catch (error) {
    console.error("Model health report error:", error);
    return NextResponse.json(
      { error: "Error generating model health report" },
      { status: 500 }
    );
  }
}
