import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { generatePDF } from "@/lib/reports";
import { WAF_ML_BENCHMARK, BASELINES, BENCHMARK_DATE } from "@/lib/benchmark-baselines";
import { authenticate } from "@/lib/auth";
import { anonymizeIP } from "@/lib/helpers";

export async function GET(request: NextRequest) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;

  try {
    const { searchParams } = new URL(request.url);
    const dateFrom = searchParams.get("date_from");
    const dateTo = searchParams.get("date_to");

    // Build date filter clauses + params
    let statsWhere = "";
    let alertsWhere = " AND accion = 'BLOCK'";
    let latWhere = "WHERE tiempo_inferencia_ms IS NOT NULL";
    const params: string[] = [];
    let paramIndex = 1;

    if (dateFrom) {
      const df = `$${paramIndex++}::date`;
      statsWhere += ` AND fecha_dia >= ${df}`;
      alertsWhere += ` AND fecha >= ${df}`;
      latWhere += ` AND fecha >= ${df}`;
      params.push(dateFrom);
    }
    if (dateTo) {
      const dt = `$${paramIndex++}::date`;
      statsWhere += ` AND fecha_dia <= ${dt}`;
      alertsWhere += ` AND fecha <= ${dt}`;
      latWhere += ` AND fecha <= ${dt}`;
      params.push(dateTo);
    }

    // 1. Stats
    const statsRes = await query(
      `SELECT COALESCE(SUM(total_requests),0) as requests,
              COALESCE(SUM(total_blocked),0) as blocked,
              COALESCE(SUM(total_allowed),0) as allowed
       FROM waf_daily_summary
       WHERE 1=1${statsWhere}`,
      params
    );
    const stats = statsRes.rows[0] || { requests: 0, blocked: 0, allowed: 0 };

    // 2. Alertas recientes (top 20) con filtro de fecha
    const alertsRes = await query(
      `SELECT fecha::text as ts, ip_origen, url, score_ml
       FROM waf_events WHERE 1=1${alertsWhere}
       ORDER BY fecha DESC LIMIT 20`,
      params
    );

    // 3. Latencia
    const latRes = await query(
      `SELECT AVG(tiempo_inferencia_ms) as avg_lat,
              PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY tiempo_inferencia_ms) as p95_lat
       FROM waf_events ${latWhere}`,
      params
    );
    const lat = latRes.rows[0] || { avg_lat: 0, p95_lat: 0 };

    // 4. Baselines — todos del mismo benchmark (constantes centralizadas)
    //    Ver benchmark-baselines.ts (fuente: docs/benchmark-resultados.md Fase 2)
    //    Los 4 WAFs se evaluaron con los mismos 224 casos. NO usar waf_baselines
    //    que contenía seed data ficticio.
    const allBaselines = [WAF_ML_BENCHMARK, ...BASELINES];

    const req = Number(stats.requests || 0);
    const blockRate = req > 0 ? ((Number(stats.blocked || 0) / req) * 100).toFixed(2) : "0.00";
    const avgLat = Number(lat.avg_lat || 0).toFixed(2);
    const p95Lat = Number(lat.p95_lat || 0).toFixed(2);

    const rangeLabel = dateFrom || dateTo
      ? `Periodo: ${dateFrom || "—"} a ${dateTo || "—"}`
      : "Todos los datos";

    const alerts = alertsRes.rows.map((r: any) => [
      r.ts?.substring(0, 19) ?? "",
      anonymizeIP(r.ip_origen),
      (r.url ?? "").substring(0, 60),
      Number(r.score_ml ?? 0).toFixed(4),
    ]);

    const baselines = allBaselines.map((b) => {
      const total = b.true_positives + b.false_positives + b.true_negatives + b.false_negatives;
      const detAcc = total > 0 ? ((b.true_positives + b.true_negatives) / total * 100).toFixed(1) : "N/A";
      return [
        b.name,
        String(b.true_positives),
        String(b.false_positives),
        String(b.true_negatives),
        String(b.false_negatives),
        `${detAcc}%`,
      ];
    });

    const buf = await generatePDF(`Reporte Completo — WAF-ML Engine (${rangeLabel})`, [
      {
        heading: "Resumen Ejecutivo",
        content: `WAF-ML (ensemble LGBM + MLP) procesó un total de ${req} requests.
Tasa de bloqueo: ${blockRate}%.
Latencia promedio: ${avgLat}ms (P95: ${p95Lat}ms).
Este reporte consolida las métricas principales del sistema.`,
      },
      {
        heading: "Métricas de Rendimiento",
        content: `Volumen total: ${req} requests | Bloqueados: ${stats.blocked} | Permitidos: ${stats.allowed}
Latencia promedio: ${avgLat}ms | P95: ${p95Lat}ms`,
      },
      {
        heading: "Últimas Alertas (20 más recientes)",
        content: "Listado de eventos bloqueados con IP, URL y score ML.",
        table: {
          headers: ["Timestamp", "IP Origen", "URL", "Score ML"],
          rows: alerts.length ? alerts : [["Sin datos", "", "", ""]],
        },
      },
      ...(baselines.length
        ? [
            {
              heading: "Matriz de Confusión por Baseline",
              content: `Benchmark ${BENCHMARK_DATE}. Comparativa contra WAFs tradicionales sobre el mismo conjunto de 224 casos (92 ataques adversariales de 8+ CWEs, 132 requests legítimos). Todos los WAFs evaluados con idéntico dataset — las métricas son directamente comparables entre sí.`,
              table: {
                headers: ["Baseline", "TP", "FP", "TN", "FN", "DetAcc", "n"],
                rows: baselines.map((row: string[]) => [...row, "224"]),
                colWidths: [135, 55, 55, 55, 55, 70, 40],
              },
            },
          ]
        : []),
    ]);

    return new NextResponse(buf as BodyInit, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="reporte-completo-wafml-${new Date().toISOString().split("T")[0]}.pdf"`,
      },
    });
  } catch (error) {
    console.error("Comprehensive report error:", error);
    return NextResponse.json({ error: "Error generating comprehensive report" }, { status: 500 });
  }
}
