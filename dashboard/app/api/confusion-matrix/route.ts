import { NextResponse } from "next/server";
import { query } from "../../../lib/db";
import { WAF_ML_BENCHMARK, BASELINES, BENCHMARK_DATE } from "../../../lib/benchmark-baselines";
import { authenticate } from "@/lib/auth";

export async function GET(request: Request) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;
  try {
    // WAF-ML en vivo desde vw_confusion_matrix (datos reales de producción)
    const realtimeRes = await query("SELECT * FROM vw_confusion_matrix");

    // Baselines del benchmark centralizado (constantes, no waf_baselines)
    const baselines = [
      { ...WAF_ML_BENCHMARK },
      ...BASELINES.map((b) => ({ ...b })),
    ];

    return NextResponse.json({
      realtime: realtimeRes.rows[0] || null,
      baselines,
      benchmark_date: BENCHMARK_DATE,
    });
  } catch (error) {
    console.error("Confusion Matrix GET Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

/**
 * POST y PUT fueron eliminados.
 *
 * Las baselines ahora son constantes centralizadas en benchmark-baselines.ts.
 * El GET devuelve esos valores, no datos de waf_baselines.
 * Para modificar las baselines, edite benchmark-baselines.ts.
 */
