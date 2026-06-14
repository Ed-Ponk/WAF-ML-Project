import { NextResponse } from "next/server";
import { query } from "../../../lib/db";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const limit = Math.max(1, parseInt(searchParams.get("limit") || "10", 10));
    const offset = (page - 1) * limit;

    // Retrieve total count of blocked events
    const countRes = await query(
      "SELECT COUNT(*)::int as total FROM waf_events WHERE accion = 'BLOCK'"
    );
    const total = countRes.rows[0]?.total || 0;

    // Retrieve paginated blocked alerts
    const alertsRes = await query(
      "SELECT id, fecha::text, ip_origen::text, user_agent, metodo_http, url, payload, shannon_entropy, score_ml, veredicto, accion, tiempo_inferencia_ms, features_json FROM waf_events WHERE accion = 'BLOCK' ORDER BY fecha DESC LIMIT $1 OFFSET $2",
      [limit, offset]
    );

    return NextResponse.json({
      total,
      page,
      limit,
      alerts: alertsRes.rows,
    });
  } catch (error) {
    console.error("Alerts API Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
