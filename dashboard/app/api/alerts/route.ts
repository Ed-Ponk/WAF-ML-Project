import { NextResponse } from "next/server";
import { query } from "../../../lib/db";
import { authenticate } from "@/lib/auth";

export async function GET(request: Request) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;
  try {
    const { searchParams } = new URL(request.url);
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const limit = Math.max(1, parseInt(searchParams.get("limit") || "10", 10));
    const offset = (page - 1) * limit;

    const method = searchParams.get("method");
    const scoreMin = searchParams.get("score_min");
    const scoreMax = searchParams.get("score_max");
    const dateFrom = searchParams.get("date_from");
    const dateTo = searchParams.get("date_to");
    const accion = searchParams.get("accion");

    // Build dynamic WHERE clauses with parameterized queries
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (accion && accion !== "") {
      const actions = accion.split(",").map((a) => a.trim()).filter(Boolean);
      if (actions.length === 1) {
        conditions.push(`accion = $${paramIndex++}`);
        params.push(actions[0]);
      } else if (actions.length > 1) {
        const placeholders = actions.map(() => `$${paramIndex++}`).join(", ");
        conditions.push(`accion IN (${placeholders})`);
        params.push(...actions);
      }
    }

    if (method && method !== "") {
      conditions.push(`metodo_http = $${paramIndex++}`);
      params.push(method);
    }
    if (scoreMin && scoreMin !== "") {
      conditions.push(`score_ml >= $${paramIndex++}`);
      params.push(parseFloat(scoreMin));
    }
    if (scoreMax && scoreMax !== "") {
      conditions.push(`score_ml <= $${paramIndex++}`);
      params.push(parseFloat(scoreMax));
    }
    if (dateFrom && dateFrom !== "") {
      conditions.push(`fecha >= $${paramIndex++}`);
      params.push(dateFrom);
    }
    if (dateTo && dateTo !== "") {
      conditions.push(`fecha < ($${paramIndex++}::date + interval '1 day')`);
      params.push(dateTo);
    }

    const whereClause = conditions.length ? conditions.join(" AND ") : "1=1";

    // Retrieve total count with same filters
    const countRes = await query(
      `SELECT COUNT(*)::int as total FROM waf_events WHERE ${whereClause}`,
      params
    );
    const total = countRes.rows[0]?.total || 0;

    // Retrieve paginated alerts with same filters
    const alertsRes = await query(
      `SELECT id, fecha::text, ip_origen::text, user_agent, metodo_http, url, payload, shannon_entropy, score_ml, veredicto, accion, tiempo_inferencia_ms, features_json, waf_version FROM waf_events WHERE ${whereClause} ORDER BY fecha DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      [...params, limit, offset]
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
