import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { toCSV, generatePDF } from "@/lib/reports";
import { authenticate } from "@/lib/auth";

export async function GET(request: NextRequest) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;

  try {
    const { searchParams } = new URL(request.url);
    const format = searchParams.get("format") || "csv";
    const dateFrom = searchParams.get("date_from");
    const dateTo = searchParams.get("date_to");

    let whereClause = "";
    const params: string[] = [];
    let paramIndex = 1;

    if (dateFrom) {
      whereClause += ` AND fecha_dia >= $${paramIndex++}::date`;
      params.push(dateFrom);
    }
    if (dateTo) {
      whereClause += ` AND fecha_dia <= $${paramIndex++}::date`;
      params.push(dateTo);
    }

    const result = await query(
      `SELECT fecha_dia::text as date, total_requests, total_blocked, total_allowed,
              sqli_detected as sqli, xss_detected as xss, cmd_detected as rce,
              round(
                CASE WHEN total_requests > 0
                  THEN (total_blocked::numeric / total_requests) * 100
                  ELSE 0
                END, 2
              ) as block_rate
       FROM waf_daily_summary
       WHERE 1=1${whereClause}
       ORDER BY fecha_dia DESC
       LIMIT 30`,
      params
    );

    const rows = result.rows.map((r: any) => ({
      date: r.date,
      requests: Number(r.requests ?? r.total_requests ?? 0),
      blocked: Number(r.blocked ?? r.total_blocked ?? 0),
      allowed: Number(r.allowed ?? r.total_allowed ?? 0),
      block_rate: Number(r.block_rate ?? 0),
      sqli: Number(r.sqli ?? 0),
      xss: Number(r.xss ?? 0),
      rce: Number(r.rce ?? 0),
    }));

    if (format === "pdf") {
      const totals = rows.reduce(
        (acc: any, r: any) => ({
          requests: acc.requests + r.requests,
          blocked: acc.blocked + r.blocked,
          allowed: acc.allowed + r.allowed,
        }),
        { requests: 0, blocked: 0, allowed: 0 }
      );

      const buf = await generatePDF("Resumen Diario de Tráfico", [
        {
          heading: "Resumen Ejecutivo",
          content: `Este reporte muestra el volumen de tráfico procesado por WAF-ML en los últimos 30 días.
Total de requests: ${totals.requests} | Bloqueados: ${totals.blocked} |
Permitidos: ${totals.allowed} | Tasa de bloqueo: ${totals.requests > 0 ? ((totals.blocked / totals.requests) * 100).toFixed(2) : 0}%`,
        },
        {
          heading: "Distribución Diaria",
          content: "Detalle día por día de requests, bloqueos y ataques detectados por tipo (SQLi, XSS, RCE).",
          table: {
            headers: ["Fecha", "Requests", "Bloqueados", "Tasa Bloqueo", "SQLi", "XSS", "RCE"],
            rows: rows.map((r: any) => [
              r.date,
              String(r.requests),
              String(r.blocked),
              `${r.block_rate}%`,
              String(r.sqli),
              String(r.xss),
              String(r.rce),
            ]),
          },
        },
      ]);

      return new NextResponse(buf as BodyInit, {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="reporte-diario-${new Date().toISOString().split("T")[0]}.pdf"`,
        },
      });
    }

    // CSV
    const csv = toCSV(rows);
    return new NextResponse(csv, {
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="reporte-diario-${new Date().toISOString().split("T")[0]}.csv"`,
      },
    });
  } catch (error) {
    console.error("Daily report error:", error);
    return NextResponse.json({ error: "Error generating daily report" }, { status: 500 });
  }
}
