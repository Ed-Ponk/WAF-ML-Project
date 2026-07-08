import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";
import { toCSV, generatePDF } from "@/lib/reports";
import { authenticate } from "@/lib/auth";
import { anonymizeIP } from "@/lib/helpers";

export async function GET(request: NextRequest) {
  const auth = await authenticate(request);
  if (!auth.ok) return auth.response;

  try {
    const { searchParams } = new URL(request.url);
    const format = searchParams.get("format") || "csv";
    const dateFrom = searchParams.get("date_from");
    const dateTo = searchParams.get("date_to");

    let whereClause = " AND accion = 'BLOCK'";
    const params: string[] = [];
    let paramIndex = 1;

    if (dateFrom) {
      whereClause += ` AND fecha >= $${paramIndex++}::timestamp`;
      params.push(dateFrom);
    }
    if (dateTo) {
      whereClause += ` AND fecha <= $${paramIndex++}::timestamp`;
      params.push(dateTo);
    }

    const result = await query(
      `SELECT fecha::text as timestamp, ip_origen as source_ip, metodo_http as method,
              url, score_ml as score, accion as action, tiempo_inferencia_ms as latency_ms
       FROM waf_events
       WHERE 1=1${whereClause}
       ORDER BY fecha DESC
       LIMIT 100`,
      params
    );

    const rows = result.rows.map((r: any) => ({
      timestamp: r.timestamp,
      source_ip: anonymizeIP(r.source_ip),
      method: r.method,
      url: (r.url ?? "").substring(0, 80),
      score: Number(r.score ?? 0).toFixed(4),
      action: r.action,
      latency_ms: Number(r.latency_ms ?? 0),
    }));

    if (format === "pdf") {
      const buf = await generatePDF("Reporte de Alertas de Seguridad", [
        {
          heading: "Alertas Bloqueadas",
          content: `Total de alertas: ${rows.length}. Listado de los últimos 100 eventos bloqueados por WAF-ML con score, IP origen y URL.`,
          table: {
            headers: ["Timestamp", "IP Origen", "Método", "URL", "Score", "Latencia"],
            rows: rows.map((r: any) => [
              r.timestamp ?? "",
              r.source_ip ?? "",
              r.method ?? "",
              r.url ?? "",
              r.score ?? "",
              `${r.latency_ms}ms`,
            ]),
          },
        },
      ]);

      return new NextResponse(buf as BodyInit, {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="alertas-seguridad-${new Date().toISOString().split("T")[0]}.pdf"`,
        },
      });
    }

    const csv = toCSV(rows);
    return new NextResponse(csv, {
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="alertas-seguridad-${new Date().toISOString().split("T")[0]}.csv"`,
      },
    });
  } catch (error) {
    console.error("Alerts report error:", error);
    return NextResponse.json({ error: "Error generating alerts report" }, { status: 500 });
  }
}
