import { NextResponse } from "next/server";
import { query } from "../../../lib/db";

export async function GET() {
  try {
    // Query recent latencies (last 20 requests)
    const latenciesRes = await query(
      "SELECT tiempo_inferencia_ms, fecha::text FROM waf_events WHERE tiempo_inferencia_ms IS NOT NULL ORDER BY fecha DESC LIMIT 20"
    );

    // Query recent hardware metrics (last 50 rows)
    const hardwareRes = await query(
      "SELECT container_name, cpu_usage_pct, ram_usage_mb, timestamp::text FROM waf_hardware_metrics ORDER BY timestamp DESC LIMIT 50"
    );

    const latencies = latenciesRes.rows.map((row) => ({
      latency: Number(row.tiempo_inferencia_ms || 0),
      timestamp: row.fecha,
    }));

    const hardware = hardwareRes.rows.map((row) => ({
      container_name: row.container_name,
      cpu_usage_pct: Number(row.cpu_usage_pct || 0),
      ram_usage_mb: Number(row.ram_usage_mb || 0),
      timestamp: row.timestamp,
    }));

    return NextResponse.json({
      latencies,
      hardware,
    });
  } catch (error) {
    console.error("Telemetry API Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
