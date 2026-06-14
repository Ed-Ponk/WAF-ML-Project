import { NextResponse } from "next/server";
import { query } from "../../../lib/db";

export async function GET(request: Request) {
  try {
    // 1. Query pre-aggregated daily summaries
    const result = await query(
      "SELECT fecha_dia::text as date, total_requests as requests, total_blocked as blocked, total_allowed as allowed, sqli_detected as sqli, xss_detected as xss, cmd_detected as rce FROM waf_daily_summary ORDER BY fecha_dia ASC"
    );

    // 2. Map data to compute totals and attack distributions
    let totalRequests = 0;
    let totalBlocked = 0;
    let totalAllowed = 0;
    let sqli = 0;
    let xss = 0;
    let rce = 0;

    const daily = result.rows.map((row) => {
      const requests = Number(row.requests || 0);
      const blocked = Number(row.blocked || 0);
      const allowed = Number(row.allowed || 0);
      const dSqli = Number(row.sqli || 0);
      const dXss = Number(row.xss || 0);
      const dRce = Number(row.rce || 0);

      totalRequests += requests;
      totalBlocked += blocked;
      totalAllowed += allowed;
      sqli += dSqli;
      xss += dXss;
      rce += dRce;

      return {
        date: row.date,
        requests,
        blocked,
        allowed,
        sqli: dSqli,
        xss: dXss,
        rce: dRce,
      };
    });

    const blockRate = totalRequests > 0 ? Number(((totalBlocked / totalRequests) * 100).toFixed(2)) : 0;

    return NextResponse.json({
      totals: {
        requests: totalRequests,
        blocked: totalBlocked,
        allowed: totalAllowed,
        blockRate,
        attacks: {
          sqli,
          xss,
          rce,
        },
      },
      daily,
    });
  } catch (error) {
    console.error("Stats API Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}
