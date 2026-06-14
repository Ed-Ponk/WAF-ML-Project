import { NextResponse } from "next/server";
import { query } from "../../../lib/db";

export async function GET() {
  try {
    const realtimeRes = await query("SELECT * FROM vw_confusion_matrix");
    const baselinesRes = await query("SELECT * FROM waf_baselines ORDER BY id ASC");

    return NextResponse.json({
      realtime: realtimeRes.rows[0] || null,
      baselines: baselinesRes.rows,
    });
  } catch (error) {
    console.error("Confusion Matrix GET Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      baseline_name,
      true_positives,
      false_positives,
      true_negatives,
      false_negatives,
    } = body;

    if (!baseline_name) {
      return NextResponse.json(
        { error: "baseline_name is required" },
        { status: 400 }
      );
    }

    // Check if baseline exists
    const checkRes = await query(
      "SELECT * FROM waf_baselines WHERE baseline_name = $1",
      [baseline_name]
    );

    if (checkRes.rows.length === 0) {
      return NextResponse.json(
        { error: `Baseline '${baseline_name}' not found` },
        { status: 404 }
      );
    }

    // Update baseline
    await query(
      `UPDATE waf_baselines
       SET true_positives = $1, false_positives = $2, true_negatives = $3, false_negatives = $4, updated_at = NOW()
       WHERE baseline_name = $5`,
      [
        Number(true_positives ?? checkRes.rows[0].true_positives),
        Number(false_positives ?? checkRes.rows[0].false_positives),
        Number(true_negatives ?? checkRes.rows[0].true_negatives),
        Number(false_negatives ?? checkRes.rows[0].false_negatives),
        baseline_name,
      ]
    );

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Confusion Matrix POST/PUT Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

// Support PUT as an alias for POST for REST convention compatibility
export async function PUT(request: Request) {
  return POST(request);
}
