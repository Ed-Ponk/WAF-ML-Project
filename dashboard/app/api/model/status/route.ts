import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import jwt from "jsonwebtoken";
import { query } from "@/lib/db";
import { getJwtSecret } from "@/lib/jwt";

export async function GET(request: Request) {
  try {
    // 1. Authenticate
    const cookieStore = cookies();
    let token = cookieStore.get("token")?.value;

    if (!token) {
      const cookieHeader = request.headers.get("cookie") || "";
      const tokenMatch = cookieHeader.match(/token=([^;]+)/);
      token = tokenMatch ? tokenMatch[1] : undefined;
    }

    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    let decoded: any;
    try {
      decoded = jwt.verify(token, getJwtSecret());
    } catch (err) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // 2. Get active model
    const result = await query(
      "SELECT id, name, version, accuracy, f1_score, training_date, algorithm, feature_count, status, uploaded_at FROM waf_models WHERE status = 'active' ORDER BY uploaded_at DESC LIMIT 1"
    );

    if (result.rows.length === 0) {
      return NextResponse.json({ model: null }, { status: 200 });
    }

    return NextResponse.json({ model: result.rows[0] });
  } catch (error: any) {
    console.error("Model Status API Error:", error);
    return NextResponse.json(
      { error: error.message || "Internal Server Error" },
      { status: 500 }
    );
  }
}