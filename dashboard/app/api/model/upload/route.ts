import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { query } from "@/lib/db";
import { getJwtSecret } from "@/lib/jwt";

export async function POST(request: Request) {
  try {
    // 1. Authenticate and authorize admin role
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

    if (!decoded || decoded.role !== "admin") {
      return NextResponse.json(
        { error: "Forbidden: Admin role required" },
        { status: 403 }
      );
    }

    // 2. Receive file from formData
    const formData = await request.formData();
    const file = formData.get("file") as File | null;
    if (!file) {
      return NextResponse.json(
        { error: "No file was uploaded" },
        { status: 400 }
      );
    }

    if (!file.name.endsWith(".pkl")) {
      return NextResponse.json(
        { error: "Only .pkl model files are allowed" },
        { status: 400 }
      );
    }

    // Extract optional metadata from formData
    const name = (formData.get("name") as string) || file.name.replace(/\.pkl$/, "");
    const version = formData.get("version") as string || null;
    const accuracy = formData.get("accuracy") ? parseFloat(formData.get("accuracy") as string) : null;
    const f1Score = formData.get("f1_score") ? parseFloat(formData.get("f1_score") as string) : null;
    const trainingDate = formData.get("training_date") as string || null;

    const buffer = Buffer.from(await file.arrayBuffer());
    const targetPath = "/ml-engine/waf_ensemble_final.pkl";

    // Ensure the shared directory exists locally (helpful in dev environment)
    const destDir = path.dirname(targetPath);
    if (!fs.existsSync(destDir)) {
      try {
        fs.mkdirSync(destDir, { recursive: true });
      } catch (err) {
        console.warn("Could not create destination volume directory:", err);
      }
    }

    // Write file to the shared volume path
    fs.writeFileSync(targetPath, buffer);

    // 3. Call the Python reload endpoint on ml-engine
    try {
      const reloadRes = await fetch("http://ml-engine:8000/reload_model", {
        method: "POST",
      });

      if (!reloadRes.ok || reloadRes.status === 400) {
        // Reload failed (e.g. invalid signature, opcode, etc.)
        // Delete the invalid file immediately
        if (fs.existsSync(targetPath)) {
          fs.unlinkSync(targetPath);
        }

        const errorData = await reloadRes.json().catch(() => ({}));
        return NextResponse.json(
          { error: errorData.detail || "Model signature or opcode validation failed" },
          { status: 400 }
        );
      }

      // 4. Extract metadata from ml-engine reload response (preferred)
      let reloadData: any = {};
      try {
        reloadData = await reloadRes.json();
      } catch { /* ignore parse errors */ }

      const algoName = reloadData?.metadata?.algorithm || "LightGBM + MLP Neural Net";
      const accFromMl = reloadData?.metadata?.accuracy ?? null;
      const f1FromMl  = reloadData?.metadata?.f1_score ?? null;
      const featsFrom = reloadData?.metadata?.feature_count ?? null;
      const trainDate = reloadData?.metadata?.training_date
                         || trainingDate
                         || new Date().toISOString().split("T")[0];

      // 5. Persist model metadata in database
      let insertResult: any = undefined;
      try {
        // Deactivate previous active models
        await query("UPDATE waf_models SET status = 'inactive' WHERE status = 'active'");
        // Insert new model record (use ml-engine metadata or original form values)
        const result = await query(
          `INSERT INTO waf_models (name, version, accuracy, f1_score, training_date, algorithm, feature_count, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
           RETURNING id, name, version, accuracy, f1_score, training_date, algorithm, status, uploaded_at`,
          [
            name, version,
            accFromMl ?? accuracy,
            f1FromMl ?? f1Score,
            trainDate,
            algoName,
            featsFrom ?? 50,
          ]
        );
        insertResult = result;
        console.log("Model metadata saved:", result.rows[0]);
      } catch (dbErr) {
        console.error("Failed to persist model metadata:", dbErr);
        // Don't fail the upload — metadata storage is non-critical
      }

      return NextResponse.json({
        success: true,
        message: "Model reloaded successfully in-memory",
        model: insertResult?.rows[0] || null,
      });
    } catch (fetchErr) {
      // In case ML engine is down or network issue occurs, delete the file to be safe
      if (fs.existsSync(targetPath)) {
        fs.unlinkSync(targetPath);
      }
      return NextResponse.json(
        { error: "ML Engine reload service unreachable" },
        { status: 400 }
      );
    }
  } catch (error: any) {
    console.error("Model Upload API Error:", error);
    return NextResponse.json(
      { error: error.message || "Internal Server Error" },
      { status: 500 }
    );
  }
}