import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";

const JWT_SECRET = process.env.JWT_SECRET || "waf-dashboard-secret-key-15-years-exp";

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
      decoded = jwt.verify(token, JWT_SECRET);
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

      return NextResponse.json({
        success: true,
        message: "Model reloaded successfully in-memory",
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
