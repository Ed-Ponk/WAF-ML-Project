import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    status: "ok",
    service: "waf-dashboard",
    ts: new Date().toISOString(),
  });
}