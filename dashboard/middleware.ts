import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { jwtVerify } from "jose/jwt/verify";
import { getJwtSecret } from "./lib/jwt";

const ALLOWED_ROLES = ["admin", "manager", "viewer"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Protect routes under /admin/*
  if (pathname.startsWith("/admin")) {
    const token = request.cookies.get("token")?.value;

    if (!token) {
      const loginUrl = new URL("/dashboard/login", request.url);
      return NextResponse.redirect(loginUrl);
    }

    let payload: any;
    try {
      // getJwtSecret() runs at request time; if JWT_SECRET is missing it
      // throws here and the token is treated as invalid (fail closed).
      const { payload: verified } = await jwtVerify(
        token,
        new TextEncoder().encode(getJwtSecret())
      );
      payload = verified;
    } catch {
      // Signature invalid or token expired — clear and redirect
      const response = NextResponse.redirect(
        new URL("/dashboard/login", request.url)
      );
      response.cookies.delete("token");
      return response;
    }

    // RBAC: verify role is authorized for admin dashboard
    if (!ALLOWED_ROLES.includes(payload.role as string)) {
      const forbiddenUrl = new URL("/dashboard/login?error=unauthorized", request.url);
      return NextResponse.redirect(forbiddenUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*"],
};