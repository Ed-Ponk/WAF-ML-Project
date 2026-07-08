import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Edge-safe JWT decoder (no Node.js dependencies)
function decodeJwt(token: string) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Protect routes under /admin/*
  if (pathname.startsWith("/admin")) {
    const token = request.cookies.get("token")?.value;

    if (!token) {
      const loginUrl = new URL("/dashboard/login", request.url);
      return NextResponse.redirect(loginUrl);
    }

    const payload = decodeJwt(token);
    if (!payload || !payload.role) {
      // Clear invalid token and redirect
      const response = NextResponse.redirect(new URL("/dashboard/login", request.url));
      response.cookies.delete("token");
      return response;
    }

    // RBAC: Verify if role is authorized for admin dashboard
    const allowedRoles = ["admin", "manager", "viewer"];
    if (!allowedRoles.includes(payload.role)) {
      const forbiddenUrl = new URL("/dashboard/login?error=unauthorized", request.url);
      return NextResponse.redirect(forbiddenUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*"],
};
