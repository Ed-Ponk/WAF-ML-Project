/**
 * ══════════════════════════════════════════════════════════════════
 * Auth Helper — JWT verification for API routes
 *
 * Reusable authentication for dashboard API endpoints.
 * Extracts token from cookie or Authorization header,
 * verifies it with jsonwebtoken.
 * ══════════════════════════════════════════════════════════════════
 */

import jwt from "jsonwebtoken";
import { getJwtSecret } from "./jwt";

const ALLOWED_ROLES = ["admin", "manager", "viewer"] as const;

export interface AuthUser {
  userid: number;
  username: string;
  role: string;
  iat: number;
  exp: number;
}

export interface AuthResult {
  ok: true;
  user: AuthUser;
  response?: never;
}

export interface AuthError {
  ok: false;
  user?: never;
  response: Response;
}

export type AuthenticatedResult = AuthResult | AuthError;

/**
 * Authenticate a request. Returns { ok: true, user } on success,
 * or { ok: false, response } with a pre-built 401/403 Response.
 */
export async function authenticate(
  request: Request,
  options?: { requireAdmin?: boolean }
): Promise<AuthenticatedResult> {
  // 1. Extract token from cookie or Authorization header
  let token: string | undefined;

  const cookieHeader = request.headers.get("cookie") || "";
  const cookieMatch = cookieHeader.match(/token=([^;]+)/);
  if (cookieMatch) {
    token = cookieMatch[1];
  }

  if (!token) {
    const authHeader = request.headers.get("authorization") || "";
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch) {
      token = bearerMatch[1];
    }
  }

  if (!token) {
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    };
  }

  // 2. Verify token — getJwtSecret() runs at request time (fail closed)
  let decoded: any;
  try {
    decoded = jwt.verify(token, getJwtSecret());
  } catch {
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    };
  }

  if (!decoded || !decoded.role) {
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    };
  }

  // 3. Check role
  if (!ALLOWED_ROLES.includes(decoded.role as any)) {
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    };
  }

  if (options?.requireAdmin && decoded.role !== "admin") {
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "Forbidden: Admin role required" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    };
  }

  return { ok: true, user: decoded as AuthUser };
}