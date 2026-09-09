import { NextResponse } from "next/server";
import { query } from "../../../lib/db";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { getJwtSecret } from "../../../lib/jwt";

// ─────────────────────────────────────────────────────────────
// In-memory rate limiter for login attempts (brute-force mitigation)
//
// IMPORTANT: This store lives only in the dashboard process memory.
//   - It RESETS when the dashboard container restarts.
//   - It is NOT shared across replicas.
// If the dashboard is ever scaled to more than one instance, this
// mechanism must be moved to a shared store (e.g. Redis).
//
// Keyed by ip + username so brute-forcing one account does not lock
// out every user behind the same NAT/proxy.
// ─────────────────────────────────────────────────────────────
const MAX_FAILED_ATTEMPTS = 5;            // allowed failures; the NEXT one is blocked
const FAILURE_WINDOW_MS = 15 * 60 * 1000; // window in which failures count
const LOCK_MS = 15 * 60 * 1000;           // temp lock duration after limit hit
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;  // housekeeping cadence

interface LoginAttemptEntry {
  failTimes: number[];
  lockedUntil: number; // 0 = not locked
}

const loginAttempts = new Map<string, LoginAttemptEntry>();
let lastSweep = Date.now();

function getClientIp(request: Request): string {
  // X-Real-IP is set unconditionally by nginx to $remote_addr and is the
  // authoritative source. X-Forwarded-For can carry attacker-supplied values,
  // so it is only a fallback (last entry) when X-Real-IP is absent.
  const realIp = request.headers.get("x-real-ip");
  if (realIp && realIp.trim()) {
    return realIp.trim();
  }
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded && forwarded.trim()) {
    const parts = forwarded.split(",");
    return parts[parts.length - 1].trim();
  }
  return "unknown";
}

function isLoginLocked(key: string, now: number): boolean {
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (now < entry.lockedUntil) return true;
  const lastFail = entry.failTimes[entry.failTimes.length - 1];
  if (entry.failTimes.length === 0 || now - lastFail > FAILURE_WINDOW_MS) {
    loginAttempts.delete(key);
  }
  return false;
}

function recordFailedLogin(key: string, now: number): boolean {
  let entry = loginAttempts.get(key);
  if (!entry) {
    entry = { failTimes: [], lockedUntil: 0 };
    loginAttempts.set(key, entry);
  }
  const cutoff = now - FAILURE_WINDOW_MS;
  entry.failTimes = entry.failTimes.filter((t) => t > cutoff);
  entry.failTimes.push(now);
  // MAX_FAILED_ATTEMPTS failures are allowed (401); block from the (MAX+1)-th on.
  if (entry.failTimes.length > MAX_FAILED_ATTEMPTS) {
    entry.lockedUntil = now + LOCK_MS;
  }
  if (now - lastSweep > SWEEP_INTERVAL_MS) {
    lastSweep = now;
    for (const [k, e] of loginAttempts) {
      if (now > e.lockedUntil &&
          (e.failTimes.length === 0 || now - e.failTimes[e.failTimes.length - 1] > FAILURE_WINDOW_MS)) {
        loginAttempts.delete(k);
      }
    }
  }
  return now < entry.lockedUntil;
}

function logFailedLogin(ip: string, username: string): void {
  console.warn(
    `Failed login attempt: username=${username}, ip=${ip}, time=${new Date().toISOString()}`
  );
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { username, password } = body;

    // Brute-force gate: runs before any password work (bcrypt.compare) or DB hit.
    const ip = getClientIp(request);
    const rateKey = `${ip}:${String(username ?? "")}`;
    const now = Date.now();

    if (isLoginLocked(rateKey, now)) {
      return NextResponse.json(
        { error: "Too many failed login attempts. Please try again later." },
        { status: 429 }
      );
    }

    if (!username || !password) {
      return NextResponse.json(
        { error: "Username and password are required" },
        { status: 400 }
      );
    }

    const result = await query("SELECT * FROM waf_users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      // Count as failure too, so username enumeration is also rate-limited.
      const locked = recordFailedLogin(rateKey, Date.now());
      logFailedLogin(ip, username);
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: locked ? 429 : 401 }
      );
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      const locked = recordFailedLogin(rateKey, Date.now());
      logFailedLogin(ip, username);
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: locked ? 429 : 401 }
      );
    }

    // Success: clear failed-attempt history for this combo
    loginAttempts.delete(rateKey);

    // Sign JWT token with: userid, username, role
    const token = jwt.sign(
      {
        userid: user.id,
        username: user.username,
        role: user.role,
      },
      getJwtSecret(),
      { expiresIn: "8h" }
    );

    const response = NextResponse.json(
      {
        success: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
      },
      { status: 200 }
    );

    // Set secure HttpOnly cookie containing the signed JWT token
    // secure=false because Nginx terminates TLS and proxies internally as HTTP.
    // In front of a real TLS-terminating reverse proxy, set secure=true
    // and configure the proxy to forward X-Forwarded-Proto: https.
    response.cookies.set({
      name: "token",
      value: token,
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 8, // 8 hours
    });

    return response;
  } catch (error) {
    console.error("Login API Error:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

// Support GET for session verification if needed
export async function GET(request: Request) {
  try {
    const cookieHeader = request.headers.get("cookie") || "";
    const tokenMatch = cookieHeader.match(/token=([^;]+)/);
    const token = tokenMatch ? tokenMatch[1] : null;

    if (!token) {
      return NextResponse.json({ authenticated: false }, { status: 401 });
    }

    const decoded = jwt.verify(token, getJwtSecret()) as any;
    return NextResponse.json({ authenticated: true, user: decoded }, { status: 200 });
  } catch (err) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }
}

// Support DELETE for logout
export async function DELETE() {
  const response = NextResponse.json({ success: true });
  response.cookies.set({
    name: "token",
    value: "",
    httpOnly: true,
    expires: new Date(0),
    path: "/",
  });
  return response;
}