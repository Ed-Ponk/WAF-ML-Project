import { NextResponse } from "next/server";
import { query } from "../../../lib/db";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { getJwtSecret } from "../../../lib/jwt";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return NextResponse.json(
        { error: "Username and password are required" },
        { status: 400 }
      );
    }

    const result = await query("SELECT * FROM waf_users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 }
      );
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 }
      );
    }

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