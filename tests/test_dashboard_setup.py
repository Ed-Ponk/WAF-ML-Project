"""TDD tests for Phase 4: Next.js Setup & Auth Components

These tests validate:
  - Task 4.1: Standalone Next.js folder structure, configurations, and package.json dependencies.
  - Task 4.2: Asynchronous PostgreSQL pooling configuration in dashboard/lib/db.ts.
  - Task 4.3: JWT and Bcrypt Authentication in Next.js (api route & middleware logic).
  - Task 4.4: UI Components (AuthCard.tsx, login/page.tsx, entry routing page.tsx, admin/layout.tsx).

Spec references:
  - R1: RBAC Administration (Bcrypt, Cookie-based JWT, middleware)
  - R7: Production DB Protection (pg pool, max: 20 connections, idleTimeout: 30000, connTimeout: 5000)
"""

import json
import re
from pathlib import Path

# Paths to dashboard and config files
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
PACKAGE_JSON = DASHBOARD_DIR / "package.json"
NEXT_CONFIG = DASHBOARD_DIR / "next.config.js"
TS_CONFIG = DASHBOARD_DIR / "tsconfig.json"
TAILWIND_CONFIG = DASHBOARD_DIR / "tailwind.config.js"
POSTCSS_CONFIG = DASHBOARD_DIR / "postcss.config.js"
DB_TS = DASHBOARD_DIR / "lib" / "db.ts"
AUTH_API_ROUTE = DASHBOARD_DIR / "app" / "api" / "auth" / "route.ts"
MIDDLEWARE_TS = DASHBOARD_DIR / "middleware.ts"
AUTH_CARD_TSX = DASHBOARD_DIR / "components" / "dashboard" / "AuthCard.tsx"
LOGIN_PAGE_TSX = DASHBOARD_DIR / "app" / "login" / "page.tsx"
ENTRY_PAGE_TSX = DASHBOARD_DIR / "app" / "page.tsx"
ADMIN_LAYOUT_TSX = DASHBOARD_DIR / "app" / "admin" / "layout.tsx"


# ═══════════════════════════════════════════════════════════════════════
# 1. Folder Structure & Configurations Validation
# ═══════════════════════════════════════════════════════════════════════

def test_dashboard_folder_structure_exists():
    """Verify that all required Next.js dashboard subdirectories exist."""
    required_dirs = [
        DASHBOARD_DIR,
        DASHBOARD_DIR / "app",
        DASHBOARD_DIR / "app" / "api",
        DASHBOARD_DIR / "app" / "api" / "auth",
        DASHBOARD_DIR / "app" / "admin",
        DASHBOARD_DIR / "components",
        DASHBOARD_DIR / "components" / "dashboard",
        DASHBOARD_DIR / "lib",
    ]
    for d in required_dirs:
        assert d.exists(), f"Directory {d.relative_to(DASHBOARD_DIR.parent)} does not exist."
        assert d.is_dir(), f"Path {d.relative_to(DASHBOARD_DIR.parent)} is not a directory."


def test_package_json_has_correct_dependencies():
    """Verify package.json exists and has correct dependencies for Next.js and secure auth."""
    assert PACKAGE_JSON.exists(), "package.json does not exist in dashboard/"
    
    with open(PACKAGE_JSON, "r") as f:
        data = json.load(f)
    
    assert "dependencies" in data, "package.json missing 'dependencies' field"
    deps = data["dependencies"]
    
    required_deps = [
        "next",
        "react",
        "react-dom",
        "lucide-react",
        "recharts",
        "pg",
        "bcryptjs",
        "jsonwebtoken",
        "tailwindcss"
    ]
    
    for dep in required_deps:
        assert dep in deps, f"Required dependency '{dep}' is missing from package.json"


def test_next_config_is_standalone_with_basepath():
    """Verify next.config.js exists and is configured for basePath: '/dashboard' and standalone output."""
    assert NEXT_CONFIG.exists(), "next.config.js does not exist"
    
    content = NEXT_CONFIG.read_text()
    
    # Check for basePath: "/dashboard" or '/dashboard'
    assert re.search(r"basePath:\s*['\"]/dashboard['\"]", content), (
        "next.config.js missing basePath: '/dashboard' configuration"
    )
    
    # Check for output: "standalone" or 'standalone'
    assert re.search(r"output:\s*['\"]standalone['\"]", content), (
        "next.config.js missing output: 'standalone' configuration"
    )


def test_tsconfig_tailwind_postcss_exist():
    """Verify that required Next.js configurations (TS, Tailwind, PostCSS) exist."""
    assert TS_CONFIG.exists(), "tsconfig.json does not exist"
    assert TAILWIND_CONFIG.exists(), "tailwind.config.js does not exist"
    assert POSTCSS_CONFIG.exists(), "postcss.config.js does not exist"


# ═══════════════════════════════════════════════════════════════════════
# 2. Non-blocking Asynchronous DB Connection Pool (Task 4.2)
# ═══════════════════════════════════════════════════════════════════════

def test_db_pool_configuration():
    """Verify that database connection pool in db.ts is correctly configured."""
    assert DB_TS.exists(), "lib/db.ts does not exist"
    
    content = DB_TS.read_text()
    
    # Must use 'pg' Pool
    assert "Pool" in content, "lib/db.ts must import and use pg.Pool"
    
    # Verify pool configuration parameters (max: 20, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000)
    # Checking for typical keys like max: 20, idleTimeoutMillis: 30000, and connectionTimeoutMillis: 5000
    assert re.search(r"max:\s*20", content), (
        "Database pool 'max' connection limit must be configured as 20 for DB performance protection (R7)"
    )
    assert re.search(r"idleTimeoutMillis:\s*30000", content) or re.search(r"idleTimeout:\s*30000", content), (
        "Database pool idle timeout must be 30000 ms"
    )
    assert re.search(r"connectionTimeoutMillis:\s*5000", content) or re.search(r"connectionTimeout:\s*5000", content), (
        "Database pool connection timeout must be 5000 ms"
    )


# ═══════════════════════════════════════════════════════════════════════
# 3. JWT & Bcrypt Authentication Endpoint & Middleware (Task 4.3)
# ═══════════════════════════════════════════════════════════════════════

def test_auth_api_route_implements_credentials_validation():
    """Verify that app/api/auth/route.ts exists and implements login validation."""
    assert AUTH_API_ROUTE.exists(), "app/api/auth/route.ts does not exist"
    
    content = AUTH_API_ROUTE.read_text()
    
    # Must import bcryptjs and jsonwebtoken
    assert "bcryptjs" in content or "bcrypt" in content, "Authentication API route should use bcrypt for password checking"
    assert "jsonwebtoken" in content or "jwt" in content, "Authentication API route should use jsonwebtoken to sign session tokens"
    
    # Must query database table waf_users
    assert "waf_users" in content, "Authentication API route must query the 'waf_users' table"
    
    # Must set secure HttpOnly cookie containing JWT
    assert "HttpOnly" in content or "httpOnly" in content, "JWT session token must be returned as a secure, HTTP-Only cookie"


def test_middleware_protects_admin_routes_with_rbac():
    """Verify that middleware.ts protects admin routes and validates JWT roles."""
    assert MIDDLEWARE_TS.exists(), "middleware.ts does not exist"
    
    content = MIDDLEWARE_TS.read_text()
    
    # Must check path starting with /admin or matcher config
    assert "/admin" in content, "Middleware must match or process administrative path redirects"
    
    # Must read/parse the JWT token and verify roles
    assert "jwt" in content or "jsonwebtoken" in content or "jose" in content or "NextResponse.redirect" in content, (
        "Middleware must inspect and parse JWT credentials and handle redirects"
    )


# ═══════════════════════════════════════════════════════════════════════
# 4. UI Page Components & Layouts (Task 4.4)
# ═══════════════════════════════════════════════════════════════════════

def test_auth_card_component_structure():
    """Verify AuthCard.tsx is a custom client form component with inputs and state."""
    assert AUTH_CARD_TSX.exists(), "AuthCard.tsx does not exist"
    
    content = AUTH_CARD_TSX.read_text()
    
    # Must be client-side component (Next.js use client)
    assert "use client" in content, "AuthCard component must be a client component ('use client')"
    
    # Check for inputs for username/email and password
    assert "password" in content, "AuthCard must contain a password input field"
    assert "username" in content or "email" in content, "AuthCard must contain a username or email input field"
    
    # Must handle error feedback state or loading state
    assert "error" in content or "err" in content or "setError" in content, (
        "AuthCard must have state and handlers to display error feedback to the user"
    )


def test_login_page_renders_auth_card():
    """Verify login/page.tsx exists and references/renders AuthCard component."""
    assert LOGIN_PAGE_TSX.exists(), "login/page.tsx does not exist"
    
    content = LOGIN_PAGE_TSX.read_text()
    assert "AuthCard" in content, "login/page.tsx must import and render the AuthCard component"


def test_entry_page_redirects_based_on_cookies():
    """Verify root page.tsx redirects entry points based on session cookie presence."""
    assert ENTRY_PAGE_TSX.exists(), "app/page.tsx does not exist"
    
    content = ENTRY_PAGE_TSX.read_text()
    # Should perform a server-side or middleware-assisted redirect
    assert "redirect" in content, "app/page.tsx should handle entry redirect to /login or /admin"


def test_admin_layout_provides_sidebar_and_logout():
    """Verify admin/layout.tsx exists and provides sidebar structure with logout capability."""
    assert ADMIN_LAYOUT_TSX.exists(), "app/admin/layout.tsx does not exist"
    
    content = ADMIN_LAYOUT_TSX.read_text()
    
    # Sidebar components or layout divs
    assert "children" in content, "admin/layout.tsx must render children components"
    assert "Sidebar" in content or "sidebar" in content or "nav" in content or "aside" in content, (
        "admin/layout.tsx must define a sidebar navigation area"
    )
    assert "logout" in content or "Logout" in content or "signout" in content or "SignOut" in content, (
        "admin/layout.tsx must provide a mechanism or element for user logout"
    )
