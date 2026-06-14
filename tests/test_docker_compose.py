"""TDD tests for docker-compose.yml — Phase 1: Foundation

These tests validate the expected docker-compose.yml structure AFTER Phase 1
changes (network reconfiguration, new pyme services). They are written FIRST
(TDD RED phase) and will fail until the corresponding changes are implemented.

Spec references:
  - R1: Single Entry Point (no host ports on backend)
  - R2: Unified Network Topology (pyme-security-net bridge)
  - R6: Backend Hardening (no ports directive)

Phase 1 Tasks:
  - 1.2: pyme-security-net driver:bridge + add to ml-engine
  - 1.3: pyme-react-frontend service
  - 1.4: pyme-php-backend service (no ports)
"""

import yaml
from pathlib import Path

COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"


def load_compose() -> dict:
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


# ── Task 1.2: pyme-security-net reconfiguration ──────────────────────


def test_pyme_security_net_is_bridge_not_external():
    """Task 1.2: pyme-security-net must be driver: bridge, NOT external."""
    compose = load_compose()
    net = compose["networks"]["pyme-security-net"]
    assert net.get("driver") == "bridge", (
        f"Expected driver: bridge, got {net.get('driver')!r}"
    )
    assert "external" not in net, (
        "pyme-security-net should NOT be external — Compose must auto-create it"
    )


def test_ml_engine_on_both_networks():
    """Task 1.2: ml-engine must have pyme-security-net added (keeping waf-backend)."""
    compose = load_compose()
    networks = compose["services"]["ml-engine"]["networks"]
    assert "pyme-security-net" in networks, (
        "ml-engine missing pyme-security-net"
    )
    assert "waf-backend" in networks, (
        "ml-engine must keep waf-backend"
    )


def test_proxy_has_all_three_networks():
    """Task 1.2: proxy must have waf-frontend, waf-backend, pyme-security-net."""
    compose = load_compose()
    networks = compose["services"]["proxy"]["networks"]
    required = {"waf-frontend", "waf-backend", "pyme-security-net"}
    assert required.issubset(networks), (
        f"proxy networks missing: {required - set(networks)}"
    )


# ── Task 1.3: pyme-react-frontend service ────────────────────────────


def _env_to_dict(env_list: list) -> dict:
    """Convert docker-compose env list format ['KEY=val'] to dict."""
    result = {}
    for item in env_list:
        if "=" in item:
            key, _, val = item.partition("=")
            result[key.strip()] = val.strip()
        else:
            result[item.strip()] = ""
    return result


def test_pyme_react_frontend_service_exists():
    """Task 1.3: pyme-react-frontend must have correct config."""
    compose = load_compose()
    svc = compose["services"]["pyme-react-frontend"]

    assert svc["container_name"] == "pyme-react-frontend"
    assert svc["build"]["context"] == "../../thesis/app-pyme/atel-front"
    assert svc.get("restart") == "unless-stopped"
    assert "pyme-security-net" in svc["networks"], (
        "Frontend must be on pyme-security-net"
    )

    # R6: No host ports
    assert "ports" not in svc, (
        "Frontend must NOT expose host ports — traffic enters through proxy"
    )

    # Memory limit
    assert svc["deploy"]["resources"]["limits"]["memory"] == "512M", (
        "Frontend memory limit should be 512M"
    )

    # Environment (docker-compose list format)
    env = _env_to_dict(svc["environment"])
    assert env.get("VITE_LINK_BACKEND") == "/api/v1"


# ── Task 1.4: pyme-php-backend service ───────────────────────────────


def test_pyme_php_backend_service_exists():
    """Task 1.4: pyme-php-backend must have correct config and NO ports."""
    compose = load_compose()
    svc = compose["services"]["pyme-php-backend"]

    assert svc["container_name"] == "pyme-php-backend"
    assert svc["build"]["context"] == "../../thesis/app-pyme/atel-back"
    assert svc.get("restart") == "unless-stopped"
    assert "pyme-security-net" in svc["networks"], (
        "Backend must be on pyme-security-net"
    )

    # R1 / R6: NO host ports — single entry point enforcement
    assert "ports" not in svc, (
        "Backend MUST NOT have ports directive — R1 single entry point violation"
    )

    # Memory limit
    assert svc["deploy"]["resources"]["limits"]["memory"] == "256M", (
        "Backend memory limit should be 256M"
    )

    # Environment should reference database hostname from compose
    env = _env_to_dict(svc["environment"])
    db_url = env.get("DATABASE_URL", "")
    assert "database" in db_url, (
        "Backend DATABASE_URL must reference the 'database' hostname"
    )
    assert "${DB_USER}" in db_url
    assert "${DB_PASSWORD}" in db_url
    assert "${DB_PORT}" in db_url
    assert "${DB_NAME}" in db_url


# ── WAF Admin Dashboard — Phase 1 & 2 TDD Tests ──────────────────────


def test_database_init_sql_has_required_tables():
    """Phase 1: init.sql must define waf_users, waf_hardware_metrics, and waf_baselines with initial seeds."""
    sql_path = Path(__file__).parent.parent / "database" / "init.sql"
    sql_content = sql_path.read_text().lower()

    # Check for waf_users table
    assert "create table if not exists waf_users" in sql_content, (
        "database/init.sql missing CREATE TABLE IF NOT EXISTS waf_users"
    )
    assert "username" in sql_content and "varchar" in sql_content, "waf_users table missing username varchar column"
    assert "password_hash" in sql_content and "varchar" in sql_content, "waf_users table missing password_hash varchar column"
    assert "role" in sql_content and "varchar" in sql_content, "waf_users table missing role varchar column"

    # Check for admin seed in waf_users
    assert "insert into waf_users" in sql_content or "insert into waf_users_data" in sql_content, (
        "database/init.sql missing admin user insertion"
    )
    assert "'admin'" in sql_content, "database/init.sql missing seed of 'admin'"

    # Check for waf_hardware_metrics table
    assert "create table if not exists waf_hardware_metrics" in sql_content, (
        "database/init.sql missing CREATE TABLE IF NOT EXISTS waf_hardware_metrics"
    )
    assert "container_name" in sql_content and "varchar" in sql_content
    assert "cpu_usage_pct" in sql_content and "numeric" in sql_content
    assert "ram_usage_mb" in sql_content and "numeric" in sql_content

    # Check for waf_baselines table
    assert "create table if not exists waf_baselines" in sql_content, (
        "database/init.sql missing CREATE TABLE IF NOT EXISTS waf_baselines"
    )
    assert "baseline_name" in sql_content and "varchar" in sql_content
    assert "true_positives" in sql_content and "integer" in sql_content
    assert "false_positives" in sql_content and "integer" in sql_content
    assert "true_negatives" in sql_content and "integer" in sql_content
    assert "false_negatives" in sql_content and "integer" in sql_content
    assert "generated always as" in sql_content or "generated always as (round" in sql_content, (
        "waf_baselines column 'fpr' must be GENERATED ALWAYS AS"
    )

    # Check for initial seed matrices
    assert "modsecurity" in sql_content, "waf_baselines missing ModSecurity seed"
    assert "coraza" in sql_content, "waf_baselines missing Coraza seed"
    assert "naxsi" in sql_content, "waf_baselines missing NAXSI seed"


def test_nginx_conf_has_dashboard_routing():
    """Phase 2: nginx/default.conf must route /dashboard with auth_request off and WebSocket upgrades."""
    nginx_path = Path(__file__).parent.parent / "nginx" / "default.conf"
    nginx_content = nginx_path.read_text()

    # We expect location /dashboard blocks
    # Should occur twice, once for port 80, once for port 443
    loc_blocks = [line for line in nginx_content.splitlines() if "location /dashboard" in line]
    assert len(loc_blocks) >= 2, (
        f"Expected at least 2 location /dashboard blocks in nginx config, found: {len(loc_blocks)}"
    )

    # Verify key configurations in location /dashboard
    # Let's search for "auth_request off" inside Nginx config
    assert "auth_request off;" in nginx_content, (
        "nginx/default.conf must bypass validation with auth_request off; for /dashboard"
    )

    # Verify WS header upgrades
    assert "proxy_set_header Upgrade" in nginx_content, (
        "nginx/default.conf must proxy Upgrade header for WebSocket fast-refresh"
    )
    assert "proxy_set_header Connection" in nginx_content, (
        "nginx/default.conf must proxy Connection header for WebSocket upgrades"
    )

    # Verify proxy_pass to waf-dashboard
    assert "proxy_pass http://waf-dashboard:3000" in nginx_content, (
        "nginx/default.conf must proxy_pass to http://waf-dashboard:3000"
    )


def test_docker_compose_has_waf_dashboard_service():
    """Phase 2: docker-compose.yml must define waf-dashboard with dependencies, volumes, and env."""
    compose = load_compose()
    assert "waf-dashboard" in compose["services"], (
        "docker-compose.yml missing 'waf-dashboard' service"
    )

    svc = compose["services"]["waf-dashboard"]
    assert svc.get("container_name") == "waf-dashboard", (
        f"Expected container_name: waf-dashboard, got {svc.get('container_name')}"
    )

    build = svc.get("build", {})
    assert build.get("context") == "./dashboard", (
        f"Expected build context: ./dashboard, got {build.get('context')}"
    )

    # Volume mapping
    volumes = svc.get("volumes", [])
    assert "./ml-engine:/ml-engine" in volumes or "/ml-engine" in "".join(volumes), (
        f"Expected shared ml-engine volume mapping, got {volumes}"
    )

    # Dependencies
    deps = svc.get("depends_on", [])
    if isinstance(deps, dict):
        assert "database" in deps, "waf-dashboard must depend on 'database'"
        assert "ml-engine" in deps, "waf-dashboard must depend on 'ml-engine'"
    else:
        assert "database" in deps, "waf-dashboard must depend on 'database'"
        assert "ml-engine" in deps, "waf-dashboard must depend on 'ml-engine'"

    # Environment variables (could be list or dict)
    env = svc.get("environment", [])
    if isinstance(env, list):
        env_dict = _env_to_dict(env)
    else:
        env_dict = env or {}

    assert "POSTGRES_USER" in env_dict or "DB_USER" in env_dict or any("DB" in k for k in env_dict), (
        "waf-dashboard missing database environment variables"
    )
    assert "JWT_SECRET" in env_dict, "waf-dashboard missing JWT_SECRET environment variable"
    assert "ML_ENGINE_URL" in env_dict, "waf-dashboard missing ML_ENGINE_URL environment variable"

