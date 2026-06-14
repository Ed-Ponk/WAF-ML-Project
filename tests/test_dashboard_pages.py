"""TDD tests for Phase 5: Dashboard Pages & Charts

These tests validate:
  - Task 5.1/5.3: API routes for stats and alerts exist, query the correct tables, use async query and pg pool constraints.
  - Task 5.2/5.3: Alerts API implements pagination ('page', 'limit') and offset calculation.
  - Task 5.4: UI Components exist under components/dashboard/ (GeneralTraffic.tsx and AlertTable.tsx) with 'use client' tags.
  - Task 5.5: app/admin/page.tsx exists and imports/renders both GeneralTraffic and AlertTable.

Spec references:
  - R2: General Traffic Telemetry (waf_daily_summary, AreaChart for Allowed/Blocked, PieChart for Attacks)
  - R3: Chronological Alert Log (waf_events, pagination page & limit, detail modal with raw Payload, Shannon Entropy, and LightGBM/MLP scores)
  - R7: Production DB Protection (query aggregated views, pg pool constraints)
"""

from pathlib import Path
import re

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
STATS_API = DASHBOARD_DIR / "app" / "api" / "stats" / "route.ts"
ALERTS_API = DASHBOARD_DIR / "app" / "api" / "alerts" / "route.ts"
GENERAL_TRAFFIC = DASHBOARD_DIR / "components" / "dashboard" / "GeneralTraffic.tsx"
ALERT_TABLE = DASHBOARD_DIR / "components" / "dashboard" / "AlertTable.tsx"
ADMIN_PAGE = DASHBOARD_DIR / "app" / "admin" / "page.tsx"


def test_api_routes_exist_and_query_correct_tables():
    """Verify that stats and alerts API routes exist and query proper tables."""
    assert STATS_API.exists(), "api/stats/route.ts does not exist"
    assert ALERTS_API.exists(), "api/alerts/route.ts does not exist"
    
    stats_content = STATS_API.read_text()
    alerts_content = ALERTS_API.read_text()
    
    # Check that stats queries waf_daily_summary (R7)
    assert "waf_daily_summary" in stats_content, "Stats API must query 'waf_daily_summary' for heavy read telemetry protection"
    # Stats API should NOT query raw waf_events to protect performance
    assert "waf_events" not in stats_content, "Stats API should use pre-aggregated 'waf_daily_summary' instead of raw 'waf_events'"
    
    # Check that alerts queries waf_events
    assert "waf_events" in alerts_content, "Alerts API must query 'waf_events' table"
    
    # Verify pool usage (async query from lib/db)
    assert "query" in stats_content, "Stats API must use db query helper from lib/db"
    assert "query" in alerts_content, "Alerts API must use db query helper from lib/db"


def test_alerts_api_implements_pagination():
    """Verify that alerts API processes page/limit parameters and offsets."""
    assert ALERTS_API.exists(), "api/alerts/route.ts does not exist"
    
    content = ALERTS_API.read_text()
    
    # Must parse page and limit params
    assert "page" in content.lower(), "Alerts API must parse 'page' query parameter"
    assert "limit" in content.lower(), "Alerts API must parse 'limit' query parameter"
    
    # Offset calculation
    assert "offset" in content.lower(), "Alerts API must compute or use SQL OFFSET"
    
    # Limit & Offset in SQL string
    assert "limit" in content.lower() and "offset" in content.lower(), (
        "Alerts API must apply LIMIT and OFFSET constraints to the SQL query"
    )
    # Check for accion = 'BLOCK'
    assert "BLOCK" in content, "Alerts API should query specifically for events with accion = 'BLOCK'"


def test_ui_components_exist_with_client_directive():
    """Verify GeneralTraffic.tsx and AlertTable.tsx exist with client components directive."""
    assert GENERAL_TRAFFIC.exists(), "GeneralTraffic.tsx does not exist"
    assert ALERT_TABLE.exists(), "AlertTable.tsx does not exist"
    
    gt_content = GENERAL_TRAFFIC.read_text()
    at_content = ALERT_TABLE.read_text()
    
    # NextJS client components
    assert "use client" in gt_content or "'use client'" in gt_content or '"use client"' in gt_content, (
        "GeneralTraffic must use client components directive"
    )
    assert "use client" in at_content or "'use client'" in at_content or '"use client"' in at_content, (
        "AlertTable must use client components directive"
    )
    
    # GeneralTraffic should use Recharts
    assert "recharts" in gt_content.lower() or "responsivecontainer" in gt_content.lower(), (
        "GeneralTraffic component must use Recharts for visual traffic charts"
    )
    
    # AlertTable should have modal references or modal state for alert details (Shannon entropy, ensemble score)
    assert "shannon" in at_content.lower() or "entropy" in at_content.lower(), (
        "AlertTable modal must display Shannon Entropy details"
    )
    assert "lightgbm" in at_content.lower() or "mlp" in at_content.lower(), (
        "AlertTable modal must display LightGBM/MLP ensemble details"
    )


def test_admin_page_renders_both_components():
    """Verify app/admin/page.tsx exists and renders GeneralTraffic and AlertTable components."""
    assert ADMIN_PAGE.exists(), "app/admin/page.tsx does not exist"
    
    content = ADMIN_PAGE.read_text()
    
    # Imports both components
    assert "GeneralTraffic" in content, "admin/page.tsx must import and render GeneralTraffic"
    assert "AlertTable" in content, "admin/page.tsx must import and render AlertTable"
