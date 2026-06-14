"""TDD tests for Phase 6: Advanced Operations & Background loops

These tests validate:
  - Telemetry API (api/telemetry/route.ts) returns latencies and container metrics.
  - Confusion Matrix API (api/confusion-matrix/route.ts) reads/edits baselines, calculating FPR.
  - Model Upload API (api/model/upload/route.ts) enforces RBAC (admin only) and handles safe reload.
  - Components exist: HardwareMonitor, ModelManagement, ConfusionMatrix with 'use client' directive.
  - Admin page updates to render the new components.
"""

from pathlib import Path
import re

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
TELEMETRY_API = DASHBOARD_DIR / "app" / "api" / "telemetry" / "route.ts"
CONFUSION_MATRIX_API = DASHBOARD_DIR / "app" / "api" / "confusion-matrix" / "route.ts"
MODEL_UPLOAD_API = DASHBOARD_DIR / "app" / "api" / "model" / "upload" / "route.ts"

HARDWARE_MONITOR = DASHBOARD_DIR / "components" / "dashboard" / "HardwareMonitor.tsx"
MODEL_MANAGEMENT = DASHBOARD_DIR / "components" / "dashboard" / "ModelManagement.tsx"
CONFUSION_MATRIX = DASHBOARD_DIR / "components" / "dashboard" / "ConfusionMatrix.tsx"

ADMIN_PAGE = DASHBOARD_DIR / "app" / "admin" / "page.tsx"


def test_telemetry_api_exists_and_queries_metrics():
    """Verify telemetry API queries recent latencies and container hardware metrics."""
    assert TELEMETRY_API.exists(), "Telemetry API route.ts does not exist"
    
    content = TELEMETRY_API.read_text()
    
    # Must query recent latencies from waf_events
    assert "waf_events" in content, "Telemetry API must query 'waf_events'"
    assert "tiempo_inferencia_ms" in content, "Telemetry API must extract 'tiempo_inferencia_ms'"
    
    # Must query container metrics from waf_hardware_metrics
    assert "waf_hardware_metrics" in content, "Telemetry API must query 'waf_hardware_metrics'"
    assert "cpu_usage_pct" in content, "Telemetry API must retrieve 'cpu_usage_pct'"
    assert "ram_usage_mb" in content, "Telemetry API must retrieve 'ram_usage_mb'"
    assert "container_name" in content, "Telemetry API must filter/group by 'container_name'"
    
    # Must use query from lib/db
    assert "query" in content, "Telemetry API must import/use the query helper"


def test_confusion_matrix_api_reads_and_updates_baselines():
    """Verify confusion matrix API reads (GET) baselines and updates (POST/PUT) values."""
    assert CONFUSION_MATRIX_API.exists(), "Confusion Matrix API route.ts does not exist"
    
    content = CONFUSION_MATRIX_API.read_text()
    
    # GET method queries waf_baselines and vw_confusion_matrix
    assert "GET" in content, "Confusion Matrix API must support GET"
    assert "waf_baselines" in content or "vw_confusion_matrix" in content, "Confusion Matrix API must read baselines or confusion matrix"
    
    # POST/PUT updates metrics of a specific baseline
    assert "POST" in content or "PUT" in content, "Confusion Matrix API must support POST or PUT updates"
    assert "UPDATE" in content or "query" in content, "Confusion Matrix API must perform database updates"
    assert "true_positives" in content, "Confusion Matrix API must handle true_positives"
    assert "false_positives" in content, "Confusion Matrix API must handle false_positives"
    assert "true_negatives" in content, "Confusion Matrix API must handle true_negatives"
    assert "false_negatives" in content, "Confusion Matrix API must handle false_negatives"


def test_model_upload_api_rbac_and_reload_logic():
    """Verify model upload API checks for 'admin' role, writes model, and reloads it on ML engine."""
    assert MODEL_UPLOAD_API.exists(), "Model upload API route.ts does not exist"
    
    content = MODEL_UPLOAD_API.read_text()
    
    # Enforces admin-only permission
    assert "admin" in content, "Model upload API must enforce 'admin' role check"
    assert "403" in content, "Model upload API must return 403 Forbidden for unauthorized roles"
    
    # Writes to shared volume path
    assert "waf_ensemble_final.pkl" in content, "Model upload API must save to 'waf_ensemble_final.pkl'"
    assert "/ml-engine/waf_ensemble_final.pkl" in content, "Model upload API must target '/ml-engine/waf_ensemble_final.pkl'"
    
    # Reloads model using fetch/POST to ml-engine
    assert "reload_model" in content or "http://ml-engine:8000/reload_model" in content, "Model upload API must trigger reload endpoint"
    assert "400" in content, "Model upload API must handle bad requests / errors from reload endpoint"
    assert "delete" in content or "unlink" in content or "rm" in content or "fs" in content, "Model upload API must clean up or remove invalid model file on failure"


def test_ui_components_exist_with_client_directive():
    """Verify HardwareMonitor.tsx, ModelManagement.tsx, and ConfusionMatrix.tsx exist and have 'use client' tag."""
    assert HARDWARE_MONITOR.exists(), "HardwareMonitor.tsx does not exist"
    assert MODEL_MANAGEMENT.exists(), "ModelManagement.tsx does not exist"
    assert CONFUSION_MATRIX.exists(), "ConfusionMatrix.tsx does not exist"
    
    hm_content = HARDWARE_MONITOR.read_text()
    mm_content = MODEL_MANAGEMENT.read_text()
    cm_content = CONFUSION_MATRIX.read_text()
    
    # Client component directive
    assert "use client" in hm_content or "'use client'" in hm_content or '"use client"' in hm_content, "HardwareMonitor must be a client component"
    assert "use client" in mm_content or "'use client'" in mm_content or '"use client"' in mm_content, "ModelManagement must be a client component"
    assert "use client" in cm_content or "'use client'" in cm_content or '"use client"' in cm_content, "ConfusionMatrix must be a client component"
    
    # HardwareMonitor uses Recharts
    assert "recharts" in hm_content.lower() or "linechart" in hm_content.lower(), "HardwareMonitor must render Recharts line charts"
    # HardwareMonitor polls telemetry (e.g., setInterval or similar polling)
    assert "fetch" in hm_content or "useeffect" in hm_content.lower() or "interval" in hm_content.lower() or "telemetry" in hm_content.lower(), (
       "HardwareMonitor must support polling telemetry metrics"
    )
    
    # ModelManagement drag-and-drop & API upload
    assert "drag" in mm_content.lower() or "drop" in mm_content.lower() or "input" in mm_content.lower(), "ModelManagement must support file upload"
    assert "/api/model/upload" in mm_content, "ModelManagement must post uploads to the upload route"
    
    # ConfusionMatrix table comparison and admin/manager edit capabilities
    assert "baseline_name" in cm_content or "baseline" in cm_content.lower(), "ConfusionMatrix must display comparative baselines"
    assert "form" in cm_content.lower() or "input" in cm_content.lower() or "edit" in cm_content.lower() or "modal" in cm_content.lower(), (
        "ConfusionMatrix must support interactive editing"
    )


def test_admin_page_renders_new_components():
    """Verify app/admin/page.tsx renders HardwareMonitor, ModelManagement, and ConfusionMatrix."""
    assert ADMIN_PAGE.exists(), "app/admin/page.tsx does not exist"
    
    content = ADMIN_PAGE.read_text()
    
    assert "HardwareMonitor" in content, "admin/page.tsx must import and render HardwareMonitor"
    assert "ModelManagement" in content, "admin/page.tsx must import and render ModelManagement"
    assert "ConfusionMatrix" in content, "admin/page.tsx must import and render ConfusionMatrix"
