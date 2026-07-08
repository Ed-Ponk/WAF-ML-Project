"""
extract_features.py — Módulo compartido de extracción de características.

⚠️  SYNC NOTICE — Si modificás este archivo, actualizá también:
   ../../waf-ml-project/ml-engine/extract_features.py

Fuente única de verdad para la extracción de features de ataques de inyección.
Usado tanto por el pipeline de entrenamiento (preprocesamiento_data.py) como
por el motor de inferencia en producción (ml-engine/app.py, que tiene su propia
copia estática en ml-engine/extract_features.py).

CHANGELOG:
  v1.1 (2026) — Auditoría de falsos negativos:
    - FIX: regex "sql" y "has_tautology" con paréntesis opcionales
    - NUEVO: familia "backup_disclosure" (CWE-200)

  v1.2 (2026) — Refuerzo de features de payload:
    - payload_has_injection, payload_to_url_ratio
    - has_suspicious_path_keyword
    - Interacciones: deep_path_with_encoding, post_with_payload,
      sql_with_encoding, get_with_long_query

  v1.3 (2026) — Corrección de falsos positivos en contraseñas encoded:
    - PROBLEMA: contraseñas con caracteres latinos (%E9=é, %F3=ó, %ED=í)
      y símbolos legítimos (%40=@, %24=$) activaban has_url_encoding y
      encoding_density igual que ataques de evasión WAF.
    - SOLUCIÓN: separar encoding en tres categorías:
        * Latino (%Cx, %Dx, %Ex, %Fx): caracteres internacionales → legítimo
        * Símbolo de credencial (%40=@, %2B=+, %24=$, etc.): legítimo en
          campos password/email cuando el parámetro es de autenticación
        * Evasión WAF (%27=', %3C=<, %3E=>, %00=null, etc.): sospechoso
    - NUEVO: is_credential_field() detecta si el encoding está en un campo
      de contraseña o email → neutraliza la penalización
    - NUEVO: count_evasion_encoding solo cuenta los realmente peligrosos
    - NUEVO: evasion_encoding_density reemplaza encoding_density
    - NUEVO: latin_encoding_ratio como señal de legitimidad

  v2.0 (2026) — Mejora de recall en POST body y FPs de apóstrofe:
    - FIX: has_single_quote ahora ignora apóstrofes entre letras (D'Onofrio)
    - NUEVO: single_quote_count — cuenta comillas en lugar de binario
    - NUEVO: single_quote_in_word — detecta apóstrofe de nombre propio
    - NUEVO: body_is_form, max_field_value_len, body_field_count — para
      detectar ataques en POST form-urlencoded sin diluir señal
"""

import re
import math
from urllib.parse import unquote
from collections import Counter


# ==========================================================
# PATRONES DE ATAQUE
# ==========================================================

PATTERNS = {
    "sql": (
        r"(?i)("
        r"select[\s\+\%20]+"
        r"|union[\s\+\%20]+"
        r"|insert[\s\+\%20]+"
        r"|update[\s\+\%20]+"
        r"|delete[\s\+\%20]+"
        r"|drop[\s\+\%20]+"
        r"|waitfor[\s\+]+delay"
        r"|sleep\s*\("
        r"|benchmark\s*\("
        r"|0x[0-9a-f]+"
        r"|char\s*\("
        r"|convert\s*\("
        r"|cast\s*\("
        r"|xp_"
        r"|sp_"
        r"|--"
        r"|;"
        r"|\/\*"
        r"|\*\/"
        r"|(?:\bor\b|\band\b)\s*\(?\s*"
        r"['\"]?[a-zA-Z0-9_]{1,20}['\"]?"
        r"\s*=\s*"
        r"['\"]?[a-zA-Z0-9_]{1,20}['\"]?"
        r"\s*\)?"
        r"|'\s*or\s*'"
        r'|"\s*or\s*"'
        r")"
    ),
    "xss": (
        r"(?i)("
        r"<script"
        r"|javascript:"
        r"|onerror="
        r"|onload="
        r"|onmouseover="
        r"|alert\s*\("
        r"|document\.cookie"
        r"|<iframe"
        r"|<img[^>]+src\s*="
        r"|%3cscript"
        r"|%3c%2fscript"
        r"|&#x3c;script"
        r")"
    ),
    "rce": (
        r"(?i)("
        r"phpunit"
        r"|eval\s*\("
        r"|exec\s*\("
        r"|system\s*\("
        r"|passthru"
        r"|shell_exec"
        r"|popen"
        r"|proc_open"
        r"|`[^`]+`"
        r"|md5\s*\("
        r"|base64_decode"
        r"|\$\{.*\}"
        r"|\$\(.*\)"
        r"|\|\s*(id|whoami|ls|cat|wget|curl|bash|sh)\b"
        r")"
    ),
    "path": (
        r"(?i)("
        r"\.\./"
        r"|\.\.\\"
        r"|%2e%2e"
        r"|%252e%252e"
        r"|/etc/passwd"
        r"|/etc/shadow"
        r"|%2fetc%2fpasswd"
        r"|%252fetc%252fpasswd"
        r"|c:\\windows"
        r"|windows/system32"
        r"|boot\.ini"
        r"|win\.ini"
        r"|/proc/self"
        r"|/var/www"
        r"|/{3,}"
        r"|\{[a-z]+\}"
        r")"
    ),
    "crlf": (
        r"(?i)("
        r"%0d%0a"
        r"|\r\n"
        r"|\r"
        r"|\n"
        r").*?(set-cookie|location:|content-type:|x-forwarded)"
    ),
    "ldap": (
        r"(?i)("
        r"\*\)\("
        r"|\(\|"
        r"|\(&"
        r"|objectclass="
        r"|cn="
        r"|dc="
        r")"
    ),
    "xxe": (
        r"(?i)("
        r"<!entity"
        r"|<!doctype"
        r"|system\s+['\"]"
        r"|public\s+['\"]"
        r"|file://"
        r"|php://"
        r"|expect://"
        r")"
    ),
    "open_redirect": (
        r"(?i)("
        r"redirect_to=https?://"
        r"|url=https?://"
        r"|next=https?://"
        r"|return=https?://"
        r"|returnurl=https?://"
        r"|continue=https?://"
        r"|dest=https?://"
        r"|destination=https?://"
        r"|redir=https?://"
        r"|redirect=https?://"
        r")"
    ),
    "graphql": (
        r"(?i)("
        r"\{__schema"
        r"|\{__type"
        r"|query\s*\{"
        r"|mutation\s*\{"
        r"|introspection"
        r"|__typename"
        r")"
    ),
    "oracle_sql": (
        r"(?i)("
        r"dbms_pipe"
        r"|dbms_output"
        r"|utl_http"
        r"|utl_file"
        r"|all_tables"
        r"|user_tables"
        r"|v\$"
        r"|sys\."
        r")"
    ),
    "backup_disclosure": (
        r"(?i)("
        r"\.bak\b"
        r"|\.old\b"
        r"|\.backup\b"
        r"|\.orig\b"
        r"|\.tmp\b"
        r"|\.swp\b"
        r"|\.save\b"
        r"|~(?:\?|$|\s)"
        r"|\.java\b"
        r")"
    ),
}


# ==========================================================
# CLASIFICACIÓN DE ENCODING (v1.3)
#
# Principio: el mismo byte %XX puede ser legítimo o malicioso
# dependiendo del contexto. Separamos en tres grupos:
#
# LATINO — caracteres internacionales Unicode (é, ó, ñ, ü, etc.)
#   %C0-%FF: Latin Extended, Latin-1 Supplement
#   Aparecen en contraseñas y nombres de usuarios en español/portugués.
#   → NO penalizar
#
# CREDENCIAL — símbolos comunes en contraseñas (@, +, $, !, etc.)
#   %40=@ %2B=+ %24=$ %21=! %23=# %26=& %28=( %29=) %2C=, %2E=.
#   Son legítimos si aparecen en campos pwd/password/pass/email.
#   → NO penalizar si is_credential_field() == True
#
# EVASION — los que usa un atacante para bypassear WAFs
#   %27=' %22=" %3C=< %3E=> %00=null %0A=\n %0D=\r %2F=/ %5C=\
#   %3D== %28=( %29=) cuando NO están en campo de credencial
#   → SÍ penalizar siempre
# ==========================================================

# Encoding latino: rangos %C0-%FF (Latin-1 + Extended)
_RE_LATIN_ENC = re.compile(
    r"%(?:[Cc][0-9A-Fa-f]"
    r"|[Dd][0-9A-Fa-f]"
    r"|[Ee][0-9A-Fa-f]"
    r"|[Ff][0-9A-Fa-f])",
    re.IGNORECASE,
)

# Encoding de evasión WAF — siempre sospechoso
_RE_EVASION_ENC = re.compile(
    r"%(?:27|22|3[Cc]|3[Ee]|00|0[Aa]|0[Dd]|2[Ff]|5[Cc]|7[Cc]|60)",
    re.IGNORECASE,
)

# Símbolos de credencial: @, +, $, !, #, &, (, ), ', espacio
_RE_CREDENTIAL_SYMBOL_ENC = re.compile(
    r"%(?:40|2[Bb]|24|21|23|26|28|29|2[Cc]|2[Ee]|3[Aa]|3[Ff]|5[Ff])",
    re.IGNORECASE,
)

# Nombres de parámetros que indican campo de credencial
_RE_CREDENTIAL_PARAM = re.compile(
    r"(?i)(password|passwd|pwd|pass|contrasena|clave|secret"
    r"|token|api_key|apikey|auth|credential"
    r"|email|mail|correo"
    r"|login|user|usuario|username)",
)


def is_credential_field(payload: str, url: str) -> bool:
    """
    Detecta si la petición contiene campos de credencial (password, email, etc.).
    Si es así, el encoding de símbolos comunes (@, $, +) es legítimo.

    Estrategia: busca nombres de parámetros conocidos en el payload o query string.
    Ejemplo:
        pwd=lucembu%24rgu%E9s  → is_credential_field=True → %24 no se penaliza
        q=SELECT%20*%20FROM    → is_credential_field=False → encoding sí se penaliza
    """
    combined_params = f"{payload} {url}"
    return bool(_RE_CREDENTIAL_PARAM.search(combined_params))


def classify_encoding(raw: str, payload: str, url: str) -> dict:
    """
    Clasifica todos los %XX encontrados en raw en tres categorías.
    Retorna conteos y flags para usar como features.
    """
    all_encoded   = re.findall(r"%[0-9a-fA-F]{2}", raw)
    latin_matches   = _RE_LATIN_ENC.findall(raw)
    evasion_matches = _RE_EVASION_ENC.findall(raw)
    cred_sym_matches = _RE_CREDENTIAL_SYMBOL_ENC.findall(raw)

    total = len(all_encoded)
    n_latin   = len(latin_matches)
    n_evasion = len(evasion_matches)
    n_cred    = len(cred_sym_matches)

    in_cred_field = is_credential_field(payload, url)

    # Si estamos en campo de credencial, los símbolos de credencial son legítimos
    # Solo penalizamos los de evasión real
    effective_evasion = n_evasion
    # Nota: %27 (') y %22 (") SÍ se penalizan incluso en contraseñas
    # porque son los vectores de SQLi más comunes — ninguna app sana
    # permite comillas en contraseñas sin escapar en el servidor.

    # Ratio: qué fracción del encoding total es latino (señal de legitimidad)
    latin_ratio = n_latin / (total + 1)

    return {
        "count_all_encoded":       total,
        "count_latin_encoding":    n_latin,
        "count_evasion_encoding":  effective_evasion,
        "count_cred_sym_encoding": n_cred,
        "latin_encoding_ratio":    round(latin_ratio, 4),
        "has_evasion_encoding":    int(effective_evasion > 0),
        "in_credential_field":     int(in_cred_field),
        # Densidad de evasión respecto al tamaño total — reemplaza encoding_density
        "evasion_encoding_density": round(
            effective_evasion / (len(raw) + 1), 6
        ),
        # has_url_encoding solo True si hay encoding de evasión real
        # (no latino, no credencial en campo de auth)
        "has_url_encoding": int(
            effective_evasion > 0
            or (n_cred > 0 and not in_cred_field)
        ),
        # Double encoding siempre es sospechoso, sin excepciones
        "has_double_encoding": int(
            bool(re.search(r"%25[0-9a-fA-F]{2}", raw, re.IGNORECASE))
        ),
    }


# ==========================================================
# ENTROPÍA
# ==========================================================

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ==========================================================
# FEATURE EXTRACTION
# ==========================================================

def extract_features(
    method: str,
    url: str,
    payload: str = "",
    include_extras: bool = True,
) -> dict:

    raw           = f"{url} {payload}"
    decoded_once  = unquote(raw)
    decoded_twice = unquote(decoded_once)
    combined      = decoded_twice.lower()

    path_only  = url.split("?")[0]
    query_part = url.split("?")[1] if "?" in url else ""

    f = {
        "method":        method.upper(),
        "url_path_len":  len(path_only),
        "url_path_depth": len([x for x in path_only.split("/") if x]),
        "has_suspicious_path_keyword": int(bool(re.search(
            r"(?i)(admin|wp-|login|api/v[0-9]|backup|config|db|shell|phpmyadmin)",
            path_only,
        ))),
    }

    # ── Familias de ataque ────────────────────────────────────────
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, combined)
        f[f"has_{name}"]   = int(len(matches) > 0)
        f[f"count_{name}"] = len(matches)

    # ── Clasificación de encoding (v1.3) ─────────────────────────
    enc = classify_encoding(raw, payload, url)
    f.update(enc)

    # Mantener alias para compatibilidad con modelos anteriores
    f["count_special_encoded"] = enc["count_all_encoded"]
    f["encoding_density"]      = enc["evasion_encoding_density"]

    # ── Features de comilla simple contextual (v2.0) ──────────────
    # Apóstrofe entre letras → nombre propio (D'Onofrio, O'Brien)
    # No debe activar has_single_quote — es tráfico legítimo.
    # Comilla sola o al borde de palabra → sospechosa (admin' OR 1=1)
    _quote_in_word = bool(re.search(r"(?i)[a-z]'[a-z]", combined))
    _quote_not_in_word = bool(re.search(r"(?<![a-z])'|'(?![a-z])", combined.lower()))

    f["has_single_quote"]     = int(_quote_not_in_word or "%27" in raw.lower())
    f["single_quote_count"]   = combined.count("'") + raw.lower().count("%27")
    f["single_quote_in_word"] = int(_quote_in_word)
    f["has_comment_sql"]   = int(bool(re.search(r"--|/\*|#", combined)))
    f["payload_len"]       = len(payload)
    f["payload_to_url_ratio"] = len(payload) / (len(raw) + 1)

    # Tautología
    f["has_tautology"] = int(bool(re.search(
        r"(?i)(?:\bor\b|\band\b)\s*\(?\s*"
        r"['\"]?[a-zA-Z0-9_]{1,20}['\"]?\s*=\s*"
        r"['\"]?[a-zA-Z0-9_]{1,20}['\"]?\s*\)?",
        combined,
    )))

    f["has_timebased_sql"] = int(bool(re.search(
        r"(?i)(waitfor[\s\+]+delay|sleep\s*\(\d+\)|benchmark\s*\()",
        combined,
    )))

    # Inyección detectada en el PAYLOAD
    f["payload_has_injection"] = int(
        any(f.get(f"has_{k}", 0) for k in PATTERNS)
        or f["has_tautology"]
        or f["has_timebased_sql"]
        or (f["has_single_quote"] and len(payload) > 5)
    )

    # ── Features de interacción ───────────────────────────────────
    f["deep_path_with_encoding"] = int(
        f["url_path_depth"] >= 3 and f["has_url_encoding"] == 1
    )
    f["post_with_payload"] = int(
        method.upper() == "POST" and len(payload) > 20
    )
    # sql_with_encoding: solo penaliza si el encoding es de evasión real
    f["sql_with_encoding"] = int(
        f["has_sql"] == 1 and f["has_evasion_encoding"] == 1
    )
    f["get_with_long_query"] = int(
        method.upper() == "GET" and len(query_part) > 100
    )

    # ── Lucz, WordPress ──────────────────────────────────────────
    lucz_segments = re.findall(r"/d_[0-9a-f]{8}", url.lower())
    f["has_lucz_obfuscation"] = int(len(lucz_segments) > 0)
    f["count_lucz_segments"]  = len(lucz_segments)

    f["has_xmlrpc"]  = int("xmlrpc.php" in url.lower())
    f["has_wp_admin"] = int(bool(re.search(
        r"(?i)(wp-login|wp-admin|wp-json)", url
    )))

    f["has_header_injection"] = int(bool(re.search(
        r"(?i)(set-cookie|x-forwarded-for|content-type|location:)", combined
    )))

    # ── Feature agregada ─────────────────────────────────────────
    f["has_any_injection"] = int(
        f["payload_has_injection"] == 1
        or f["has_lucz_obfuscation"] == 1
        or f["has_xmlrpc"] == 1
    )

    # ── Extras ───────────────────────────────────────────────────
    if include_extras:
        f.update({
            "url_query_len":      len(query_part),
            "payload_entropy":    shannon_entropy(payload),
            "has_double_dash":    int("--" in combined),
            "has_backtick":       int("`" in combined),
            "has_semicolon":      int(";" in combined),
            "has_union_select":   int(bool(re.search(r"(?i)union.*select", combined))),
            "count_digits":       len(re.findall(r"\d", combined)),
            "count_special_chars": len(re.findall(r"[^\w\s]", combined)),
        })

    return f


def extract_features_df(
    method: str,
    url: str,
    payload: str = "",
    include_extras: bool = True,
) -> "pd.DataFrame":
    """Wrapper que retorna DataFrame. Útil para app.py (inferencia)."""
    import pandas as pd
    return pd.DataFrame([extract_features(method, url, payload, include_extras)])