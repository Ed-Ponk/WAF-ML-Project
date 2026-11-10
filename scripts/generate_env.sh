#!/usr/bin/env bash
# Genera un .env LOCAL a partir de .env.example con secretos nuevos.
# Uso: ./scripts/generate_env.sh [--force] [--apps-dir RUTA]
#   --apps-dir RUTA  carpeta que contiene atel-front, atel-back y projecto_landing
#                    (también se puede pasar con la variable ATEL_UPLOAD_DIR)
set -euo pipefail

cd "$(dirname "$0")/.."
EXAMPLE=".env.example"
TARGET=".env"
APP_FOLDERS=(atel-front atel-back projecto_landing)

FORCE=0
APPS_DIR="${ATEL_UPLOAD_DIR:-}"
while [ $# -gt 0 ]; do
  case "$1" in
  --force) FORCE=1 ;;
  --apps-dir)
    [ -n "${2:-}" ] || {
      echo "--apps-dir necesita una ruta"
      exit 1
    }
    APPS_DIR="$2"
    shift
    ;;
  -h | --help)
    sed -n '2,6p' "$0"
    exit 0
    ;;
  *)
    echo "Opción desconocida: $1"
    exit 1
    ;;
  esac
  shift
done

[ -f "$EXAMPLE" ] || {
  echo "No existe $EXAMPLE"
  exit 1
}
if [ -f "$TARGET" ] && [ "$FORCE" -ne 1 ]; then
  echo "$TARGET ya existe. Usa --force para sobrescribirlo."
  exit 1
fi
command -v openssl >/dev/null || {
  echo "Falta openssl"
  exit 1
}

# ── Localizar la carpeta de las apps cliente ─────────────────────
# valid_apps_dir RUTA: true si contiene las tres carpetas.
valid_apps_dir() {
  local d
  for d in "${APP_FOLDERS[@]}"; do
    [ -d "$1/$d" ] || return 1
  done
}
# abs_path RUTA: expande ~ y devuelve la ruta absoluta (vacío si no existe).
abs_path() {
  local p="${1/#\~/$HOME}"
  (cd "$p" 2>/dev/null && pwd) || true
}

RESOLVED=""
if [ -n "$APPS_DIR" ]; then
  cand="$(abs_path "$APPS_DIR")"
  if [ -n "$cand" ] && valid_apps_dir "$cand"; then
    RESOLVED="$cand"
  else
    echo "⚠ '$APPS_DIR' no existe o no contiene: ${APP_FOLDERS[*]}"
  fi
fi

if [ -z "$RESOLVED" ]; then
  for c in ../atel-upload ../app-pyme ../../atel-upload "$HOME/projects/atel-upload" "$HOME/projects/app-pyme" "$HOME/atel-upload"; do
    cand="$(abs_path "$c")"
    if [ -n "$cand" ] && valid_apps_dir "$cand"; then
      RESOLVED="$cand"
      echo "✔ Apps encontradas en: $RESOLVED"
      break
    fi
  done
fi

if [ -z "$RESOLVED" ] && [ -t 0 ]; then
  echo "No encontré la carpeta con: ${APP_FOLDERS[*]}"
  while [ -z "$RESOLVED" ]; do
    read -r -p "Ruta de esa carpeta (vacío para omitir): " input
    [ -z "$input" ] && break
    cand="$(abs_path "$input")"
    if [ -n "$cand" ] && valid_apps_dir "$cand"; then
      RESOLVED="$cand"
    else
      echo "  ✗ No existe o le faltan carpetas. Prueba otra ruta."
    fi
  done
fi

cp "$EXAMPLE" "$TARGET"
chmod 600 "$TARGET"

# set_var KEY VALUE: reemplaza la línea KEY= o la añade al final.
# Usa ENVIRON para que / + \ del valor no rompan nada.
set_var() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  if grep -q "^${key}=" "$TARGET"; then
    K="$key" V="$val" awk -F= '
      $1 == ENVIRON["K"] { print ENVIRON["K"] "=" ENVIRON["V"]; next } { print }
    ' "$TARGET" >"$tmp"
  else
    cat "$TARGET" >"$tmp"
    printf '%s=%s\n' "$key" "$val" >>"$tmp"
  fi
  mv "$tmp" "$TARGET"
  chmod 600 "$TARGET"
}

hex() { openssl rand -hex 32; }
pass() { openssl rand -hex 16; }

# ── Entorno local ────────────────────────────────────────────────
set_var WAF_ENV development
set_var COOKIE_SECURE false
set_var WAF_DOMAIN localhost
set_var PYME_DOMAIN pyme.waf.local
set_var ADMIN_DOMAIN admin.waf.local
set_var MADERERA_DOMAIN maderera.waf.local

# ── Secretos ─────────────────────────────────────────────────────
set_var JWT_SECRET "$(openssl rand -base64 48 | tr -d '\n')"
set_var MADERERA_AUTH_SECRET "$(hex)"
set_var DB_PASSWORD "$(pass)"
MYSQL_PASS="$(pass)"
set_var MYSQL_ROOT_PASSWORD "$MYSQL_PASS"
set_var DB_MYSQL_USERNAME root
set_var DB_MYSQL_PASSWORD "$MYSQL_PASS" # root usa la misma clave que MYSQL_ROOT_PASSWORD

# ── ML engine: incluir maderera en la allowlist ──────────────────
set_var BACKEND_ALLOWLIST "http://pyme-php-backend:80,http://maderera-app:3000"

# ── Laravel (APP_KEY + par de llaves Passport, 2048 bits para local) ─
set_var PYME_APP_KEY "base64:$(openssl rand -base64 32 | tr -d '\n')"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMPD/priv.pem" 2>/dev/null
openssl pkey -in "$TMPD/priv.pem" -pubout -out "$TMPD/pub.pem"
oneline() { awk 'BEGIN{ORS="\\n"}{print}' "$1"; }
set_var PYME_PASSPORT_PRIVATE_KEY "\"$(oneline "$TMPD/priv.pem")\""
set_var PYME_PASSPORT_PUBLIC_KEY "\"$(oneline "$TMPD/pub.pem")\""

# ── Contextos de build ───────────────────────────────────────────
if [ -n "$RESOLVED" ]; then
  set_var ATEL_UPLOAD_DIR "$RESOLVED"
else
  echo "⚠ ATEL_UPLOAD_DIR sin definir: el compose usará ../../atel-upload y el build fallará"
  echo "  si esa carpeta no existe. Reejecuta con: ./scripts/generate_env.sh --force --apps-dir RUTA"
fi

grep -qx '.env' .gitignore 2>/dev/null || echo '.env' >>.gitignore

echo "✔ .env generado (permisos 600)."
[ -n "$RESOLVED" ] && echo "  ATEL_UPLOAD_DIR=$RESOLVED"
echo "Añade a /etc/hosts:"
echo "  127.0.0.1 pyme.waf.local admin.waf.local maderera.waf.local"
