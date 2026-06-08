#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# WAF-ML — Script de Instalación para PYMES (Linux/Mac)
# Uso: ./instalar_waf.sh [--port <puerto>]
# ══════════════════════════════════════════════════════════════════

set -e

# ── Directorio raíz del proyecto (donde vive este script) ─────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colores ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Banner ────────────────────────────────────────────────────────
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     WAF-ML — Instalador para PYMES v1.0          ║"
echo "║     Universidad Católica Santo Toribio           ║"
echo "║     de Mogrovejo — USAT 2026                     ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Argumentos ───────────────────────────────────────────────────
WAF_PORT=80
DB_PASSWORD="waf_$(openssl rand -hex 8)"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port)    WAF_PORT="$2";    shift ;;
        --help)
            echo "Uso: ./instalar_waf.sh [--port <puerto>]"
            echo ""
            echo "Opciones:"
            echo "  --port     Puerto del WAF (default: 80)"
            echo ""
            echo "Ejemplos:"
            echo "  ./instalar_waf.sh"
            echo "  ./instalar_waf.sh --port 8888"
            exit 0
            ;;
        *) echo -e "${RED}❌ Argumento desconocido: $1${NC}"; exit 1 ;;
    esac
    shift
done

# ── Validaciones ──────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Verificando requisitos...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker no está instalado${NC}"
    echo "   Instala Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose no está instalado${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker disponible: $(docker --version)${NC}"

# ── Verificar que los proyectos PYME existen ─────────────────────
echo -e "${YELLOW}[2/5] Verificando proyectos PYME...${NC}"

PYME_FRONTEND_DIR="$SCRIPT_DIR/../../thesis/app-pyme/atel-front"
PYME_BACKEND_DIR="$SCRIPT_DIR/../../thesis/app-pyme/atel-back"

if [ ! -d "$PYME_FRONTEND_DIR" ] || [ ! -f "$PYME_FRONTEND_DIR/Dockerfile" ]; then
    echo -e "${YELLOW}⚠️  Frontend PYME no encontrado en: $PYME_FRONTEND_DIR${NC}"
    echo "   El WAF arrancará sin el frontend. Verifica la ruta del proyecto."
    echo "   Ruta esperada (relativa): ../../thesis/app-pyme/atel-front"
fi

if [ ! -d "$PYME_BACKEND_DIR" ] || [ ! -f "$PYME_BACKEND_DIR/Dockerfile" ]; then
    echo -e "${YELLOW}⚠️  Backend PYME no encontrado en: $PYME_BACKEND_DIR${NC}"
    echo "   El WAF arrancará sin el backend. Verifica la ruta del proyecto."
    echo "   Ruta esperada (relativa): ../../thesis/app-pyme/atel-back"
fi

echo -e "${GREEN}✅ Proyectos PYME verificados${NC}"

# ── Generar .env junto al docker-compose.yml ──────────────────────
echo -e "${YELLOW}[3/5] Generando configuración...${NC}"

cat > "$SCRIPT_DIR/.env" << EOF
# WAF-ML — Configuración generada automáticamente
# Generado: $(date)

WAF_PORT=${WAF_PORT}

DB_USER=waf_user
DB_PASSWORD=${DB_PASSWORD}
DB_NAME=waf_db
DB_PORT=5432

ML_ENGINE_PORT=8000
ML_MEMORY_LIMIT=800M

THRESHOLD_BLOCK=0.70
THRESHOLD_LOG=0.40

VITE_LINK_BACKEND=/api/v1

TZ=America/Lima
WAF_DEBUG=false
EOF

# Verificar que el .env se creó correctamente antes de continuar
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo -e "${RED}❌ Error: no se pudo crear el archivo .env en $SCRIPT_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Archivo .env generado en: $SCRIPT_DIR/.env${NC}"

# ── Crear directorios necesarios ──────────────────────────────────
echo -e "${YELLOW}[4/5] Preparando estructura de archivos...${NC}"
mkdir -p "$SCRIPT_DIR/config/vpn"
echo -e "${GREEN}✅ Directorios creados${NC}"

# ── Levantar contenedores desde el directorio correcto ────────────
echo -e "${YELLOW}[5/5] Iniciando WAF-ML...${NC}"
cd "$SCRIPT_DIR"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

# ── Esperar que esté listo ────────────────────────────────────────
echo -e "${YELLOW}   Esperando que el sistema esté listo...${NC}"
MAX_WAIT=60
WAITED=0

while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -s "http://localhost:${WAF_PORT}" > /dev/null 2>&1; then
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    echo "   Esperando... (${WAITED}s/${MAX_WAIT}s)"
done

# ── Resultado final ───────────────────────────────────────────────
echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║         ✅ WAF-ML instalado correctamente        ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  🌐 WAF activo en    : ${GREEN}http://localhost:${WAF_PORT}${NC}"
echo -e "  🖥️  Frontend servido desde: ${GREEN}http://localhost:${WAF_PORT}${NC}"
echo -e "  🔒 API protegida por WAF-ML ${GREEN}(LightGBM + MLP)${NC}"
echo -e "  📊 Base de datos    : ${GREEN}PostgreSQL (waf_db)${NC}"
echo ""
echo -e "  ${YELLOW}Comandos útiles:${NC}"
echo -e "  Ver logs    : docker compose logs -f"
echo -e "  Detener WAF : docker compose down"
echo -e "  Ver eventos : docker compose exec database psql -U waf_user -d waf_db -c 'SELECT * FROM vw_confusion_matrix;'"
echo ""
