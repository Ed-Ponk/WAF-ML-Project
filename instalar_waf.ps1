# ══════════════════════════════════════════════════════════════════
# WAF-ML — Script de Instalación para PYMES (Windows PowerShell)
# Uso: .\instalar_waf.ps1 -Backend http://mi-servidor:3000
# ══════════════════════════════════════════════════════════════════

param(
    [Parameter(Mandatory=$false)]
    [string]$Backend = "",

    [Parameter(Mandatory=$false)]
    [int]$Port = 80,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# ── Colores ───────────────────────────────────────────────────────
function Write-Color($Text, $Color = "White") {
    Write-Host $Text -ForegroundColor $Color
}

# ── Banner ────────────────────────────────────────────────────────
Write-Color ""
Write-Color "╔══════════════════════════════════════════════════╗" "Cyan"
Write-Color "║     WAF-ML — Instalador para PYMES v1.0         ║" "Cyan"
Write-Color "║     Universidad Católica Santo Toribio           ║" "Cyan"
Write-Color "║     de Mogrovejo — USAT 2026                     ║" "Cyan"
Write-Color "╚══════════════════════════════════════════════════╝" "Cyan"
Write-Color ""

# ── Ayuda ─────────────────────────────────────────────────────────
if ($Help) {
    Write-Color "Uso: .\instalar_waf.ps1 -Backend <URL> [-Port <puerto>]" "Yellow"
    Write-Color ""
    Write-Color "Opciones:"
    Write-Color "  -Backend   URL de tu servidor/aplicación (requerido)"
    Write-Color "  -Port      Puerto del WAF (default: 80)"
    Write-Color ""
    Write-Color "Ejemplos:"
    Write-Color "  .\instalar_waf.ps1 -Backend http://localhost:8080"
    Write-Color "  .\instalar_waf.ps1 -Backend http://192.168.1.5:3000 -Port 8888"
    exit 0
}

# ── Validaciones ──────────────────────────────────────────────────
Write-Color "[1/6] Verificando requisitos..." "Yellow"

if ([string]::IsNullOrEmpty($Backend)) {
    Write-Color "❌ Error: -Backend es requerido" "Red"
    Write-Color "   Ejemplo: .\instalar_waf.ps1 -Backend http://localhost:8080" "Red"
    exit 1
}

try {
    $dockerVersion = docker --version 2>&1
    Write-Color "✅ Docker disponible: $dockerVersion" "Green"
} catch {
    Write-Color "❌ Docker no está instalado o no está corriendo" "Red"
    Write-Color "   Instala Docker Desktop: https://www.docker.com/products/docker-desktop/" "Red"
    exit 1
}

# ── Verificar backend ─────────────────────────────────────────────
Write-Color "[2/6] Verificando conexión al backend..." "Yellow"
try {
    $response = Invoke-WebRequest -Uri $Backend -TimeoutSec 5 -ErrorAction Stop
    Write-Color "✅ Backend accesible: $Backend" "Green"
} catch {
    Write-Color "⚠️  Backend no responde en $Backend" "Yellow"
    Write-Color "   El WAF se instalará de todas formas." "Yellow"
}

# ── Generar contraseña segura ─────────────────────────────────────
$DbPassword = "waf_" + [System.Web.Security.Membership]::GeneratePassword(12, 2)
if (-not $DbPassword) {
    $DbPassword = "waf_" + (Get-Random -Maximum 99999999)
}

# ── Generar .env ─────────────────────────────────────────────────
Write-Color "[3/6] Generando configuración..." "Yellow"

$envContent = @"
# WAF-ML — Configuración generada automáticamente
# Generado: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

PYME_BACKEND_URL=$Backend
WAF_PORT=$Port

DB_USER=waf_user
DB_PASSWORD=$DbPassword
DB_NAME=waf_db
DB_PORT=5432

ML_ENGINE_PORT=8000
ML_MEMORY_LIMIT=800M

THRESHOLD_BLOCK=0.70
THRESHOLD_LOG=0.40

TZ=America/Lima
WAF_DEBUG=false
"@

$envContent | Out-File -FilePath ".env" -Encoding UTF8
Write-Color "✅ Archivo .env generado" "Green"

# ── Crear directorios ─────────────────────────────────────────────
Write-Color "[4/6] Preparando estructura de archivos..." "Yellow"
New-Item -ItemType Directory -Force -Path "config\vpn" | Out-Null
Write-Color "✅ Directorios creados" "Green"

# ── Levantar contenedores ─────────────────────────────────────────
Write-Color "[5/6] Iniciando WAF-ML..." "Yellow"
docker compose down --remove-orphans 2>$null
docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    Write-Color "❌ Error al iniciar los contenedores" "Red"
    Write-Color "   Revisa los logs: docker compose logs" "Red"
    exit 1
}

# ── Esperar que esté listo ────────────────────────────────────────
Write-Color "[6/6] Esperando que el sistema esté listo..." "Yellow"
$maxWait = 60
$waited  = 0

while ($waited -lt $maxWait) {
    try {
        $test = Invoke-WebRequest -Uri "http://localhost:$Port" -TimeoutSec 3 -ErrorAction Stop
        break
    } catch {
        Start-Sleep -Seconds 3
        $waited += 3
        Write-Host "   Esperando... ($waited s / $maxWait s)"
    }
}

# ── Resultado final ───────────────────────────────────────────────
Write-Color ""
Write-Color "╔══════════════════════════════════════════════════╗" "Green"
Write-Color "║         ✅ WAF-ML instalado correctamente        ║" "Green"
Write-Color "╚══════════════════════════════════════════════════╝" "Green"
Write-Color ""
Write-Color "  🌐 WAF activo en    : http://localhost:$Port" "Cyan"
Write-Color "  🔒 Backend protegido: $Backend" "Cyan"
Write-Color "  📊 Base de datos    : PostgreSQL (waf_db)" "Cyan"
Write-Color ""
Write-Color "  Comandos útiles:" "Yellow"
Write-Color "  Ver logs    : docker compose logs -f"
Write-Color "  Detener WAF : docker compose down"
Write-Color "  Ver eventos : docker compose exec database psql -U waf_user -d waf_db -c 'SELECT * FROM vw_confusion_matrix;'"
Write-Color ""
