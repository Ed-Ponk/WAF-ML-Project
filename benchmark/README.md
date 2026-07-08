# 🔬 WAF Benchmark Suite — Evaluación Comparativa

Benchmark para tesis: **"Web Application Firewall open source basado en machine learning para la detección de ataques de inyección OWASP A05:2025 en entornos PYMES simulados"**

**Autor:** Fernandez Alva, E. — USAT, Perú 2026

## 📋 WAFs evaluados

| WAF | Puerto | Descripción |
|-----|--------|-------------|
| [WAF-ML](http://localhost:80) | `:80` | Propio — Ensemble LGBM+MLP (ya corriendo) |
| [ModSecurity + CRS](http://localhost:8081) | `:8081` | OWASP CRS Paranoia Level 1 |
| [Coraza + Caddy](http://localhost:8082) | `:8082` | Coraza WAF con OWASP CRS |
| [NAXSI](http://localhost:8083) | `:8083` | nginx + NAXSI module |

## 📊 Casos de prueba

- **20 ataques** OWASP A05:2025 (SQLi, XSS, CMD, Path Traversal, CRLF)
- **10 tráfico legítimo** (incluyendo casos con caracteres especiales, JSON, Chrome UA)
- **Total: 30 casos × 4 WAFs = 120 pruebas**

Métricas calculadas: Accuracy, Precision, Recall, F1-Score, FPR, latencia promedio y P95.

## 🚀 Instrucciones de ejecución (Windows PowerShell)

### Prerrequisitos

- Docker Desktop para Windows corriendo
- WAF-ML funcionando (puerto 80): `docker compose -f docker-compose.yml up -d`
- Python 3.10+ con `requests` instalado

```powershell
# Instalar dependencia del script
pip install requests
```

### Paso 1: Crear red compartida (solo la primera vez)

```powershell
docker network create waf-benchmark-net
```

### Paso 2: Construir y levantar WAFs de comparación

```powershell
# Desde la raíz del proyecto (D:\WAF\)
cd D:\WAF

# Construir NAXSI (toma ~3-5 min la primera vez)
docker compose -f benchmark/docker-compose.benchmark.yml build

# Levantar todos los servicios
docker compose -f benchmark/docker-compose.benchmark.yml up -d
```

### Paso 3: Verificar que todos los WAFs respondan

```powershell
# Verificar cada WAF
curl -s -o nul -w "WAF-ML: %{http_code}\n" http://localhost:80/health
curl -s -o nul -w "ModSecurity: %{http_code}\n" http://localhost:8081/health
curl -s -o nul -w "Coraza: %{http_code}\n" http://localhost:8082/health
curl -s -o nul -w "NAXSI: %{http_code}\n" http://localhost:8083/health
```

### Paso 4: Ejecutar el benchmark

```powershell
cd D:\WAF\benchmark
python benchmark_waf.py
```

> ⏱️ El benchmark completo toma aproximadamente **3-5 minutos** (30 casos × 4 WAFs).

### Paso 5: Revisar resultados

```powershell
# Los resultados se guardan en:
ls D:\WAF\benchmark\results\
```

### Paso 6: Limpiar (al finalizar)

```powershell
docker compose -f benchmark/docker-compose.benchmark.yml down
```

## 📁 Estructura de archivos

```
benchmark/
├── docker-compose.benchmark.yml   # Orquestación de WAFs
├── benchmark_waf.py               # Script principal del benchmark
├── dummy_backend.conf             # Config del backend dummy
├── README.md                      # Este archivo
│
├── coraza/
│   └── Caddyfile                  # Config Coraza + CRS
│
├── naxsi/
│   ├── Dockerfile                 # Build NAXSI sobre nginx:alpine
│   ├── nginx.conf                 # Config nginx + NAXSI
│   └── naxsi.rules                # Reglas de detección NAXSI
│
└── results/                       # Resultados generados aquí
    ├── resultados_detalle_*.csv   # Resultado por prueba individual
    ├── resumen_wafs_*.csv         # Métricas resumidas por WAF
    └── reporte_completo_*.json    # Reporte completo (para tesis)
```

## 📐 Hipótesis a verificar

> **H1:** El WAF-ML propuesto reduce la tasa de falsos positivos en al menos un 30% respecto a ModSecurity con OWASP CRS.

> **H2:** El WAF-ML mantiene un overhead de latencia promedio inferior a 50ms.

El script evalúa ambas hipótesis automáticamente al finalizar.

## ⚠️ Notas importantes

### NAXSI
NAXSI no tiene imagen Docker oficial mantenida. Este benchmark incluye un `Dockerfile` que compila `nginx` + `naxsi module` desde fuente. La primera construcción toma ~3-5 minutos.

### WAF-ML
El WAF-ML propio (puerto 80) debe estar corriendo desde el `docker-compose.yml` principal del proyecto. El benchmark no lo levanta automáticamente.

### ModSecurity + CRS
Usa la imagen oficial `owasp/modsecurity-crs:nginx-alpine` con Paranoia Level 1 (balance entre detección y falsos positivos).

### Coraza
Usa la imagen oficial `ghcr.io/corazawaf/coraza-caddy:latest` con OWASP CRS embebido.

## 📄 Formato de salida JSON

El JSON generado incluye:
- Metadatos del benchmark (fecha, autor, universidad)
- Resultados detallados por WAF y por caso
- Métricas calculadas (TP, TN, FP, FN, Accuracy, Precision, Recall, F1, FPR, latencias)
- Ready para importar en LaTeX, Overleaf o herramientas de análisis
