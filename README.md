# WAF-ML: Web Application Firewall Basado en Machine Learning

**WAF-ML** es una solución de seguridad perimetral diseñada para proteger aplicaciones web de PYMES mediante un ensamble híbrido de modelos de Inteligencia Artificial (LightGBM + MLP). El sistema actúa como un proxy inverso inteligente que intercepta, analiza y clasifica el tráfico en tiempo real para mitigar ataques de Inyección SQL (SQLi) y Cross-Site Scripting (XSS).

> ⚠️ **Repo público.** Este README no contiene credenciales, tokens, ni rutas internas. Los datos sensibles (contraseñas de DB, claves VPN) se generan automáticamente en el primer arranque y quedan protegidos por `.gitignore`. Revisa `.env.example` si existe o genera tu propio `.env` con `instalar_waf.sh`.

## Características Principales

- **Cerebro Híbrido**: Detección avanzada utilizando un ensamble de redes neuronales y árboles de decisión.
- **Proxy Reverso con TLS**: Terminación SSL/TLS con certificados autofirmados generados automáticamente (modo dev, zero-touch).
- **Instalación Automatizada**: Scripts listos para desplegar en entornos Linux (Bash) y Windows (PowerShell).
- **Modo Resiliente**: Capacidad de operar en modo local si la base de datos de telemetría no está disponible.
- **VPN Integrada**: Capa adicional de seguridad mediante WireGuard para acceso administrativo seguro.

---

## Requisitos del Sistema

- **Docker** (con soporte para Docker Compose v2).
- **Git** para clonar el repositorio.
- Puertos **80** (HTTP), **443** (HTTPS), y **51820** (VPN UDP) disponibles.

---

## Instalación y Despliegue

### 1. Clonar el Repositorio

```bash
git clone https://github.com/Ed-Ponk/WAF-ML-Project.git
cd WAF-ML-Project
```

### 2. Ejecutar el Instalador

El instalador configura automáticamente las redes de Docker, genera credenciales seguras para la base de datos, crea la estructura de directorios necesaria y levanta el stack completo.

**Linux / WSL2:**

```bash
chmod +x instalar_waf.sh
./instalar_waf.sh --port 80
```

**Windows (PowerShell):**

```powershell
.\instalar_waf.ps1 -Port 80
```

> El flag `--port` / `-Port` es opcional. Por defecto usa el puerto 80.

### 3. Acceder al WAF

| Protocolo | URL                              | Descripción                       |
|-----------|----------------------------------|-----------------------------------|
| HTTP      | `http://localhost:80`            | Acceso sin cifrar (modo dev)      |
| HTTPS     | `https://localhost:443`          | Acceso con TLS autofirmado        |

En modo desarrollo, los certificados TLS se generan automáticamente al arrancar el contenedor de Nginx. No se requiere intervención manual. Usa `curl -k` o acepta la advertencia del navegador para probar HTTPS.

---

## Arquitectura de Red

El proyecto segmenta sus componentes en redes Docker aisladas para minimizar la superficie de ataque:

```
                      ┌──────────────────────────────────┐
                      │        Cliente (Browser/API)      │
                      └────────────┬─────────────────────┘
                                   │
                          HTTP :80 / HTTPS :443
                                   │
                       ┌────────────▼─────────────────────┐
                       │    Capa 1: Nginx (Proxy Reverso)  │
                       │   • Terminación TLS (autofirmado) │
                       │   • proxy_pass a WAF Engine       │
                       │     (decide BLOCK o proxy al      │
                       │      backend con body completo)   │
                       └────────────┬─────────────────────┘
                                   │
                    ┌──────────────┼──────────────────┐
                    │              │                   │
          waf-frontend     waf-backend       pyme-security-net
                    │              │                   │
         ┌─────────▼──────┐ ┌─────▼────────┐  ┌───────▼────────┐
         │ PYME React     │ │ ML Engine    │  │ PYME PHP       │
         │ (Frontend SPA) │ │ (FastAPI)    │  │ (Backend API)  │
         └────────────────┘ └──────┬───────┘  └────────────────┘
                                   │
                          ┌───────▼───────┐
                          │ PostgreSQL 15 │
                          │ (Telemetría)  │
                          └───────────────┘
```

### Redes

1. **`waf-frontend`**: Red expuesta que recibe el tráfico del cliente a través de Nginx.
2. **`waf-backend`**: Red privada donde Nginx se comunica con el Motor de ML, quien decide si permite (proxy al backend) o bloquea (403).
3. **`pyme-security-net`**: Red aislada para el backend de la aplicación PYME y sus dependencias.
3. **`pyme-security-net`**: Red aislada para los servicios PYME (React + PHP), invisibles desde el host.

---

## TLS/SSL en Modo Desarrollo

El entrypoint del contenedor Nginx (`generate_certs.sh`) implementa un pipeline zero-touch:

1. Verifica si existen `/etc/nginx/certs/waf.{crt,key}` (montados desde `./certs/` en el host).
2. Si no existen, ejecuta OpenSSL en modo no interactivo (`-subj`) para generar un certificado autofirmado RSA 2048, válido por 365 días.
3. Si OpenSSL falla, registra el error y permite la degradación segura: el contenedor se reinicia e intenta de nuevo. Mientras tanto, el puerto 80 sigue operativo.

```bash
# Forzar regeneración de certificados (borrarlos y reiniciar):
rm -rf certs/
docker compose up -d --build proxy
```

> Los certificados generados están ignorados por `.gitignore`. No se suben al repositorio.

---

## Variables de Entorno

El archivo `.env` se genera automáticamente con `instalar_waf.sh`. Nunca se versiona (está en `.gitignore`).

| Variable           | Descripción                                    | Default (generado)       |
|--------------------|------------------------------------------------|--------------------------|
| `WAF_PORT`         | Puerto HTTP de entrada                         | `80`                     |
| `WAF_ENV`          | Entorno de ejecución (`development`/`production`) | `development`          |
| `DB_USER`          | Usuario de PostgreSQL                          | `waf_user`               |
| `DB_PASSWORD`      | Contraseña de PostgreSQL (generada aleatoriamente) | —                    |
| `DB_NAME`          | Nombre de la base de datos                     | `waf_db`                 |
| `ML_ENGINE_PORT`   | Puerto interno del motor ML                    | `8000`                   |
| `THRESHOLD_BLOCK`  | Probabilidad mínima para bloquear una request  | `0.70`                   |
| `THRESHOLD_LOG`    | Probabilidad mínima para registrar alerta      | `0.30`                   |
| `WAF_DEBUG`        | Modo debug del motor ML                        | `false`                  |

Para personalizar, edita `.env` antes de ejecutar `docker compose up`, o usa `instalar_waf.sh` que lo regenera.

---

## Comandos de Monitoreo

```bash
# Logs en tiempo real
docker compose logs -f

# Ver matriz de confusión (auditoría)
docker compose exec database psql -U "${DB_USER}" -d "${DB_NAME}" -c 'SELECT * FROM vw_confusion_matrix;'
```

> El comando `psql` usa las variables de tu `.env`. Las credenciales reales se generan en el primer arranque y no están hardcodeadas en el código fuente.

---

## Consideraciones de Seguridad (Repo Público)

- **`.env`** está en `.gitignore` — las credenciales de DB, VPN y configuración sensible nunca se versionan.
- **`certs/`** está en `.gitignore` — los certificados TLS autofirmados son locales a cada despliegue.
- **`config/vpn/`** está en `.gitignore` — las claves de WireGuard se generan en el primer arranque.
- Los puertos y nombres de servicio en `docker-compose.yml` son referenciales; los valores reales (contraseñas, tokens) se inyectan vía variables de entorno.
- Si clonas este repo, ejecuta `instalar_waf.sh` para generar tu propia configuración segura. **No uses el `.env` de otro entorno.**

---

## Stack Tecnológico

| Capa        | Tecnología                          |
|-------------|-------------------------------------|
| Proxy       | Nginx (Alpine) con TLS termination  |
| ML Engine   | FastAPI + LightGBM + MLP (PyTorch)  |
| Base datos  | PostgreSQL 15                       |
| VPN         | WireGuard                           |
| Frontend    | React (Vite) + TypeScript           |
| Backend     | PHP (simulado para pruebas)         |

---

**Autor:** Edu Fernandez Alva
**Institución:** Universidad Católica Santo Toribio de Mogrovejo — USAT 2026
