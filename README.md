# 🛡️ WAF-ML: Web Application Firewall Basado en Machine Learning

**WAF-ML** es una solución de seguridad perimetral diseñada para proteger aplicaciones web de PYMES (como el sistema ATEL) mediante un ensamble híbrido de modelos de Inteligencia Artificial (LightGBM + MLP). El sistema actúa como un proxy inverso inteligente que intercepta, analiza y clasifica el tráfico en tiempo real para mitigar ataques de Inyección SQL (SQLi) y Cross-Site Scripting (XSS).

## 🚀 Características Principales

* **Cerebro Híbrido**: Detección avanzada utilizando un ensamble de redes neuronales y árboles de decisión.
* **Instalación Automatizada**: Scripts listos para desplegar en entornos Linux (Bash) y Windows (PowerShell).
* **Modo Resiliente**: Capacidad de operar en modo "Local" si la base de datos de telemetría no está disponible, garantizando disponibilidad.
* **VPN Integrada**: Capa adicional de seguridad mediante WireGuard para acceso administrativo seguro.

---

## 🛠️ Requisitos del Sistema

Antes de comenzar, asegúrate de tener instalado:

* **Docker Desktop** (con soporte para WSL2 en Windows).
* **Git** para la clonación del repositorio.
* Puerto **80** (HTTP) y **51820** (VPN UDP) disponibles.

---

## 📥 Instalación y Despliegue

### 1. Clonar el Repositorio

```bash
git clone https://github.com/Ed-Ponk/WAF-ML-Project.git
cd WAF-ML-Project

```

### 2. Ejecutar el Instalador

El instalador configurará automáticamente las redes de Docker, generará credenciales seguras y vinculará tu aplicación existente.

**En Linux / WSL2:**

```bash
chmod +x instalar_waf.sh
./instalar_waf.sh --backend http://localhost:8000

```

**En Windows (PowerShell):**

```powershell
.\instalar_waf.ps1 -Backend http://localhost:8000

```

---

## 📋 Arquitectura de Red

El proyecto utiliza una arquitectura de red segmentada para aislar componentes críticos:

1. **`waf-frontend`**: Red expuesta que recibe el tráfico del cliente a través del Proxy (Nginx).
2. **`waf-backend`**: Red privada donde el Proxy se comunica con el Motor de ML y la base de datos de logs.

---

## ⚠️ Consideraciones Importantes

* **Persistencia de Datos**: Los logs se almacenan en el volumen `waf_db_data`. No lo elimines si deseas mantener el histórico de ataques para auditoría.
* **Umbrales de Bloqueo**: Puedes ajustar la sensibilidad de la IA en el archivo `.env` generado:
* `THRESHOLD_BLOCK`: Probabilidad mínima para bloquear una petición (default: 0.70).
* `THRESHOLD_LOG`: Probabilidad mínima para registrar una alerta sin bloquear (default: 0.40).


* **Integración con ATEL**: Asegúrate de que tu aplicación backend esté en la misma red de Docker o sea accesible mediante la URL proporcionada durante la instalación.

---

## 📊 Comandos de Monitoreo

* **Ver logs en tiempo real**: `docker compose logs -f`
* **Ver matriz de confusión (Auditoría)**:
```bash
docker compose exec database psql -U waf_user -d waf_db -c 'SELECT * FROM vw_confusion_matrix;'

```



---

**Autor:** Edu Fernandez Alva
**Institución:** Universidad Católica Santo Toribio de Mogrovejo — USAT 2026