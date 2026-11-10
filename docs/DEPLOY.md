# Procedimiento de despliegue

Este documento describe el orden de despliegue en el VPS. No incluye secretos:
los valores reales viven únicamente en el `.env` del servidor.

## 1. Backup de la base de datos

Antes de tocar nada, generar un backup verificable de `waf_db`:

```bash
docker compose exec -T database sh -c \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > "waf_db_$(date +%Y%m%d_%H%M%S).dump"
```

Guardar el archivo fuera del directorio del proyecto y comprobar que no está vacío.

## 2. Revisar el `.env` del VPS

`WAF_ENV` debe definirse explícitamente en el `.env` del VPS. No depender del
default del proxy ni del default de ningún servicio:

```bash
grep -q '^WAF_ENV=production$' .env || echo 'WAF_ENV debe ser production'
for key in WAF_DOMAIN PYME_DOMAIN ADMIN_DOMAIN MADERERA_DOMAIN; do
  grep -q "^${key}=." .env || echo "Falta ${key}"
done
grep -q '^MADERERA_AUTH_SECRET=.' .env || echo 'Falta MADERERA_AUTH_SECRET'
```

Requisitos:

- `WAF_ENV` distinto de `development`.
- `WAF_DOMAIN`, `PYME_DOMAIN`, `ADMIN_DOMAIN` y `MADERERA_DOMAIN` definidos.
- `COOKIE_SECURE=true` si el panel se sirve por HTTPS.
- Certificados y rutas `CERT_PATH`/`KEY_PATH` revisados.

## 3. Preparar el SQL de dominios

Preparar el SQL antes de reiniciar servicios. Ajustar dominios y backends reales:

```sql
BEGIN;

UPDATE waf_apps
SET domain = 'pyme.example.com'
WHERE slug = 'default';

INSERT INTO waf_apps (slug, name, domain, backend_url)
VALUES ('maderera', 'Maderera', 'maderera.example.com', 'http://maderera-app:3000')
ON CONFLICT (slug) DO UPDATE
SET domain = EXCLUDED.domain,
    backend_url = EXCLUDED.backend_url;

INSERT INTO waf_app_domains (app_id, domain)
SELECT id, 'pyme.example.com' FROM waf_apps WHERE slug = 'default'
ON CONFLICT (domain) DO NOTHING;

INSERT INTO waf_app_domains (app_id, domain)
SELECT id, 'maderera.example.com' FROM waf_apps WHERE slug = 'maderera'
ON CONFLICT (domain) DO NOTHING;

COMMIT;
```

Los alias adicionales se agregan como filas extra en `waf_app_domains`.

## 4. Desplegar y aplicar el SQL

```bash
git pull --ff-only
docker compose up -d --build
docker compose exec -T database sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < dominios.sql
```

Aplicar el SQL inmediatamente después del `up`. Entre el arranque de los
servicios y la aplicación del SQL, `/api/` puede devolver `421` porque los
dominios todavía no están registrados en la base.

## 5. Refrescar la caché de aplicaciones

Reiniciar el motor o pedir una recarga explícita:

```bash
docker compose restart ml-engine
```

Alternativa, si el endpoint está disponible:

```bash
docker compose exec -T ml-engine \
  curl -fsS -X POST http://127.0.0.1:8000/reload_apps
```

## 6. Verificaciones

```bash
curl -fsS -o /dev/null -w '%{http_code}\n' https://pyme.example.com/
curl -fsS https://maderera.example.com/api/auth/providers
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: desconocido.example.com' https://127.0.0.1/
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  http://pyme.example.com/
```

Esperado:

- PYME responde `200`.
- Maderera responde JSON de `/api/auth/providers` con `200`.
- Un Host desconocido falla (`421` o conexión rechazada), nunca sirve otra app.
- HTTP redirige a HTTPS.
- El login del panel funciona en `/admin`.

## 7. Rollback

Si falla la verificación, restaurar el backup y volver a la versión anterior:

```bash
docker compose down
docker compose up -d database
docker compose exec -T database sh -c \
  'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  < waf_db_YYYYMMDD_HHMMSS.dump
git checkout <commit-anterior>
docker compose up -d --build
```

## Limitaciones y cuidados

- **Rotar `MADERERA_AUTH_SECRET`**: generar un valor nuevo con
  `openssl rand -hex 32`, actualizarlo en el `.env` del VPS y en la app
  maderera, y reiniciar ambos servicios. La rotación invalida las sesiones
  emitidas con el secreto anterior.
- **Backends HTTPS reales**: no registrar un backend HTTPS sin probar antes su
  cadena de certificados y su hostname. Verificar desde el contenedor del
  motor con `openssl s_client` o `curl`; una CA desconocida o un hostname
  incorrecto deben fallar, no ignorarse.
- **Dominios nuevos**: el panel solo registra la app en el WAF. Un dominio
  nuevo también requiere su `server` block en Nginx y su certificado TLS. Sin
  ambos, el tráfico no llega al WAF.
- **`WAF_ENV` y TLS del proxy**: el proxy no usa `WAF_ENV` para decidir el tipo
  de certificado. Si faltan `CERT_PATH`/`KEY_PATH`, genera un autofirmado; para
  producción se deben montar certificados válidos o usar el sidecar certbot con
  `ACME_PRIMARY_DOMAIN`. Definir `WAF_ENV` explícitamente evita depender de
  defaults ambiguos.
