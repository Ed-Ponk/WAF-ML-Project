-- Migración 001: Multi-app support (fase 1) - waf_apps + waf_events.app_id
BEGIN;

-- 1) Crear tabla waf_apps
CREATE TABLE IF NOT EXISTS waf_apps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug VARCHAR(63) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  domain VARCHAR(253) NOT NULL UNIQUE,
  backend_url TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT waf_apps_slug_check CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  CONSTRAINT waf_apps_domain_check CHECK (domain = lower(domain)),
  CONSTRAINT waf_apps_backend_url_check CHECK (backend_url ~ '^https?://')
);

-- 2) Seed app por defecto
INSERT INTO waf_apps (slug, name, domain, backend_url, enabled)
VALUES ('default', 'PYME Atel (atel-back)', 'pyme.waf.local', 'http://pyme-php-backend:80', TRUE)
ON CONFLICT (slug) DO NOTHING;

-- 3) Agregar app_id a waf_events (nullable primero)
ALTER TABLE waf_events ADD COLUMN IF NOT EXISTS app_id UUID;

-- 4) FK
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_events_app'
  ) THEN
    ALTER TABLE waf_events
      ADD CONSTRAINT fk_waf_events_app
        FOREIGN KEY (app_id) REFERENCES waf_apps(id)
        ON DELETE RESTRICT;
  END IF;
END $$;

-- 5) Backfill a app por defecto
UPDATE waf_events
SET app_id = (SELECT id FROM waf_apps WHERE slug = 'default')
WHERE app_id IS NULL;

-- 6) Hacer NOT NULL
ALTER TABLE waf_events ALTER COLUMN app_id SET NOT NULL;

-- 7) Índice por app + fecha
CREATE INDEX IF NOT EXISTS idx_waf_events_app_fecha ON waf_events (app_id, fecha DESC);

COMMIT;
