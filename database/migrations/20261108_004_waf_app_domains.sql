-- Migración 004: múltiples dominios por aplicación
-- Idempotente: se puede aplicar sobre volúmenes nuevos y sobre producción.
BEGIN;

-- 1) Tabla de dominios por app (un dominio pertenece a una sola app)
CREATE TABLE IF NOT EXISTS waf_app_domains (
  id BIGSERIAL PRIMARY KEY,
  app_id UUID NOT NULL,
  domain VARCHAR(253) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2) FK idempotente
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_app_domains_app'
  ) THEN
    ALTER TABLE waf_app_domains
      ADD CONSTRAINT fk_waf_app_domains_app
        FOREIGN KEY (app_id) REFERENCES waf_apps(id)
        ON DELETE CASCADE;
  END IF;
END $$;

-- 3) Restricciones idempotentes
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_app_domains_domain_check'
  ) THEN
    ALTER TABLE waf_app_domains
      ADD CONSTRAINT waf_app_domains_domain_check
        CHECK (domain = lower(domain));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_app_domains_domain_key'
  ) THEN
    ALTER TABLE waf_app_domains
      ADD CONSTRAINT waf_app_domains_domain_key UNIQUE (domain);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_waf_app_domains_app_id ON waf_app_domains (app_id);

-- 4) Backfill del dominio legacy (waf_apps.domain) a la nueva tabla
INSERT INTO waf_app_domains (app_id, domain)
SELECT id, domain FROM waf_apps
ON CONFLICT (domain) DO NOTHING;

-- 5) Mantener updated_at sincronizado en waf_apps
CREATE OR REPLACE FUNCTION fn_waf_apps_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_waf_apps_updated_at ON waf_apps;
CREATE TRIGGER trg_waf_apps_updated_at
BEFORE UPDATE ON waf_apps
FOR EACH ROW EXECUTE FUNCTION fn_waf_apps_touch_updated_at();

CREATE INDEX IF NOT EXISTS idx_waf_apps_enabled ON waf_apps (enabled);

COMMIT;
