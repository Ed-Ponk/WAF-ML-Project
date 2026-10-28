-- Migración 002: waf_daily_summary por app + trigger reescrito
BEGIN;

-- 1) Agregar app_id
ALTER TABLE waf_daily_summary ADD COLUMN IF NOT EXISTS app_id UUID;

-- 2) Backfill
UPDATE waf_daily_summary
SET app_id = (SELECT id FROM waf_apps WHERE slug = 'default')
WHERE app_id IS NULL;

-- 3) FK
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_daily_summary_app'
  ) THEN
    ALTER TABLE waf_daily_summary
      ADD CONSTRAINT fk_waf_daily_summary_app
        FOREIGN KEY (app_id) REFERENCES waf_apps(id)
        ON DELETE RESTRICT;
  END IF;
END $$;

-- 4) NOT NULL
ALTER TABLE waf_daily_summary ALTER COLUMN app_id SET NOT NULL;

-- 5) Eliminar constraint unique antigua (fecha_dia) si existe
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_daily_summary_fecha_dia_key'
  ) THEN
    ALTER TABLE waf_daily_summary DROP CONSTRAINT waf_daily_summary_fecha_dia_key;
  END IF;
END $$;

-- 6) Crear unique por (app_id, fecha_dia)
CREATE UNIQUE INDEX IF NOT EXISTS waf_daily_summary_app_fecha_key ON waf_daily_summary (app_id, fecha_dia);

-- 7) Reescribir función de trigger para usar app_id
CREATE OR REPLACE FUNCTION fn_update_daily_summary()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO waf_daily_summary (
        app_id,
        fecha_dia, total_requests, total_blocked, total_allowed,
        sqli_detected, xss_detected, cmd_detected,
        cwe_sqli, cwe_xss, cwe_rce, cwe_crlf,
        avg_score_ml, updated_at
    )
    VALUES (
        NEW.app_id,
        DATE(NEW.fecha),
        1,
        CASE WHEN NEW.accion = 'BLOCK' THEN 1 ELSE 0 END,
        CASE WHEN NEW.accion = 'ALLOW' THEN 1 ELSE 0 END,
        COALESCE((NEW.features_json->>'has_sql')::INTEGER, 0),
        COALESCE((NEW.features_json->>'has_xss')::INTEGER, 0),
        COALESCE((NEW.features_json->>'has_rce')::INTEGER, 0),
        CASE WHEN NEW.cwe_family = 'sql'  THEN 1 ELSE 0 END,
        CASE WHEN NEW.cwe_family = 'xss'  THEN 1 ELSE 0 END,
        CASE WHEN NEW.cwe_family = 'rce'  THEN 1 ELSE 0 END,
        CASE WHEN NEW.cwe_family = 'crlf' THEN 1 ELSE 0 END,
        NEW.score_ml,
        NOW()
    )
    ON CONFLICT (app_id, fecha_dia) DO UPDATE SET
        total_requests = waf_daily_summary.total_requests + 1,
        total_blocked  = waf_daily_summary.total_blocked  + EXCLUDED.total_blocked,
        total_allowed  = waf_daily_summary.total_allowed  + EXCLUDED.total_allowed,
        sqli_detected  = waf_daily_summary.sqli_detected  + EXCLUDED.sqli_detected,
        xss_detected   = waf_daily_summary.xss_detected   + EXCLUDED.xss_detected,
        cmd_detected   = waf_daily_summary.cmd_detected   + EXCLUDED.cmd_detected,
        cwe_sqli       = waf_daily_summary.cwe_sqli       + EXCLUDED.cwe_sqli,
        cwe_xss        = waf_daily_summary.cwe_xss        + EXCLUDED.cwe_xss,
        cwe_rce        = waf_daily_summary.cwe_rce        + EXCLUDED.cwe_rce,
        cwe_crlf       = waf_daily_summary.cwe_crlf       + EXCLUDED.cwe_crlf,
        avg_score_ml   = ROUND(
                            (COALESCE(waf_daily_summary.avg_score_ml, 0) * waf_daily_summary.total_requests
                             + EXCLUDED.avg_score_ml) /
                            (waf_daily_summary.total_requests + 1), 4),
        updated_at     = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger ya existe, se mantiene (creado en init)
COMMIT;
