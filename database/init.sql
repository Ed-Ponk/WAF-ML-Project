-- ══════════════════════════════════════════════════════════════
-- WAF-ML Engine · Base de datos de telemetría de seguridad
-- Autor: Fernandez Alva, E. · USAT 2026
-- ══════════════════════════════════════════════════════════════

-- ── Extensión para UUID ──────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ══════════════════════════════════════════════════════════════
-- TABLA PRINCIPAL: Eventos de inspección del WAF
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS waf_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    fecha           TIMESTAMPTZ NOT NULL    DEFAULT NOW(),
    ip_origen       INET        NOT NULL,
	user_agent      TEXT,  -- Para análisis forense
    metodo_http     VARCHAR(10) NOT NULL,
    url             TEXT        NOT NULL,
    payload         TEXT,

    -- Features del OE2 (trazabilidad metodológica)
    url_length          INTEGER,
    payload_length      INTEGER,
    special_char_count  INTEGER,
    shannon_entropy     NUMERIC(8,6),
    features_json       JSONB, -- Guarda las 17 dimensiones exactas

    -- Resultado del motor ML
    score_ml        NUMERIC(6,4) NOT NULL CHECK (score_ml BETWEEN 0 AND 1),
    veredicto       SMALLINT     NOT NULL CHECK (veredicto IN (0,1)),
	etiqueta_real   SMALLINT,
    accion          VARCHAR(5)   NOT NULL CHECK (accion IN ('BLOCK','ALLOW', 'LOG')),

    -- Metadata
    tiempo_inferencia_ms  NUMERIC(8,3),
    waf_version           VARCHAR(20) DEFAULT '1.0'
);

-- ══════════════════════════════════════════════════════════════
-- TABLA SECUNDARIA: Resumen diario para reportes
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS waf_daily_summary (
    id              SERIAL      PRIMARY KEY,
    fecha_dia       DATE        NOT NULL UNIQUE,
    total_requests  INTEGER     DEFAULT 0,
    total_blocked   INTEGER     DEFAULT 0,
    total_allowed   INTEGER     DEFAULT 0,
    sqli_detected   INTEGER     DEFAULT 0,
    xss_detected    INTEGER     DEFAULT 0,
    cmd_detected    INTEGER     DEFAULT 0,
    avg_score_ml    NUMERIC(6,4),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ══════════════════════════════════════════════════════════════
-- ÍNDICES: Para consultas rápidas en evaluación comparativa
-- ══════════════════════════════════════════════════════════════
CREATE INDEX idx_waf_fecha       ON waf_events (fecha DESC);
CREATE INDEX idx_waf_ip          ON waf_events (ip_origen);
CREATE INDEX idx_waf_veredicto   ON waf_events (veredicto);
CREATE INDEX idx_waf_accion      ON waf_events (accion);
CREATE INDEX idx_waf_score       ON waf_events (score_ml DESC);

-- ══════════════════════════════════════════════════════════════
-- VISTA: Métricas para la matriz de confusión de tu tesis
-- ══════════════════════════════════════════════════════════════
CREATE VIEW vw_confusion_matrix AS
SELECT
    COUNT(*)                                        AS total,
    COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK') AS true_positive,
    COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'ALLOW') AS true_negative,
    COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK') AS false_positive,
    COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'ALLOW') AS false_negative,
    ROUND(
        COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK')::NUMERIC /
        NULLIF(COUNT(*) FILTER (WHERE veredicto = 1), 0) * 100, 2
    )                                               AS recall_pct,
    ROUND(
        COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK')::NUMERIC /
        NULLIF(COUNT(*) FILTER (WHERE accion = 'BLOCK'), 0) * 100, 2
    )                                               AS false_positive_rate_pct
FROM waf_events;

-- ══════════════════════════════════════════════════════════════
-- FUNCIÓN + TRIGGER: Actualiza resumen diario automáticamente
-- ══════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION fn_update_daily_summary()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO waf_daily_summary (
        fecha_dia, total_requests, total_blocked, total_allowed,
        sqli_detected, xss_detected, cmd_detected, avg_score_ml, updated_at
    )
    VALUES (
        DATE(NEW.fecha),
        1,
        CASE WHEN NEW.accion = 'BLOCK' THEN 1 ELSE 0 END,
        CASE WHEN NEW.accion = 'ALLOW' THEN 1 ELSE 0 END,
        (NEW.features_json->>'sqli_keyword_flag')::INTEGER,
        (NEW.features_json->>'xss_keyword_flag')::INTEGER,
        (NEW.features_json->>'cmd_keyword_flag')::INTEGER,
        NEW.score_ml,
        NOW()
    )
    ON CONFLICT (fecha_dia) DO UPDATE SET
        total_requests = waf_daily_summary.total_requests + 1,
        total_blocked  = waf_daily_summary.total_blocked  + EXCLUDED.total_blocked,
        total_allowed  = waf_daily_summary.total_allowed  + EXCLUDED.total_allowed,
        sqli_detected  = waf_daily_summary.sqli_detected  + EXCLUDED.sqli_detected,
        xss_detected   = waf_daily_summary.xss_detected   + EXCLUDED.xss_detected,
        cmd_detected   = waf_daily_summary.cmd_detected   + EXCLUDED.cmd_detected,
        avg_score_ml   = ROUND(
                            (waf_daily_summary.avg_score_ml * waf_daily_summary.total_requests
                             + EXCLUDED.avg_score_ml) /
                            (waf_daily_summary.total_requests + 1), 4),
        updated_at     = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_daily_summary
AFTER INSERT ON waf_events
FOR EACH ROW EXECUTE FUNCTION fn_update_daily_summary();

-- ══════════════════════════════════════════════════════════════
-- DATOS DE PRUEBA: Para verificar que el schema funciona
-- ══════════════════════════════════════════════════════════════
INSERT INTO waf_events (
    ip_origen, metodo_http, url, payload,
    url_length, payload_length, shannon_entropy,
    score_ml, veredicto, accion, tiempo_inferencia_ms,
    features_json
) VALUES
(
    '192.168.1.100', 'POST',
    '/login', 'username=admin&password=1'' OR ''1''=''1',
    6, 42, 3.8214,
    0.9823, 1, 'BLOCK', 12.4,
    '{"sqli_keyword_flag": 1, "special_chars": 8, "url_len": 6}'::JSONB
),
(
    '10.0.0.5', 'GET',
    '/productos?id=3', '',
    16, 0, 2.9543,
    0.0312, 0, 'ALLOW', 3.1,
    '{"sqli_keyword_flag": 0, "special_chars": 1, "url_len": 16}'::JSONB
);

-- Verificación final
SELECT 'Schema WAF-ML creado correctamente' AS status;
SELECT * FROM vw_confusion_matrix;