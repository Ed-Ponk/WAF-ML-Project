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
        NULLIF(COUNT(*) FILTER (WHERE veredicto = 0), 0) * 100, 2
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
        COALESCE((NEW.features_json->>'has_sql')::INTEGER, 0),
        COALESCE((NEW.features_json->>'has_xss')::INTEGER, 0),
        COALESCE((NEW.features_json->>'has_rce')::INTEGER, 0),
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
                            (COALESCE(waf_daily_summary.avg_score_ml, 0) * waf_daily_summary.total_requests
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
-- TABLAS DEL DASHBOARD ADMINISTRATIVO (Fase 1)
-- ══════════════════════════════════════════════════════════════

-- Tabla de usuarios con RBAC
CREATE TABLE IF NOT EXISTS waf_users (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR         NOT NULL UNIQUE,
    password_hash   VARCHAR         NOT NULL,
    role            VARCHAR         NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Seed de usuario administrador por defecto (Bcrypt para '***REMOVED***')
INSERT INTO waf_users (username, password_hash, role)
VALUES ('admin', '***REMOVED***', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Tabla de métricas de hardware
CREATE TABLE IF NOT EXISTS waf_hardware_metrics (
    id              SERIAL          PRIMARY KEY,
    container_name  VARCHAR(100)    NOT NULL,
    cpu_usage_pct   NUMERIC(5,2)    NOT NULL,
    ram_usage_mb    NUMERIC(9,2)    NOT NULL,
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Tabla de matrices de comparación (Baselines)
CREATE TABLE IF NOT EXISTS waf_baselines (
    id              SERIAL          PRIMARY KEY,
    baseline_name   VARCHAR(100)    NOT NULL UNIQUE,
    true_positives  INTEGER         NOT NULL DEFAULT 0,
    false_positives INTEGER         NOT NULL DEFAULT 0,
    true_negatives  INTEGER         NOT NULL DEFAULT 0,
    false_negatives INTEGER         NOT NULL DEFAULT 0,
    fpr             NUMERIC(5,2)    GENERATED ALWAYS AS (ROUND(false_positives::NUMERIC / NULLIF(false_positives + true_negatives, 0) * 100, 2)) STORED,
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Seed de métricas iniciales de comparación (baselines)
-- Valores reales del benchmark de 224 casos (docs/benchmark-resultados.md Fase 2)
-- Los endpoints usan benchmark-baselines.ts (constantes centralizadas). Esta tabla
-- se mantiene como referencia histórica para consultas directas a la DB.
INSERT INTO waf_baselines (baseline_name, true_positives, false_positives, true_negatives, false_negatives)
VALUES 
    ('WAF-ML (LGBM+MLP)', 91, 0, 132, 1),
    ('ModSecurity + OWASP CRS', 79, 0, 132, 13),
    ('Coraza + CRS', 79, 0, 132, 13),
    ('NAXSI', 84, 0, 132, 8)
ON CONFLICT (baseline_name) DO NOTHING;

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
    '{"has_sql": 1, "has_xss": 0, "has_rce": 0, "special_char_count": 8, "url_path_len": 6}'::JSONB
),
(
    '10.0.0.5', 'GET',
    '/productos?id=3', '',
    16, 0, 2.9543,
    0.0312, 0, 'ALLOW', 3.1,
    '{"has_sql": 0, "has_xss": 0, "has_rce": 0, "special_char_count": 1, "url_path_len": 16}'::JSONB
);

-- ── Model version tracking ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS waf_models (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(50),
    accuracy        NUMERIC(5,2),
    f1_score        NUMERIC(5,2),
    training_date   DATE,
    algorithm       VARCHAR(255),
    feature_count   INTEGER,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    uploaded_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed: registrar el modelo existente en ml-engine/
INSERT INTO waf_models (name, version, algorithm, feature_count, status)
VALUES ('WAF Ensemble MLP + LGBM', 'v1.0', 'LightGBM + MLP Neural Net', 50, 'active');

-- Verificación final
SELECT 'Schema WAF-ML creado correctamente' AS status;
SELECT * FROM vw_confusion_matrix;
-- ══════════════════════════════════════════════════════════════
-- AUDITORÍA DE ACCIONES ADMINISTRATIVAS
-- ══════════════════════════════════════════════════════════════
-- Registra quién hizo qué y cuándo (login, logout, model.upload).
-- NOTA (operativo): este archivo corre SOLO cuando el volumen de
-- Postgres está vacío. Para aplicar a una DB existente, ejecutar el
-- mismo SQL vía: docker compose exec database psql -U <user> -d <db>
CREATE TABLE IF NOT EXISTS waf_audit_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID,                 -- actor (JWT). NULL: login fallido / sin sesión
    username        VARCHAR,              -- actor o username intentado (login fallido)
    action          VARCHAR(50) NOT NULL, -- login | logout | model.upload
    result          VARCHAR(10) NOT NULL CHECK (result IN ('success','failure','blocked')),
    ip_address      INET,                 -- IP del cliente (X-Real-IP de nginx)
    details         JSONB       NOT NULL DEFAULT '{}'::JSONB,  -- contexto redactado por acción
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at ON waf_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON waf_audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON waf_audit_log (user_id);
