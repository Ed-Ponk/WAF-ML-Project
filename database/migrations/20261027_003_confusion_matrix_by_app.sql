-- Migración 003: Métricas de confusión por app
BEGIN;

CREATE OR REPLACE VIEW vw_confusion_matrix_by_app AS
SELECT
    e.app_id,
    a.slug,
    a.name,
    COUNT(*)                                        AS total,
    COUNT(*) FILTER (WHERE e.veredicto = 1 AND e.accion = 'BLOCK') AS true_positive,
    COUNT(*) FILTER (WHERE e.veredicto = 0 AND e.accion = 'ALLOW') AS true_negative,
    COUNT(*) FILTER (WHERE e.veredicto = 0 AND e.accion = 'BLOCK') AS false_positive,
    COUNT(*) FILTER (WHERE e.veredicto = 1 AND e.accion = 'ALLOW') AS false_negative,
    ROUND(
        COUNT(*) FILTER (WHERE e.veredicto = 1 AND e.accion = 'BLOCK')::NUMERIC /
        NULLIF(COUNT(*) FILTER (WHERE e.veredicto = 1), 0) * 100, 2
    )                                               AS recall_pct,
    ROUND(
        COUNT(*) FILTER (WHERE e.veredicto = 0 AND e.accion = 'BLOCK')::NUMERIC /
        NULLIF(COUNT(*) FILTER (WHERE e.veredicto = 0), 0) * 100, 2
    )                                               AS false_positive_rate_pct
FROM waf_events e
JOIN waf_apps a ON a.id = e.app_id
GROUP BY e.app_id, a.slug, a.name;

CREATE OR REPLACE FUNCTION fn_confusion_matrix(p_app_id UUID DEFAULT NULL)
RETURNS TABLE (
    total BIGINT,
    true_positive BIGINT,
    true_negative BIGINT,
    false_positive BIGINT,
    false_negative BIGINT,
    recall_pct NUMERIC,
    false_positive_rate_pct NUMERIC
) AS $$
BEGIN
    IF p_app_id IS NULL THEN
        RETURN QUERY
        SELECT
            COUNT(*)::BIGINT                                        AS total,
            COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK')::BIGINT AS true_positive,
            COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'ALLOW')::BIGINT AS true_negative,
            COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK')::BIGINT AS false_positive,
            COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'ALLOW')::BIGINT AS false_negative,
            ROUND(
                COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK')::NUMERIC /
                NULLIF(COUNT(*) FILTER (WHERE veredicto = 1), 0) * 100, 2
            )                                               AS recall_pct,
            ROUND(
                COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK')::NUMERIC /
                NULLIF(COUNT(*) FILTER (WHERE veredicto = 0), 0) * 100, 2
            )                                               AS false_positive_rate_pct
        FROM waf_events;
    ELSE
        RETURN QUERY
        SELECT
            COUNT(*)::BIGINT                                        AS total,
            COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK')::BIGINT AS true_positive,
            COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'ALLOW')::BIGINT AS true_negative,
            COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK')::BIGINT AS false_positive,
            COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'ALLOW')::BIGINT AS false_negative,
            ROUND(
                COUNT(*) FILTER (WHERE veredicto = 1 AND accion = 'BLOCK')::NUMERIC /
                NULLIF(COUNT(*) FILTER (WHERE veredicto = 1), 0) * 100, 2
            )                                               AS recall_pct,
            ROUND(
                COUNT(*) FILTER (WHERE veredicto = 0 AND accion = 'BLOCK')::NUMERIC /
                NULLIF(COUNT(*) FILTER (WHERE veredicto = 0), 0) * 100, 2
            )                                               AS false_positive_rate_pct
        FROM waf_events
        WHERE app_id = p_app_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMIT;
