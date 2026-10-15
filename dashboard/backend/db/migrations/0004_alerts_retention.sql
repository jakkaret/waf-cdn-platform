-- Alerts were kept forever in DynamoDB (no TTL). Keep 90 days, removed by
-- the same hourly run_retention() job as audit / threat / status rows
-- (default chosen at migration time, 2026-10-15).
GRANT SELECT, DELETE ON waf.alerts TO waf_maintenance;

DROP FUNCTION waf.run_retention(integer, integer, integer);
CREATE FUNCTION waf.run_retention(
    audit_days    integer DEFAULT 180,   -- audit_log.py RETENTION_DAYS
    threat_hours  integer DEFAULT 72,    -- threat_intel.py PATTERN_RETENTION_HOURS
    history_days  integer DEFAULT 400,   -- public_status.py HISTORY_RETENTION_DAYS
    alert_days    integer DEFAULT 90
) RETURNS TABLE (table_name text, deleted bigint)
LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  DELETE FROM waf.audit_logs WHERE occurred_at < now() - make_interval(days => audit_days);
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'audit_logs'; deleted := n; RETURN NEXT;

  DELETE FROM waf.threat_patterns WHERE bucket_start < now() - make_interval(hours => threat_hours);
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'threat_patterns'; deleted := n; RETURN NEXT;

  DELETE FROM waf.status_history_days WHERE date_bucket < current_date - history_days;
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'status_history_days'; deleted := n; RETURN NEXT;

  DELETE FROM waf.alerts WHERE created_at < now() - make_interval(days => alert_days);
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'alerts'; deleted := n; RETURN NEXT;

  -- ip_rules expiry is NOT done here: the app's retention worker deletes
  -- expired rows AND re-renders the ModSecurity block/allow files.
END
$$;
COMMENT ON FUNCTION waf.run_retention(integer, integer, integer, integer) IS 'Run hourly as waf_maintenance (services/retention_worker.py).';
REVOKE ALL ON FUNCTION waf.run_retention(integer, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION waf.run_retention(integer, integer, integer, integer) TO waf_maintenance;
