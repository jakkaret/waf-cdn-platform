-- Seed the three default rate-limit rules that services/rate_limit_service.py
-- inserted into an empty SQLite rate_limits.db (rate_limit_service.py:61-98).
-- ON CONFLICT DO NOTHING: re-running never overwrites an admin's edits.
INSERT INTO waf.rate_limit_rules
    (id, name, path_pattern, method, limit_count, window_seconds, burst, action, enabled)
VALUES
    ('rule_auth_protect', 'Authentication Brute-Force Guard', '/api/auth/*', 'POST', 10, 60, 2, '429', true),
    ('rule_global_api',   'Global API Spike Protection',      '/api/*',      'ALL', 120, 60, 20, '429', true),
    ('rule_edge_flood',   'Edge Anti-Flooding Shield',        '*',           'ALL',  50,  1, 10, '429', true)
ON CONFLICT (id) DO NOTHING;
