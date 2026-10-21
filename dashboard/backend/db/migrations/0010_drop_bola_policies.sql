-- Remove the BOLA policy table together with the BOLA guard (services/bola_guard.py).
-- The guard was never in the request path: nginx and control-api did not call it,
-- it verified tokens with the dashboard's own JWT key (not a customer app's key),
-- and its policies had no origin. Object-level authorization of the platform API
-- is done in services/rbac.py and is not affected.
-- Refuse to drop the table if anyone stored a policy, so no data is lost silently.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM waf.bola_policies) THEN
        RAISE EXCEPTION 'waf.bola_policies is not empty; export its rows before running 0010';
    END IF;
END
$$;

DROP TABLE waf.bola_policies;
