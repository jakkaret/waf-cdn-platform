-- Revoking an approved ML/CVE rule (api/ml_rules.py POST /{rule_id}/revoke,
-- 2026-10-27). Revoking takes the rule out of the WAF (its ml-<id>.conf is
-- removed) but keeps the row: who revoked it, when and why stay on record,
-- and its deployed_rule_id stays taken so reserve_approval never hands the
-- same ModSecurity id out again. A revoked rule is not approved any more, so
-- it no longer counts toward an origin's approved-rule cap.
ALTER TABLE waf.pending_rules DROP CONSTRAINT pending_rules_status_check;
ALTER TABLE waf.pending_rules ADD CONSTRAINT pending_rules_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'revoked'));
ALTER TABLE waf.pending_rules
    ADD COLUMN revoked_by    text,
    ADD COLUMN revoked_at    timestamptz,
    ADD COLUMN revoke_reason text;
ALTER TABLE waf.pending_rules ADD CONSTRAINT pending_rules_revoked_recorded
    CHECK (status <> 'revoked' OR (revoked_at IS NOT NULL AND deployed_rule_id IS NOT NULL));
