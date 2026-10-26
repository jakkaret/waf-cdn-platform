-- How an approved ML/CVE rule was actually written to ml-<id>.conf
-- (services/ml_rule_service.approve_rule, 2026-10-26). From now on a rule with
-- an origin_id is deployed scoped to that origin (the TX:waf_origin_id chain)
-- and one without is global; before, every approval was global, including CVE
-- rules that already carried the origin whose tech stack matched. The review
-- queue therefore cannot read an approved rule's scope from origin_id alone:
-- approval records it here ('origin' | 'global'), and every rule approved
-- before this migration is 'global', which is how its file was written.
-- NULL for rules that were never approved (their scope follows origin_id).
ALTER TABLE waf.pending_rules ADD COLUMN deploy_scope text CHECK (deploy_scope IN ('origin', 'global'));
UPDATE waf.pending_rules SET deploy_scope = 'global' WHERE deployed_rule_id IS NOT NULL;
