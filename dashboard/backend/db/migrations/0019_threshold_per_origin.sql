-- Tuning proposals belong to one origin (2026-10-27). Only that origin's Owner
-- generates, approves, rejects or rolls one back; platform admins have no part
-- in it. An approved value is stored on the origin and reaches the WAF through
-- that origin's host-map rule (services/managed_ruleset.render_hostmap), so it
-- changes the anomaly threshold for that origin's domains only.
--   origins.anomaly_threshold   NULL = the platform threshold from System settings
--   threshold_proposals.origin_id
--                               NULL only on proposals made before this
--                               migration, which changed the global setting;
--                               they are kept for history and no longer listed.
-- previous_threshold on a per-origin proposal is the origin's own value at
-- approval time, NULL when it was using the platform threshold.
ALTER TABLE waf.origins
    ADD COLUMN anomaly_threshold integer CHECK (anomaly_threshold BETWEEN 3 AND 10);
ALTER TABLE waf.threshold_proposals
    ADD COLUMN origin_id uuid REFERENCES waf.origins (id) ON DELETE SET NULL;
CREATE INDEX threshold_proposals_origin_idx ON waf.threshold_proposals (origin_id, created_at DESC);
COMMENT ON TABLE waf.threshold_proposals IS
    'Per-origin anomaly-threshold proposals (Owner approves/rejects/rolls back). Rows without origin_id are pre-2026-10-27 global proposals.';
