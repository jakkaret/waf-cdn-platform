-- ML rule proposals per origin (api/ml_rules.py, api/ml.py, 2026-10-26).
-- An origin's Owner and Editors now ask for proposals for their own origin and
-- review them; approving one deploys it for that origin only. A proposal for
-- one origin must therefore never merge into another origin's pending rule,
-- nor into a global one: the pending dedup key becomes unique per origin
-- (NULL origin_id = the global queue, counted as one value). The old index
-- made dedup_key unique on its own, so every existing row already satisfies
-- the new one; no data changes. The name stays the same.
DROP INDEX waf.pending_rules_pending_dedup_uk;
CREATE UNIQUE INDEX pending_rules_pending_dedup_uk ON waf.pending_rules (dedup_key, origin_id) NULLS NOT DISTINCT
    WHERE status = 'pending' AND dedup_key IS NOT NULL;
