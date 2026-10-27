-- Per-origin ML protection (2026-10-27). The Gen 3 model scores every request
-- of an origin either way (ML Insights); this row decides whether a score can
-- change what the visitor gets. No row = 'log': score and record only.
--   mode             'log' | 'enforce'
--   challenge_score  score (0-100) from which a visitor without a CAPTCHA
--                    clearance gets the challenge page; NULL = no challenge band
--   block_score      score from which the request is answered 403; a
--                    clearance never lets a request in this band through
-- Owner and Editors change it (api/ml_protection.py, audited); the WAF reads
-- it from the nginx map services/ml_gate.py renders, so a missing or stale map
-- can only mean 'log', never a block nobody asked for.
CREATE TABLE waf.origin_ml_protection (
    origin_id        uuid        PRIMARY KEY REFERENCES waf.origins (id) ON DELETE CASCADE,
    mode             text        NOT NULL DEFAULT 'log' CHECK (mode IN ('log', 'enforce')),
    challenge_score  integer     CHECK (challenge_score BETWEEN 50 AND 99),
    block_score      integer     NOT NULL DEFAULT 95 CHECK (block_score BETWEEN 51 AND 100),
    updated_by       text        NOT NULL DEFAULT '',
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT origin_ml_protection_bands CHECK (challenge_score IS NULL OR challenge_score < block_score)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.origin_ml_protection TO waf_app;
