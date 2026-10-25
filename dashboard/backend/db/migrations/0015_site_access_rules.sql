-- Per-site IP access and rate limits (services/origin_ip_rules.py,
-- services/rate_limit_service.py). Until now both existed only platform-wide,
-- so a site's own owner and editors could not manage them.

-- An IP or CIDR a site blocks or lets through. Rendered per site into
-- /opt/custom-rules/siteip-<origin_id>.conf, scoped to that site's verified
-- hosts. NULL expires_at = permanent; expired rows are removed by the
-- retention worker, which re-renders the site's file.
CREATE TABLE waf.origin_ip_rules (
    id          bigserial   PRIMARY KEY,
    origin_id   uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    ip          cidr        NOT NULL,
    action      text        NOT NULL CHECK (action IN ('block', 'allow')),
    note        text        NOT NULL DEFAULT '' CHECK (length(note) <= 200),
    expires_at  timestamptz,
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT origin_ip_rules_uk UNIQUE (origin_id, ip)
);
CREATE INDEX origin_ip_rules_expires_idx ON waf.origin_ip_rules (expires_at) WHERE expires_at IS NOT NULL;

-- ModSecurity rule ids for each site's IP file: base = 3500000 + 2 * slot
-- (block, allow). A slot is never reused, so a stale id on an edge can never
-- point at another site.
CREATE TABLE waf.origin_rule_slots (
    origin_id uuid    PRIMARY KEY REFERENCES waf.origins (id) ON DELETE CASCADE,
    slot      integer GENERATED ALWAYS AS IDENTITY UNIQUE
);

-- NULL origin_id = a platform-wide rule (set by the platform operator);
-- otherwise the rule counts only requests to that site's hosts.
ALTER TABLE waf.rate_limit_rules
    ADD COLUMN origin_id uuid REFERENCES waf.origins (id) ON DELETE CASCADE;
CREATE INDEX rate_limit_rules_origin_idx ON waf.rate_limit_rules (origin_id) WHERE origin_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.origin_ip_rules, waf.origin_rule_slots TO waf_app;
GRANT USAGE, SELECT ON SEQUENCE waf.origin_ip_rules_id_seq, waf.origin_rule_slots_slot_seq TO waf_app;
