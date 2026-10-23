-- Attack incidents: blocked requests grouped per site into one event with a
-- start and an end (services/alert_incidents.py). Telegram is sent once when
-- an incident opens and once when it closes, never per blocked request.
-- scope is the origin id as text, or 'unattributed' for traffic that belongs
-- to no site (admin-only), so both share one "at most one open incident" rule.
CREATE TABLE waf.alert_incidents (
    incident_id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scope                text        NOT NULL,
    origin_id            uuid        REFERENCES waf.origins (id) ON DELETE CASCADE,
    opened_at            timestamptz NOT NULL,
    last_seen_at         timestamptz NOT NULL,
    closed_at            timestamptz,
    open_count           integer     NOT NULL,   -- blocks in the window that opened it
    blocked_count        integer     NOT NULL,
    ip_count             integer     NOT NULL,
    top_ips              jsonb       NOT NULL DEFAULT '[]',
    top_types            jsonb       NOT NULL DEFAULT '[]',
    top_paths            jsonb       NOT NULL DEFAULT '[]',
    summary              text,                   -- written on close; NULL when the AI did not answer
    summary_by_ai        boolean     NOT NULL DEFAULT false,
    open_notified_at     timestamptz,
    escalated_notified_at timestamptz,
    close_notified_at    timestamptz,
    CHECK (scope = 'unattributed' OR origin_id IS NOT NULL)
);
CREATE UNIQUE INDEX alert_incidents_one_open ON waf.alert_incidents (scope) WHERE closed_at IS NULL;
CREATE INDEX alert_incidents_scope_opened_idx ON waf.alert_incidents (scope, opened_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON waf.alert_incidents TO waf_app;
