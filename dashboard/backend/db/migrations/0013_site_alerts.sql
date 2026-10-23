-- Things a site's team has to act on (services/site_alerts.py), pushed to
-- Telegram as they happen rather than grouped like attack incidents.

-- A site its visitors cannot reach: the edge answered 502/503/504 to most
-- requests, or the site's agent tunnel went offline. At most one open per site.
CREATE TABLE waf.site_outages (
    outage_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_id        uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    reason           text        NOT NULL CHECK (reason IN ('upstream_errors', 'tunnel_offline')),
    started_at       timestamptz NOT NULL,
    last_bad_at      timestamptz NOT NULL,
    ended_at         timestamptz,
    error_count      integer     NOT NULL DEFAULT 0,
    request_count    integer     NOT NULL DEFAULT 0,
    down_notified_at timestamptz,
    up_notified_at   timestamptz
);
CREATE UNIQUE INDEX site_outages_one_open ON waf.site_outages (origin_id) WHERE ended_at IS NULL;

-- Audit events already told to the site's owner (team and setting changes),
-- so a restart or a second worker never repeats one.
CREATE TABLE waf.audit_notified (
    event_id    text        PRIMARY KEY,
    notified_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.site_outages, waf.audit_notified TO waf_app;
