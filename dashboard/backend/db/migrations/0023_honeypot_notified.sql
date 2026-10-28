-- Honeypot alerts sent (services/honeypot.py). A honeytoken coming back, or
-- a file uploaded into a trap, is pushed to the site's team at once. The row
-- is claimed with INSERT ... ON CONFLICT DO NOTHING before the message goes
-- out, so one actor reaching one stage on one site is told once an hour, and
-- a restart neither repeats nor loses it.
CREATE TABLE waf.honeypot_notified (
    origin_id  uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    actor_id   text        NOT NULL,
    stage      text        NOT NULL,
    hour       timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin_id, actor_id, stage, hour)
);
CREATE INDEX honeypot_notified_created ON waf.honeypot_notified (created_at);
GRANT SELECT, INSERT, DELETE ON waf.honeypot_notified TO waf_app;
