-- Who is told what (services/notification_prefs.py).

-- How big an attack burst must be before it becomes an incident, per site.
-- Set by the site's owner or editors; no row = 'medium'.
CREATE TABLE waf.origin_alert_settings (
    origin_id   uuid        PRIMARY KEY REFERENCES waf.origins (id) ON DELETE CASCADE,
    sensitivity text        NOT NULL DEFAULT 'medium' CHECK (sensitivity IN ('low', 'medium', 'high')),
    updated_by  uuid,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- One person's choices for one site. NULL = the default for their role on it.
CREATE TABLE waf.notification_prefs (
    user_id    uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    origin_id  uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    attacks    boolean,
    outages    boolean,
    certs      boolean,
    team       boolean,
    digest     boolean,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, origin_id)
);

-- Daily summaries already sent (one per person, site and Bangkok day).
CREATE TABLE waf.digest_sent (
    user_id   uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    origin_id uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    day       date        NOT NULL,
    sent_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, origin_id, day)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.origin_alert_settings, waf.notification_prefs, waf.digest_sent TO waf_app;
