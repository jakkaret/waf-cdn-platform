-- Quick tunnels (services/quick_tunnel.py): a host under the platform's
-- tunnel zone (t-<random>.tunnel.waf-it-kku.online) that the platform names
-- and hands to a user with no domain of their own. The user never picks the
-- name (F-129 stays closed); the origin and its verified domain row are
-- created by the platform, and this table marks them as a quick tunnel.
--
-- last_seen_at is when the expiry worker last saw the agent online; a quick
-- tunnel whose agent stays offline longer than QUICK_TUNNEL_IDLE_DAYS (counted
-- from last_seen_at, or created_at when it never connected) is removed.
CREATE TABLE waf.quick_tunnels (
    origin_id     uuid        PRIMARY KEY REFERENCES waf.origins (id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    domain_name   text        NOT NULL UNIQUE CHECK (domain_name = lower(domain_name)),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz
);
CREATE INDEX quick_tunnels_user_idx ON waf.quick_tunnels (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.quick_tunnels TO waf_app;
