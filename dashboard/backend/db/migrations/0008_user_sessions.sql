-- Per-device sessions (2026-10-16). Every sign-in creates a row and the JWT
-- carries its session_id ("sid"). Logout revokes only that row, so signing out
-- on one device leaves the others signed in. "Sign out of all devices", role
-- changes, password changes and account deletion still bump
-- users.token_version (0005), which voids every session of the account.
CREATE TABLE waf.user_sessions (
    session_id    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    user_agent    text        NOT NULL DEFAULT '',
    ip            text        NOT NULL DEFAULT ''
);
CREATE INDEX user_sessions_user_idx ON waf.user_sessions (user_id);
CREATE INDEX user_sessions_expires_idx ON waf.user_sessions (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON waf.user_sessions TO waf_app;
