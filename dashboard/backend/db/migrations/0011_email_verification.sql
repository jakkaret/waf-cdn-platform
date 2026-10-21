-- Email verification and password reset by a 6-digit code sent to the mailbox.
-- An account exists right after sign-up, but what reaches other people or the
-- edge (adding a site, inviting a team, agent tokens, AI, outbound
-- notifications) waits until the owner proves the address (services/rbac.py
-- require_verified_email). Every account that exists before this migration
-- counts as verified, so nobody already using the platform is locked out.
ALTER TABLE waf.users ADD COLUMN email_verified_at timestamptz;
UPDATE waf.users SET email_verified_at = created_at;

-- One live code per account and purpose: a new code replaces the old one.
-- Only an HMAC of the code is stored (services/email_codes.py).
CREATE TABLE waf.email_codes (
    user_id     uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    purpose     text        NOT NULL CHECK (purpose IN ('verify', 'reset')),
    code_hash   text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    attempts    integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, purpose)
);
-- Each send, kept for an hour, for the per-account hourly cap.
CREATE TABLE waf.email_code_sends (
    user_id  uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    purpose  text        NOT NULL,
    sent_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_code_sends_user_idx ON waf.email_code_sends (user_id, purpose, sent_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON waf.email_codes, waf.email_code_sends TO waf_app;
