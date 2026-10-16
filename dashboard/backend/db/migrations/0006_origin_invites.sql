-- N9/H64: sharing an origin sends an invitation to the mailbox; access starts
-- only when someone who can read that mailbox opens the link and accepts while
-- signed in. Holding an account registered under the address is not enough.
-- Only the SHA-256 of the invitation token is stored.
CREATE TABLE waf.origin_invites (
    invite_id    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_id    uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    email        text        NOT NULL,
    role         text        NOT NULL CHECK (role IN ('viewer', 'editor')),
    token_hash   text        NOT NULL UNIQUE,
    invited_by   uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    accepted_by  uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL
);
CREATE INDEX origin_invites_origin_idx ON waf.origin_invites (origin_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON waf.origin_invites TO waf_app;
