-- Support tickets and time-limited support access (docs/tickets/support-access.md).
-- An origin admin opens a ticket and may grant the platform support team
-- (platform admins) temporary viewer or editor access to that one origin.
-- No accounts are created; every grant use is logged for the owner to see.
CREATE TABLE waf.support_tickets (
    ticket_id   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_id   uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    opened_by   uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL,
    subject     text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
    status      text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    closed_at   timestamptz,
    closed_by   uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL
);
CREATE INDEX support_tickets_origin_idx ON waf.support_tickets (origin_id);
CREATE INDEX support_tickets_status_idx ON waf.support_tickets (status, updated_at DESC);

CREATE TABLE waf.support_ticket_messages (
    message_id  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   uuid        NOT NULL REFERENCES waf.support_tickets (ticket_id) ON DELETE CASCADE,
    author_id   uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL,
    is_support  boolean     NOT NULL DEFAULT false,
    body        text        NOT NULL CHECK (length(body) BETWEEN 1 AND 5000),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_ticket_messages_ticket_idx ON waf.support_ticket_messages (ticket_id, created_at);

CREATE TABLE waf.support_grants (
    grant_id    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   uuid        NOT NULL REFERENCES waf.support_tickets (ticket_id) ON DELETE CASCADE,
    origin_id   uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    level       text        NOT NULL CHECK (level IN ('viewer', 'editor')),
    granted_by  uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL
);
CREATE INDEX support_grants_origin_active_idx ON waf.support_grants (origin_id) WHERE revoked_at IS NULL;

CREATE TABLE waf.support_access_log (
    id          bigserial   PRIMARY KEY,
    grant_id    uuid        NOT NULL REFERENCES waf.support_grants (grant_id) ON DELETE CASCADE,
    origin_id   uuid        NOT NULL REFERENCES waf.origins (id) ON DELETE CASCADE,
    staff_id    uuid        REFERENCES waf.users (user_id) ON DELETE SET NULL,
    kind        text        NOT NULL CHECK (kind IN ('read', 'edit')),
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX support_access_log_grant_idx ON waf.support_access_log (grant_id, at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON waf.support_tickets, waf.support_ticket_messages,
    waf.support_grants, waf.support_access_log TO waf_app;
GRANT USAGE, SELECT ON SEQUENCE waf.support_access_log_id_seq TO waf_app;
