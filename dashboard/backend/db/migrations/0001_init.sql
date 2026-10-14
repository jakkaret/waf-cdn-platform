-- =====================================================================
-- WAF+CDN control-plane schema: DynamoDB (14 tables) + SQLite (2 DBs)
-- folded into ONE PostgreSQL database.  DEV stage: fresh schema, no data
-- migration.  ClickHouse (access_logs / security_audit_logs /
-- shield_events) and Redis (captcha/otp config, rate:limit:*, queues)
-- stay where they are.  Requires PostgreSQL >= 13.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Extensions, schema, roles
-- ---------------------------------------------------------------------
-- No extensions needed: gen_random_uuid() is built in from PostgreSQL 13.

CREATE SCHEMA IF NOT EXISTS waf;
SET search_path = waf, public;
-- Persist the search_path for every login role connecting to this DB
-- (role-level settings on NOLOGIN group roles are NOT inherited). The DSN
-- may also pass options=-csearch_path=waf,public.
DO $$
BEGIN
  EXECUTE format('ALTER DATABASE %I SET search_path = waf, public', current_database());
END
$$;

DO $$
BEGIN
  -- Group roles only (NOLOGIN). Real login users are created outside this
  -- file and GRANTed membership; no credentials live here.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'waf_app') THEN
    CREATE ROLE waf_app NOLOGIN;            -- FastAPI backend
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'waf_maintenance') THEN
    CREATE ROLE waf_maintenance NOLOGIN;    -- retention job (replaces DynamoDB TTL)
  END IF;
END
$$;

-- Migration bookkeeping (backend/db/migrate.py records each applied file).
CREATE TABLE schema_migrations (
    version     text        PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- =====================================================================
-- 1. identity-access
-- =====================================================================

-- waf_users (auth_service.py:154-174, alerts.py:207, auth_service.py:214)
CREATE TABLE users (
    user_id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email               text        NOT NULL,
    username            text        NOT NULL,
    role                text        NOT NULL DEFAULT 'viewer'
                                    CHECK (role IN ('admin', 'viewer')),  -- adapter maps any other value to 'viewer' (api/auth.py:44-47 role is a free str)
    password_hash       text,       -- argon2id; NULL for OAuth accounts (adapter returns '')
    auth_provider       text        NOT NULL DEFAULT 'local'
                                    CHECK (auth_provider IN ('local', 'google', 'telegram')),
    avatar_url          text,
    telegram_chat_id    text,       -- NULL = not connected ('' disconnect -> NULL)
    share_threat_intel  boolean     NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),   -- returned as isoformat()+'Z' (auth_service.py:152)
    last_login          timestamptz,
    CONSTRAINT users_local_has_password
        CHECK (auth_provider <> 'local' OR password_hash IS NOT NULL),
    CONSTRAINT users_password_hash_argon2
        CHECK (password_hash IS NULL OR password_hash LIKE '$argon2%')
);
-- EmailIndex replacement. '' is excluded because a Google profile may lack
-- an email (auth_service.py:277).
CREATE UNIQUE INDEX users_email_uk ON users (lower(email)) WHERE email <> '';
CREATE INDEX users_telegram_chat_idx ON users (user_id) WHERE telegram_chat_id IS NOT NULL;
COMMENT ON TABLE users IS 'Accounts (local/Google/Telegram). Was DynamoDB waf_users.';
COMMENT ON COLUMN users.auth_provider IS 'Sign-up method; login_local() rejects non-local (auth_service.py:230).';

-- ProviderIndex replacement (auth_provider, provider_id)
CREATE TABLE user_identities (
    provider            text        NOT NULL CHECK (provider IN ('google', 'telegram')),
    provider_user_id    text        NOT NULL,   -- Google "sub" / Telegram numeric id as text
    user_id             uuid        NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    linked_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id),
    CONSTRAINT user_identities_one_per_provider UNIQUE (user_id, provider)
);
COMMENT ON TABLE user_identities IS 'OAuth/Telegram links; replaces waf_users.provider_id + ProviderIndex GSI.';

-- =====================================================================
-- 2. tenancy-edge-config
-- =====================================================================

-- waf_origins (origin_service.py:209-224,513-525; tunnel.py:85-89;
-- managed_rules.py:37-43,62; dynamodb_service.py:471-494)
CREATE TABLE origins (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id            uuid        NOT NULL REFERENCES users (user_id) ON DELETE RESTRICT,
    label                    text        NOT NULL,
    ip                       text        NOT NULL,   -- IP *or* hostname (validate_ip accepts domains)
    port                     integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    status                   text        NOT NULL DEFAULT 'pending'
                                         CHECK (status IN ('pending', 'active', 'archived', 'deleted')),
    connection_mode          text        CHECK (connection_mode IN ('direct', 'agent')),
    origin_scheme            text        CHECK (origin_scheme IN ('http', 'https')),
    is_tunnel                boolean     NOT NULL DEFAULT false,
    tunnel_name              text,
    tech_stack_tags          text[]      NOT NULL DEFAULT '{}',
    managed_ruleset_mode     text        NOT NULL DEFAULT 'auto'
                                         CHECK (managed_ruleset_mode IN ('auto', 'manual')),
    managed_ruleset_version  integer     CHECK (managed_ruleset_version >= 0),
    created_at               timestamptz NOT NULL DEFAULT now(),   -- returned as isoformat()+'Z' (origin_service.py:202)
    updated_at               timestamptz NOT NULL DEFAULT now(),
    archived_at              timestamptz,
    deleted_at               timestamptz
);
CREATE INDEX origins_admin_user_idx   ON origins (admin_user_id);           -- admin_user_id-index
CREATE INDEX origins_status_idx       ON origins (status);
CREATE INDEX origins_tunnel_name_idx  ON origins (lower(tunnel_name)) WHERE tunnel_name IS NOT NULL;
COMMENT ON TABLE origins IS 'Tenant unit (customer upstream). Was DynamoDB waf_origins; viewer/editor sets moved to origin_members, tunnel hosts to origin_tunnel_domains, agent token digest to origin_agent_credentials.';

-- waf_origins.tunnel_domains (list) -> one row per claimed host.
-- UNIQUE(domain_name) makes "one hostname, one tunnel owner" a database
-- rule (today two origins can store the same host and managed_ruleset
-- silently drops it). Clashes with another origin's domains.domain_name
-- still need the app check (api/tunnels.py _assert_domain_claimable).
CREATE TABLE origin_tunnel_domains (
    origin_id    uuid        NOT NULL REFERENCES origins (id) ON DELETE CASCADE,
    domain_name  text        NOT NULL CHECK (domain_name = lower(domain_name) AND domain_name <> ''),
    position     smallint    NOT NULL DEFAULT 0,      -- keeps the list order the agent sent
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin_id, domain_name),
    CONSTRAINT origin_tunnel_domains_domain_uk UNIQUE (domain_name)
);
COMMENT ON TABLE origin_tunnel_domains IS 'Hostnames an origin''s tunnel agent may bind. Replaced wholesale on token issue. Tunnel hosts have NO domains row.';

-- waf_origins.tunnel_token_hash / tunnel_token_issued_at. Separate table so
-- the digest never rides along in SELECT * FROM origins (GET /api/origins
-- returns it to viewers today).
CREATE TABLE origin_agent_credentials (
    origin_id   uuid        PRIMARY KEY REFERENCES origins (id) ON DELETE CASCADE,
    token_hash  text        NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),  -- sha256 hex, never the secret
    issued_at   timestamptz NOT NULL DEFAULT now(),   -- code writes epoch int; adapter converts
    issued_by   uuid        REFERENCES users (user_id) ON DELETE SET NULL
);
COMMENT ON TABLE origin_agent_credentials IS 'Tunnel agent credential digest per origin. Read only by the verify-agent path.';

-- waf_origins.viewer_user_ids / editor_user_ids (String Sets)
CREATE TABLE origin_members (
    origin_id   uuid        NOT NULL REFERENCES origins (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    role        text        NOT NULL CHECK (role IN ('viewer', 'editor')),
    granted_by  uuid        REFERENCES users (user_id) ON DELETE SET NULL,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    -- role is part of the key: the two DynamoDB sets were independent, so a
    -- user can hold both grants and revoking one must not drop the other.
    PRIMARY KEY (origin_id, user_id, role)
);
CREATE INDEX origin_members_user_idx ON origin_members (user_id);
COMMENT ON TABLE origin_members IS 'Per-origin sharing (Team Workspace). Owner stays origins.admin_user_id.';

-- waf_domains (domains.py:189-198,584-593; origin_service.py:541-550; domains.py:58-66)
CREATE TABLE domains (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_id           uuid        NOT NULL REFERENCES origins (id) ON DELETE CASCADE,
    domain_name         text        NOT NULL CHECK (domain_name = lower(domain_name) AND domain_name <> ''),
    verification_token  text        NOT NULL,   -- 'waf-token-<hex16>' or 'waf-tunnel-<hex12>'
    dns_verified        boolean     NOT NULL DEFAULT false,
    ssl_status          text        NOT NULL DEFAULT 'none'
                                    CHECK (ssl_status IN ('none', 'pending', 'active')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT domains_domain_name_uk UNIQUE (domain_name)               -- domain_name-index; UniqueViolation -> HTTP 400 as today
);
CREATE INDEX domains_origin_idx     ON domains (origin_id);              -- origin_id-index
CREATE INDEX domains_unverified_idx ON domains (created_at) WHERE NOT dns_verified;  -- dns_verification_worker.py:19
COMMENT ON TABLE domains IS 'BYO hostnames (CNAME+TXT verify). Was DynamoDB waf_domains.';

-- SQLite data/ip_rules.db : ip_rules (ip_rule_service.py:43-53)
CREATE TABLE ip_rules (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip          inet        NOT NULL,   -- adapter reads abbrev(ip) so hosts render without /32
    rule_type   text        NOT NULL DEFAULT 'block' CHECK (rule_type IN ('block', 'allow')),
    reason      text        NOT NULL DEFAULT 'Manual entry',
    added_by    text        NOT NULL DEFAULT 'admin',   -- username / literal, not an FK
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,                            -- NULL = permanent
    hits        integer     NOT NULL DEFAULT 0 CHECK (hits >= 0),
    source      text        NOT NULL DEFAULT 'manual'
                            CHECK (source IN ('manual', 'ml_analyst', 'rate_limit')),
    CONSTRAINT ip_rules_ip_uk UNIQUE (ip)
);
CREATE INDEX ip_rules_type_created_idx ON ip_rules (rule_type, created_at DESC);
CREATE INDEX ip_rules_expires_idx      ON ip_rules (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX ip_rules_ip_gist          ON ip_rules USING gist (ip inet_ops);  -- client_ip <<= ip lookups
COMMENT ON TABLE ip_rules IS 'Global IP/CIDR block/allow list rendered to ModSecurity conf. Was SQLite ip_rules.db.';

-- SQLite data/rate_limits.db : rate_rules (rate_limit_service.py:40-51)
CREATE TABLE rate_limit_rules (
    id              text        PRIMARY KEY,          -- 'rule_<hex8>' or seeded 'rule_auth_protect' etc.
    name            text        NOT NULL,
    path_pattern    text        NOT NULL,
    method          text        NOT NULL DEFAULT 'ALL' CHECK (method = upper(method)),  -- adapter upper()s on write
    limit_count     integer     NOT NULL CHECK (limit_count > 0),
    window_seconds  integer     NOT NULL CHECK (window_seconds > 0),
    burst           integer     NOT NULL DEFAULT 0 CHECK (burst >= 0),
    action          text        NOT NULL DEFAULT '429' CHECK (action IN ('429', 'temp_ban')),
    enabled         boolean     NOT NULL DEFAULT true,  -- API shape is int 1/0: adapter binds bool(), returns enabled::int
    created_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE rate_limit_rules IS 'Rate-limit rule definitions; counters stay in Redis rate:limit:{ip}. Was SQLite rate_limits.db.';

-- =====================================================================
-- 3. security-events
-- =====================================================================

-- waf_alerts_v2 (telegram_listener.py:166-186, dynamodb_service.py:163-195, ai_summary.py:341-364)
CREATE TABLE alerts (
    alert_id     text        PRIMARY KEY,   -- 'ALT-{epoch}-{hex}' or caller-supplied
    origin_id    uuid        REFERENCES origins (id) ON DELETE SET NULL,  -- NULL = 'unattributed' (admin-only)
    request_id   text,                      -- NEW: exact join to ClickHouse access_logs.request_id
    domain       text        NOT NULL DEFAULT '',   -- normalized Host, same as access_logs.host
    ip           text        NOT NULL,      -- may be 'unknown' (telegram_listener.py:119) -> not inet
    url          text        NOT NULL,
    status       text        NOT NULL,      -- HTTP status as string, e.g. '403'
    rule_id      text,                      -- ModSecurity rule id (not an FK)
    attack_type  text,
    severity     text,
    edge_node    text,
    ai_summary   text,
    message      text,
    created_at   timestamptz NOT NULL DEFAULT now(),   -- DynamoDB attr "timestamp" (isoformat()+'Z')
    is_read      boolean     NOT NULL DEFAULT false    -- DynamoDB attr "read"; global per alert
);
CREATE INDEX alerts_origin_created_idx ON alerts (origin_id, created_at DESC);
CREATE INDEX alerts_created_idx        ON alerts (created_at DESC);
CREATE INDEX alerts_unread_idx         ON alerts (origin_id) WHERE NOT is_read;
COMMENT ON TABLE alerts IS 'Blocked-request alerts with Gemini summary. Was DynamoDB waf_alerts_v2 (user_id column dropped; adapter still returns the constant default-user).';

-- waf_threat_patterns (threat_intel.py:103-133) split: counter row + SS of tenant hashes
CREATE TABLE threat_patterns (
    rule_id       text        NOT NULL,
    bucket_start  timestamptz NOT NULL,     -- hour bucket (was time_bucket 'YYYYMMDDHH', UTC)
    attack_type   text,
    hit_count     bigint      NOT NULL DEFAULT 0 CHECK (hit_count >= 0),
    updated_at    timestamptz NOT NULL DEFAULT now(),   -- returned as isoformat() '+00:00' (threat_intel.py:131)
    PRIMARY KEY (rule_id, bucket_start)     -- was pattern_key '{rule_id}#{YYYYMMDDHH}'
);
CREATE INDEX threat_patterns_bucket_idx ON threat_patterns (bucket_start);
COMMENT ON TABLE threat_patterns IS 'Opt-in community threat intel: hits per (rule, hour). No IP/URL/user id stored.';

CREATE TABLE threat_pattern_contributors (
    rule_id       text        NOT NULL,
    bucket_start  timestamptz NOT NULL,
    tenant_hash   text        NOT NULL CHECK (tenant_hash ~ '^[0-9a-f]{16}$'),  -- HMAC-SHA256(salt, user_id)[:16]
    PRIMARY KEY (rule_id, bucket_start, tenant_hash),
    FOREIGN KEY (rule_id, bucket_start)
        REFERENCES threat_patterns (rule_id, bucket_start) ON DELETE CASCADE
);
COMMENT ON TABLE threat_pattern_contributors IS 'Replaces the tenant_hashes String Set (ADD) of waf_threat_patterns.';

-- =====================================================================
-- 4. ml-rules-workflow
-- =====================================================================

-- waf_pending_rules (ml_rule_service.py:51-92,112-126,201-299)
CREATE TABLE pending_rules (
    rule_id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at        timestamptz NOT NULL DEFAULT now(),   -- returned as '%Y-%m-%dT%H:%M:%SZ' (ml_rule_service.py:49)
    status            text        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'approved', 'rejected')),
    pattern           text        NOT NULL DEFAULT '',
    variable          text        NOT NULL DEFAULT 'REQUEST_URI|REQUEST_BODY',
    attack_type       text        NOT NULL DEFAULT 'Anomaly',
    severity          text        NOT NULL DEFAULT 'CRITICAL',
    secrule_template  text        NOT NULL DEFAULT '',   -- contains '{RULE_ID}' placeholder
    source_url        text        NOT NULL DEFAULT '',
    source_method     text        NOT NULL DEFAULT 'GET',
    created_by        text        NOT NULL DEFAULT 'ml-auto',  -- 'ml-auto' | 'cve-auto' (literal, not FK)
    cve_id            text,                                  -- NULL for non-CVE ('' in old code)
    origin_id         uuid        REFERENCES origins (id) ON DELETE SET NULL,  -- NULL = not attributable
    origin_label      text        NOT NULL DEFAULT '',
    generator         text        NOT NULL DEFAULT 'rf-regex',  -- known: rf-regex | gen3-detector | cve
    detector          text        NOT NULL DEFAULT '',
    dedup_key         text,                                  -- NULL when '' in old code
    hit_count         integer     NOT NULL DEFAULT 1 CHECK (hit_count >= 1),
    examples          jsonb       NOT NULL DEFAULT '[]'::jsonb  -- newest <=5 {url, method, seen_at}
                                  CHECK (jsonb_typeof(examples) = 'array'),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    backtest          jsonb,                                 -- latest rule_backtest.run_backtest() result
    reviewed_by       text,                                  -- reviewer username (not FK)
    reviewed_at       timestamptz,
    deployed_rule_id  integer     CHECK (deployed_rule_id >= 1000500),  -- ModSecurity id -> ml-{id}.conf
    reject_reason     text,
    CONSTRAINT pending_rules_approved_has_deploy
        CHECK (status <> 'approved' OR (deployed_rule_id IS NOT NULL AND reviewed_at IS NOT NULL)),
    CONSTRAINT pending_rules_rejected_reviewed
        CHECK (status <> 'rejected' OR reviewed_at IS NOT NULL),
    -- Next id must be GREATEST(max id on disk, max(deployed_rule_id))+1 under
    -- pg_advisory_xact_lock: DELETE /api/rules can remove ml-{id}.conf without
    -- touching this row (api/rules.py:194-198), so a disk-only max would reuse it.
    CONSTRAINT pending_rules_deployed_uk UNIQUE (deployed_rule_id)
);
CREATE INDEX pending_rules_status_created_idx ON pending_rules (status, created_at DESC);  -- status-index
CREATE INDEX pending_rules_cve_idx ON pending_rules (cve_id) WHERE cve_id IS NOT NULL;
CREATE UNIQUE INDEX pending_rules_pending_dedup_uk ON pending_rules (dedup_key)
    WHERE status = 'pending' AND dedup_key IS NOT NULL;
CREATE INDEX pending_rules_origin_idx ON pending_rules (origin_id) WHERE origin_id IS NOT NULL;
COMMENT ON TABLE pending_rules IS 'ML / Gen3 / CVE auto-patch SecRule proposals awaiting admin review. Was DynamoDB waf_pending_rules.';

-- waf_threshold_proposals (threshold_proposal_service.py:163-181,209-316)
CREATE TABLE threshold_proposals (
    proposal_id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    status              text        NOT NULL DEFAULT 'pending'
                                    CHECK (status IN ('pending', 'approved', 'rejected', 'rolled_back')),
    current_threshold   integer     NOT NULL,
    proposed_threshold  integer     NOT NULL CHECK (proposed_threshold BETWEEN 3 AND 10),
    lookback_hours      integer     NOT NULL CHECK (lookback_hours > 0),
    reason              text        NOT NULL,
    evidence            jsonb       NOT NULL,   -- {blended_block_rate_pct, origins[], corroborating_origins[]}
    created_by          text        NOT NULL,   -- username or 'system' / 'ml-auto'
    created_at          timestamptz NOT NULL DEFAULT now(),   -- returned as '%Y-%m-%dT%H:%M:%SZ' (threshold_proposal_service.py:185)
    approved_by         text,
    approved_at         timestamptz,
    previous_threshold  integer,                -- live value at approval, used by rollback
    rejected_by         text,
    rejected_at         timestamptz,
    reject_reason       text,
    rolled_back_by      text,
    rolled_back_at      timestamptz,
    CONSTRAINT threshold_proposals_approved_fields
        CHECK (status NOT IN ('approved', 'rolled_back') OR approved_at IS NOT NULL),
    CONSTRAINT threshold_proposals_rejected_fields
        CHECK (status <> 'rejected' OR rejected_at IS NOT NULL),
    CONSTRAINT threshold_proposals_rolled_back_fields
        CHECK (status <> 'rolled_back' OR rolled_back_at IS NOT NULL)
);
CREATE INDEX threshold_proposals_status_idx ON threshold_proposals (status, created_at DESC);
COMMENT ON TABLE threshold_proposals IS 'Global anomaly-threshold change proposals (approve/reject/rollback). Was DynamoDB waf_threshold_proposals.';

-- waf_rules (misnomer) -> bola_policies (bola_guard.py:297-322,340-353)
CREATE TABLE bola_policies (
    id             text        PRIMARY KEY,                -- 'BOLA-NNN' or caller-supplied
    name           text        NOT NULL DEFAULT 'Custom BOLA Policy',
    path_pattern   text        NOT NULL CHECK (path_pattern <> ''),   -- regex
    claim_key      text        NOT NULL DEFAULT 'sub',
    resource_type  text        NOT NULL DEFAULT 'user_id',
    action         text        NOT NULL DEFAULT 'BLOCK' CHECK (action = upper(action)),
    allow_admin    boolean     NOT NULL DEFAULT true,
    description    text        NOT NULL DEFAULT '',
    enabled        boolean     NOT NULL DEFAULT true,
    methods        text[]      NOT NULL DEFAULT '{ALL}',
    priority       integer     NOT NULL DEFAULT 100,       -- NEW: used in memory, was never persisted
    updated_at     timestamptz NOT NULL DEFAULT now()      -- code writes epoch string str(int(time.time())) (bola_guard.py:311); adapter converts both ways
);
COMMENT ON TABLE bola_policies IS 'BOLA/IDOR guard policies. Was DynamoDB waf_rules (type=bola_policy); not ModSecurity rules.';

-- =====================================================================
-- 5. observability-ops
-- =====================================================================

-- waf_audit_log (audit_log.py:41-58). Append-only. Deliberately NO foreign
-- keys: origins and users are hard-deletable, and an FK action would need
-- UPDATE/DELETE rights the app role does not have.
CREATE TABLE audit_logs (
    event_id        text        PRIMARY KEY CHECK (event_id ~ '^[0-9]{20}#[0-9a-f]{8}$'),  -- '{epoch_ms:020d}#{hex8}'
    scope_id        text        NOT NULL
                                CHECK (scope_id = 'global'
                                       OR scope_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    occurred_at     timestamptz NOT NULL DEFAULT now(),   -- DynamoDB attr "timestamp": adapter returns it under key timestamp as isoformat() '+00:00' string
    actor_user_id   uuid,                                 -- logical ref users.user_id (no FK); returned as str
    actor_username  text        NOT NULL DEFAULT '',
    action          text        NOT NULL,                 -- e.g. origin.update, viewer.grant, editor.revoke, domain.create, domain.delete, rule.approve, rule.reject, cve_scan.run, settings.update
    summary         text        NOT NULL,
    details         jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_logs_scope_event_idx ON audit_logs (scope_id, event_id DESC);
CREATE INDEX audit_logs_scope_time_idx  ON audit_logs (scope_id, occurred_at);
CREATE INDEX audit_logs_occurred_idx    ON audit_logs (occurred_at);
COMMENT ON TABLE audit_logs IS 'Append-only change trail, written in the same transaction as the change (fail-closed). scope_id = origin uuid or ''global''.';

CREATE OR REPLACE FUNCTION audit_logs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'audit_logs is append-only (UPDATE refused)';
  ELSIF TG_OP = 'DELETE' THEN
    IF OLD.occurred_at > now() - interval '180 days' THEN
      RAISE EXCEPTION 'audit_logs rows younger than 180 days cannot be deleted';
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'audit_logs is append-only (TRUNCATE refused)';
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_guard();
CREATE TRIGGER audit_logs_retention_only BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_guard();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_guard();

-- waf_status_history (public_status.py:118-143,147-172)
CREATE TABLE status_history_days (
    component_id   text        NOT NULL CHECK (component_id = lower(component_id)),  -- region.lower() of PUBLIC_REGION_LABELS: 'th','asia','main' (public_status.py:40-44,62)
    date_bucket    date        NOT NULL,                   -- UTC day; adapter returns date_bucket::text 'YYYY-MM-DD'
    name           text        NOT NULL,
    sample_count   integer     NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    healthy_count  integer     NOT NULL DEFAULT 0 CHECK (healthy_count >= 0),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component_id, date_bucket),
    CONSTRAINT status_history_days_healthy_le_samples CHECK (healthy_count <= sample_count)
);
CREATE INDEX status_history_days_date_idx ON status_history_days (date_bucket);
COMMENT ON TABLE status_history_days IS 'Daily uptime counters per region for the public status page (INSERT .. ON CONFLICT DO UPDATE).';

-- waf_ssl_certs (ssl_cert_monitor.py:131-210). Keyed by hostname because
-- tunnel hostnames have no domains row; deliberately no FK.
CREATE TABLE ssl_certificates (
    hostname         text        PRIMARY KEY CHECK (hostname = lower(hostname)),  -- was id = domain
    status           text        NOT NULL CHECK (status IN ('ok', 'error')),
    checked_at       timestamptz NOT NULL,
    not_after        timestamptz,
    issuer           text,
    days_remaining   integer,
    error            text,
    last_alerted_at  timestamptz,   -- returned as isoformat() '+00:00'; read back with fromisoformat (ssl_cert_monitor.py:190)
    CONSTRAINT ssl_certificates_ok_has_expiry CHECK (status <> 'ok' OR not_after IS NOT NULL)
);
CREATE INDEX ssl_certificates_not_after_idx ON ssl_certificates (not_after);
COMMENT ON TABLE ssl_certificates IS 'Last TLS probe per hostname (BYO + tunnel) and last Telegram expiry warning.';

-- waf_postmortems (ai_summary.py:506-524,548-583)
CREATE TABLE postmortems (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_id              uuid        NOT NULL REFERENCES origins (id) ON DELETE CASCADE,
    origin_label           text        NOT NULL DEFAULT '',   -- snapshot at generation time
    created_by             uuid        REFERENCES users (user_id) ON DELETE SET NULL,
    created_by_username    text        NOT NULL DEFAULT '',
    created_at             timestamptz NOT NULL DEFAULT now(),
    start_time             timestamptz NOT NULL,   -- code sends naive UTC '%Y-%m-%d %H:%M:%S' (ai_summary.py:470-471); adapter binds AT TIME ZONE 'UTC' and returns the same format
    end_time               timestamptz NOT NULL,
    stats                  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    hourly_buckets         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    audit_events           jsonb       NOT NULL DEFAULT '[]'::jsonb,  -- snapshot of audit_logs rows (string timestamps only)
    ai_narrative           text,
    ai_narrative_degraded  boolean     NOT NULL DEFAULT false,
    CONSTRAINT postmortems_time_order CHECK (start_time <= end_time)
);
CREATE INDEX postmortems_origin_created_idx ON postmortems (origin_id, created_at DESC);
COMMENT ON TABLE postmortems IS 'AI incident postmortem reports per origin. Was DynamoDB waf_postmortems.';

-- =====================================================================
-- 6. Views
-- =====================================================================

-- One place to resolve a Host header (ClickHouse access_logs.host /
-- shield_events.host / alerts.domain) to an origin: BYO domains + tunnel
-- domains. Mirrors domains.py:315-357 and managed_ruleset.py:270-301.
-- NOTE: includes UNVERIFIED BYO domains. The managed hostmap and the SSL
-- allow-list MUST add WHERE dns_verified (managed_ruleset.py:281,
-- domains.py:344-347); threat_intel owner map deliberately does not.
CREATE VIEW origin_hostnames AS
SELECT d.domain_name AS hostname, d.origin_id, 'byo'::text AS source,
       d.dns_verified, o.status AS origin_status
FROM domains d
JOIN origins o ON o.id = d.origin_id
UNION ALL
SELECT t.domain_name AS hostname, o.id AS origin_id, 'tunnel'::text AS source,
       true AS dns_verified, o.status AS origin_status
FROM origin_tunnel_domains t
JOIN origins o ON o.id = t.origin_id;
COMMENT ON VIEW origin_hostnames IS 'Host -> origin mapping for BYO and tunnel hostnames. Includes unverified BYO domains: hostmap and SSL allow-list consumers must filter on dns_verified.';

-- =====================================================================
-- 7. Retention (replaces DynamoDB TTL expires_at)
-- =====================================================================
CREATE OR REPLACE FUNCTION run_retention(
    audit_days           integer DEFAULT 180,   -- audit_log.py:21
    threat_hours         integer DEFAULT 72,    -- threat_intel.py:55 THREAT_INTEL_RETENTION_HOURS
    history_days integer DEFAULT 400    -- public_status.py:34 STATUS_HISTORY_RETENTION_DAYS
) RETURNS TABLE (table_name text, deleted bigint)
LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  DELETE FROM waf.audit_logs WHERE occurred_at < now() - make_interval(days => audit_days);
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'audit_logs'; deleted := n; RETURN NEXT;

  DELETE FROM waf.threat_patterns WHERE bucket_start < now() - make_interval(hours => threat_hours);
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'threat_patterns'; deleted := n; RETURN NEXT;

  DELETE FROM waf.status_history_days WHERE date_bucket < current_date - history_days;
  GET DIAGNOSTICS n = ROW_COUNT; table_name := 'status_history_days'; deleted := n; RETURN NEXT;

  -- ip_rules expiry is NOT done here: the app's retention worker deletes
  -- expired rows AND re-renders the ModSecurity block/allow files, which
  -- the database cannot do.
END
$$;
COMMENT ON FUNCTION run_retention(integer, integer, integer) IS 'Run hourly as waf_maintenance (backend worker or pg_cron).';

-- =====================================================================
-- 8. Grants
-- =====================================================================
REVOKE ALL ON SCHEMA waf FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA waf FROM PUBLIC;
REVOKE ALL ON FUNCTION run_retention(integer, integer, integer) FROM PUBLIC;

GRANT USAGE ON SCHEMA waf TO waf_app, waf_maintenance;

-- App role: full DML on operational tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    users, user_identities, origins, origin_members, origin_tunnel_domains,
    origin_agent_credentials, domains,
    ip_rules, rate_limit_rules,
    alerts, threat_patterns, threat_pattern_contributors,
    pending_rules, threshold_proposals, bola_policies,
    status_history_days, ssl_certificates, postmortems
TO waf_app;
GRANT SELECT ON origin_hostnames TO waf_app;
-- Audit log: append + read only.
GRANT SELECT, INSERT ON audit_logs TO waf_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA waf TO waf_app;  -- ip_rules identity
-- Sequences created by later migrations (run as the schema owner) too.
ALTER DEFAULT PRIVILEGES IN SCHEMA waf GRANT USAGE, SELECT ON SEQUENCES TO waf_app;

-- Maintenance role: retention deletes only.
GRANT SELECT, DELETE ON audit_logs, threat_patterns, threat_pattern_contributors,
    status_history_days TO waf_maintenance;
GRANT EXECUTE ON FUNCTION run_retention(integer, integer, integer) TO waf_maintenance;
