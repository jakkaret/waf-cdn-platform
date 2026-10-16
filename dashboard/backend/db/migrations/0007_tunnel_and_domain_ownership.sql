-- Phase 3 of the remediation plan (security audit run 1).

-- P3.3 (N5/H67/H68): one spelling per hostname. services/hostnames.py
-- canonical_host() lowercases, drops a trailing dot and checks the DNS shape;
-- the database refuses anything else, so no path can store a variant.
ALTER TABLE waf.domains ADD CONSTRAINT domains_domain_name_canonical
    CHECK (domain_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
           AND length(domain_name) <= 253);
ALTER TABLE waf.origin_tunnel_domains ADD CONSTRAINT origin_tunnel_domains_domain_name_canonical
    CHECK (domain_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
           AND length(domain_name) <= 253);

-- P3.5 (C4/H40): an unverified row no longer reserves a name. Only a
-- DNS-verified row is unique; verifying claims the name (and drops the
-- other unverified rows for it) in one transaction, see
-- PgStore.claim_verified_domain(). One origin still holds a name once.
ALTER TABLE waf.domains DROP CONSTRAINT domains_domain_name_uk;
CREATE UNIQUE INDEX domains_verified_name_uk ON waf.domains (domain_name) WHERE dns_verified;
CREATE UNIQUE INDEX domains_origin_name_uk ON waf.domains (origin_id, domain_name);
CREATE INDEX domains_name_idx ON waf.domains (domain_name);

-- P3.1 (N1/H66): who opened each FRP proxy, recorded by the NewProxy hook
-- from the tunnel token that opened it. Replaces an unbounded in-memory map
-- that a restart emptied. A deleted user's rows go with them.
CREATE TABLE waf.tunnel_proxy_owners (
    proxy_name   text        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES waf.users (user_id) ON DELETE CASCADE,
    domain_name  text        NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tunnel_proxy_owners_user_idx ON waf.tunnel_proxy_owners (user_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON waf.tunnel_proxy_owners TO waf_app;
