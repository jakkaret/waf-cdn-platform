-- H28/H31: server-side session revocation. Every dashboard session JWT carries
-- the user's token_version ("tv"); logout and role changes bump it, so tokens
-- issued before that stop working at once instead of living until they expire.
-- Tokens without "tv" (issued before this migration) count as version 0.
ALTER TABLE waf.users ADD COLUMN token_version integer NOT NULL DEFAULT 0;
