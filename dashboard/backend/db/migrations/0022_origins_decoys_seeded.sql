-- Default-on universal decoy paths for NEW origins (2026-10-27). When an
-- origin first becomes active with a verified host, the managed-ruleset worker
-- turns on the universal decoys (.env, .git, .aws/credentials, *.sql,
-- config.php.bak, server-status) once -- paths no real site serves, so it is a
-- safe baseline the owner can switch off. decoys_seeded records that this
-- one-time seeding already ran, so it never re-adds a decoy the owner removed.
--
-- Every origin that exists today is marked seeded, so this only affects origins
-- created after this migration -- it does not switch on rules for customers'
-- existing sites behind their back.
ALTER TABLE waf.origins ADD COLUMN decoys_seeded boolean NOT NULL DEFAULT false;
UPDATE waf.origins SET decoys_seeded = true;
