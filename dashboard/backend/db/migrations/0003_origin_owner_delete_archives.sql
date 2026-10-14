-- Deleting a user who still owns origins archives those origins (owner's
-- decision 2026-10-15) instead of being refused (0001's ON DELETE RESTRICT).
-- AuthService.delete_user archives the user's origins and deletes the user in
-- one transaction; the foreign key then clears admin_user_id. An origin may
-- be ownerless only while archived, so a live origin always has an owner.
ALTER TABLE waf.origins ALTER COLUMN admin_user_id DROP NOT NULL;
ALTER TABLE waf.origins DROP CONSTRAINT origins_admin_user_id_fkey;
ALTER TABLE waf.origins
    ADD CONSTRAINT origins_admin_user_id_fkey
        FOREIGN KEY (admin_user_id) REFERENCES waf.users (user_id) ON DELETE SET NULL;
ALTER TABLE waf.origins
    ADD CONSTRAINT origins_owner_unless_archived
        CHECK (admin_user_id IS NOT NULL OR status = 'archived');
