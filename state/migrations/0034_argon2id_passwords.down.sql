-- Restores upstream's credential columns.
--
-- This recovers the SCHEMA only. The MD5 values themselves cannot be recovered
-- from an argon2id hash, so every account comes back with empty credentials and
-- must have its password reset through the management API before it can sign in
-- again -- exactly as when migrating up.
--
-- Rolling back therefore does not restore access; it restores the ability to run
-- upstream's code against this database.

ALTER TABLE users
    ADD COLUMN authKey TEXT;

ALTER TABLE users
    ADD COLUMN weakMD5Pass TEXT;

ALTER TABLE users
    ADD COLUMN strongMD5Pass TEXT;

ALTER TABLE users
    DROP COLUMN passwordHash;
