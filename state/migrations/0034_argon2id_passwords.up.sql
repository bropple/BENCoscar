-- BENCO: replace the MD5 password equivalents with a single argon2id hash.
--
-- authKey/weakMD5Pass/strongMD5Pass existed to support BUCP challenge-response,
-- which requires the server to reproduce the hash the client computes. That
-- makes the stored values password *equivalents*: sufficient to sign in with,
-- so a stolen database is a stolen set of credentials. This fork drops BUCP
-- (see CLAUDE.md), which removes the only reason to keep them.
--
-- MIGRATION IS ONE-WAY AND LOSES CREDENTIALS. An argon2id hash cannot be derived
-- from an MD5 one -- that is the entire point of a one-way function -- so
-- existing rows get a NULL passwordHash and CANNOT SIGN IN until their password
-- is reset:
--
--     PUT /user/password   {"screen_name": "...", "password": "..."}
--
-- on the management API. This is deliberate rather than a gap: the alternative
-- is retaining the MD5 columns as a fallback, which would preserve exactly the
-- exposure this migration exists to remove.

ALTER TABLE users
    ADD COLUMN passwordHash TEXT;

ALTER TABLE users
    DROP COLUMN strongMD5Pass;

ALTER TABLE users
    DROP COLUMN weakMD5Pass;

ALTER TABLE users
    DROP COLUMN authKey;
