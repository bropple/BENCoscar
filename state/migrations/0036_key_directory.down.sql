-- Rolls key directory v2 back to v1's empty table.
--
-- This loses every published manifest and every encrypted identity backup. The
-- manifests are recoverable: a client re-signs and republishes, since each still
-- holds its own device keys. The BACKUPS ARE NOT. Dropping that table destroys
-- the only copy of each account's encrypted identity key, and a client under
-- transient custody does not keep a plaintext one -- so every account whose
-- backup is dropped here can no longer sign a new manifest, which means no
-- device can ever be added or removed from it again. Existing devices keep
-- working; the account is simply frozen as it stands.
--
-- Recovering from that means destroying the identity and bootstrapping a new
-- one, which changes the safety number for every contact. Take a copy of
-- keyDirIdentityBackups before running this on anything that matters.
--
-- deviceKeys is recreated EMPTY, matching 0035. The v1 keys the up migration
-- dropped are gone and this does not bring them back; clients republish their
-- own on next sign-on. The revocation tombstones are gone for good, so any
-- device previously removed under v1 becomes publishable again.

DROP TABLE IF EXISTS keyDirIdentityBackups;

DROP TABLE IF EXISTS keyDirManifests;

CREATE TABLE IF NOT EXISTS deviceKeys
(
    identScreenName TEXT    NOT NULL,
    boxKey          BLOB    NOT NULL,
    signKey         BLOB,
    publishedAt     INTEGER NOT NULL,
    revokedAt       INTEGER,
    PRIMARY KEY (identScreenName, boxKey),
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_deviceKeys_active
    ON deviceKeys (identScreenName, revokedAt);
