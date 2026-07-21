-- BENCO: retain superseded identity backups.
--
-- keyDirIdentityBackups is written with REPLACE INTO, so storing a backup
-- destroys the previous one with no record that it existed. That is the right
-- shape for the operation it was built for -- re-keying, where the same identity
-- private key is simply re-wrapped under a new recovery phrase -- but it is also
-- reachable by anyone holding the account password, and the blob it overwrites
-- is the ONLY copy of the account's identity key. Clients hold that key only
-- transiently: fetched, used to sign a manifest, discarded.
--
-- So a single write by a password-holder permanently destroys an account's
-- identity. Every existing device keeps working, but no manifest can ever be
-- signed again, which means no device can be added or removed for the life of
-- the account. Recovering means bootstrapping a new identity, which moves the
-- safety number for every contact.
--
-- This table keeps the superseded rows so that outcome is recoverable by an
-- operator with database access. It does NOT prevent the overwrite: the server
-- cannot tell a legitimate re-key from a hostile replacement, because both are
-- opaque ciphertext arriving on an authenticated session, and what actually
-- distinguishes them is whether the manifests that follow are signed by the same
-- identity key. Prevention belongs in the client's warning path, not here.
--
-- What an attacker who reads the database gains: older ciphertexts of the same
-- identity key under OLDER recovery phrases. That is a real widening -- a phrase
-- retired precisely because it may have been seen is still a phrase that opens a
-- row here -- and it is the reason for the retention cap rather than keeping
-- every version forever. The blobs remain argon2id-wrapped under generated
-- ~110-bit phrases, which is the same fight the live table already presents.
--
-- Absence of history is normal: an account that has never re-keyed has no rows.
CREATE TABLE IF NOT EXISTS keyDirIdentityBackupHistory
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    identScreenName TEXT    NOT NULL,
    kdf             INTEGER NOT NULL,
    params          BLOB    NOT NULL,
    salt            BLOB    NOT NULL,
    blob            BLOB    NOT NULL,
    -- updatedAt is when the superseded row was WRITTEN; supersededAt is when it
    -- was replaced. Both matter when reconstructing what happened and when.
    updatedAt       INTEGER NOT NULL,
    supersededAt    INTEGER NOT NULL,
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_keyDirIdentityBackupHistory_account
    ON keyDirIdentityBackupHistory (identScreenName, supersededAt DESC);
