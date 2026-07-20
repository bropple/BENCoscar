-- BENCO: key directory v2 -- signed device manifests (foodgroup 0xBE00).
--
-- v1 stored a bare list of device keys and made the SERVER the authority over
-- which devices an account has, with removal implemented as a tombstone column.
-- That left a gap no client could close: the server could insert a device, omit
-- one, or serve an older list, and every one of those looked identical to the
-- truth from the outside.
--
-- v2 stores a MANIFEST instead: the whole device set as one statement, signed by
-- an account identity key the server never holds. The server keeps bytes it
-- cannot forge and a signature it can only check, not produce.
--
-- Removal stops being a database concept. Under v2, removing a device means the
-- client publishes a manifest without it at a higher counter, and clients refuse
-- any manifest below the highest counter they have seen. So there is no
-- revokedAt column here and no tombstone table -- the counter does that job, and
-- unlike a tombstone it does not require trusting the server to honour it.

-- DESTRUCTIVE, DELIBERATELY. This drops every v1 device key.
--
-- Do not read this as a pattern to copy. It was acceptable here for one reason
-- that will not be true again: no account outside the owner's own test accounts
-- had ever published a key, and there is a script to wipe the database
-- (scripts/benco-deploy/reset-db.sh). There was no user data to migrate, so
-- carrying both formats through a flag day would have been more risk than the
-- cutover it avoided.
--
-- Nothing is lost that cannot be regenerated: every device still holds its own
-- keypair. What is lost is the revocation tombstones, which v2 does not have a
-- use for anyway.
DROP INDEX IF EXISTS idx_deviceKeys_active;

DROP TABLE IF EXISTS deviceKeys;

-- One manifest per account -- hence identScreenName as the primary key rather
-- than a row per device. Publishing replaces the whole thing, because the whole
-- thing is what was signed.
--
-- manifest is the load-bearing column, and it is stored EXACTLY as received. It
-- is never decoded and re-encoded, because signature holds over those precise
-- bytes and any encoding difference -- a field order, a padding choice, a
-- length-prefix width -- would invalidate it for every client that fetched it
-- afterwards. The failure would surface as a signature mismatch on the client,
-- a long way from the server that caused it.
--
-- identityAlg, identityKey, counter and issuedAt are DENORMALISED out of the
-- manifest blob. They are copies, not the source of truth: the signed bytes are.
-- They exist because the server has to compare the incoming counter and identity
-- against the stored ones on every publish, and decoding a blob to do it would
-- mean parsing untrusted data on the hot path for values that never change once
-- written.
--
-- counter is INTEGER, which SQLite stores signed. The protocol field is uint64,
-- so the storage layer refuses anything above the signed maximum rather than
-- letting it wrap into a negative that would compare backwards and silently
-- break the rollback defence.
CREATE TABLE IF NOT EXISTS keyDirManifests
(
    identScreenName TEXT    NOT NULL,
    identityAlg     INTEGER NOT NULL,
    identityKey     BLOB    NOT NULL,
    counter         INTEGER NOT NULL,
    issuedAt        INTEGER NOT NULL,
    manifest        BLOB    NOT NULL,
    sigAlg          INTEGER NOT NULL,
    signature       BLOB    NOT NULL,
    PRIMARY KEY (identScreenName),
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

-- The encrypted account identity key, one per account.
--
-- The identity private key is held only transiently by a client -- fetched,
-- used to sign a manifest, discarded -- so it has to survive somewhere between
-- uses, and the server is the only place available. It is stored encrypted under
-- a key derived from a generated recovery phrase. The server never sees the
-- phrase, never sees the derived key, and cannot derive either.
--
-- kdf, params and salt are stored alongside the blob rather than assumed,
-- so argon2id's work factor can be raised later without stranding backups made
-- under the old parameters. Hardcoding them server-side would mean every change
-- required re-encrypting every existing blob, which in practice means the
-- parameters never get raised at all.
--
-- What this table gives an attacker who reads the database: a ciphertext they
-- can attack offline with no rate limiting. That is why the recovery phrase is
-- generated rather than user-chosen -- roughly 110 bits from a word list wins
-- that fight and a human-chosen passphrase does not -- and why GetBackup is
-- scoped to the session's own account with no field to name another.
--
-- Absence is meaningful, not just empty. No row means the account has never
-- bootstrapped an identity, which is what tells a client it is in the first-run
-- flow. No separate "has signed in" flag is needed.
CREATE TABLE IF NOT EXISTS keyDirIdentityBackups
(
    identScreenName TEXT    NOT NULL,
    kdf             INTEGER NOT NULL,
    params          BLOB    NOT NULL,
    salt            BLOB    NOT NULL,
    blob            BLOB    NOT NULL,
    updatedAt       INTEGER NOT NULL,
    PRIMARY KEY (identScreenName),
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);
