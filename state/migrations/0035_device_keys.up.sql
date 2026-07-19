-- BENCO: the device key directory (foodgroup 0xBE00).
--
-- Replaces publishing end-to-end encryption keys inside the Locate profile text,
-- which meant keys could only be read for an ONLINE user, a client could not see
-- its own other devices, and "remove device" did not stick.
--
-- boxKey is the device identity: the X25519 public key messages are sealed to.
-- signKey is the Ed25519 key that attributes chat-room messages to a sender, and
-- is nullable because a client may not have generated one.
--
-- revokedAt is the load-bearing column. Removing a device does NOT delete the
-- row, because the removed machine keeps its keypair and republishes on its next
-- sign-on -- without a record that the key was revoked it silently returns and
-- removal means nothing. A tombstoned key is refused on publish and reported
-- back to the client, which surfaces it for approval rather than accepting it.
--
-- Only public keys are stored here. The server never sees a private key or a
-- plaintext message body, and nothing in this table would help it if it did.

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

-- Queries are always "the active devices for one account", which is the common
-- read path on every sign-on and every conversation opened with a new peer.
CREATE INDEX IF NOT EXISTS idx_deviceKeys_active
    ON deviceKeys (identScreenName, revokedAt);
