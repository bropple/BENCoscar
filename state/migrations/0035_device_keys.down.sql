-- Drops the device key directory.
--
-- Rolling this back loses every published device key and every revocation
-- tombstone. Clients recover the keys on their next publish, since each device
-- holds its own keypair -- but the tombstones are gone for good, so any device
-- previously removed becomes publishable again and will silently return.

DROP INDEX IF EXISTS idx_deviceKeys_active;

DROP TABLE IF EXISTS deviceKeys;
