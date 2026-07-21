-- Drops the retained identity backups.
--
-- This throws away the only record of identity keys that have been superseded.
-- The CURRENT backup of each account is untouched and lives in
-- keyDirIdentityBackups, so nothing in normal operation breaks -- but any
-- account whose identity was overwritten before this runs loses the last means
-- of getting the old one back.
--
-- Take a copy first if any account is mid-recovery.
DROP INDEX IF EXISTS idx_keyDirIdentityBackupHistory_account;

DROP TABLE IF EXISTS keyDirIdentityBackupHistory;
