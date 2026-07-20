-- BENCO: down migration for the one-time AIM grandfather seed.
--
-- This is intentionally a no-op. The up migration seeds contactPreauth rows that
-- are indistinguishable from rows a user later creates organically by accepting
-- an authorization request. Deleting "the grandfathered rows" cannot be done
-- without also destroying legitimately granted authorizations, which would be
-- worse than leaving the seed in place. contactPreauth is additive, idempotent
-- data; carrying an extra pre-authorization across a rollback is harmless.
SELECT 1;
