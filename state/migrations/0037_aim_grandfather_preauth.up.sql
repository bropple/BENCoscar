-- BENCO one-time grandfather for AIM consensual buddy connections.
--
-- Before this fork, AIM<->AIM buddy adds were silent and unilateral: no
-- authorization flow existed for AIM, so every existing AIM buddy edge is, by
-- definition, an already-accepted relationship. Turning on AIM authorization
-- (feedbag UpsertItem aim->aim case + icbm ChannelMsgToHost gate) must NOT
-- retroactively wall those off, which would lock existing accounts out of both
-- presence and messaging with contacts they already have.
--
-- So seed the pre-authorization store (contactPreauth, the exact table
-- RequiresAuthorization consults) from every existing AIM buddy edge, in BOTH
-- directions, so each pre-existing relationship counts as fully authorized both
-- ways. This is a one-time data seed; it does not run again.
--
-- Scope and safety:
--   * Only pure AIM<->AIM edges (both ends isICQ = 0). ICQ already ran the real
--     authorization flow, so its contactPreauth rows are already correct and
--     must not be widened here.
--   * feedbag.name is normalized to ident form (lowercase, spaces removed) to
--     match state.NewIdentScreenName; feedbag.screenName is already ident form.
--   * The JOINs to users drop edges whose buddy is not a registered account
--     (RequiresAuthorization returns "not required" for a non-user owner anyway,
--     and the FK on contactPreauth would reject such a row).
--   * authPending = 0 excludes not-yet-authorized rows.
--   * INSERT OR IGNORE keeps it idempotent and collision-free.

-- Direction 1: (owner = buddy, authorized = list owner)
-- Lets the list owner add / message the buddy without a fresh prompt.
INSERT OR IGNORE INTO contactPreauth (ownerScreenName, authorizedScreenName, createdAt)
SELECT LOWER(REPLACE(f.name, ' ', '')), f.screenName, UNIXEPOCH()
FROM feedbag f
JOIN users owner ON owner.identScreenName = f.screenName
JOIN users buddy ON buddy.identScreenName = LOWER(REPLACE(f.name, ' ', ''))
WHERE f.classID = 0
  AND f.authPending = 0
  AND owner.isICQ = 0
  AND buddy.isICQ = 0;

-- Direction 2: (owner = list owner, authorized = buddy)
-- Lets the buddy add / message the list owner back.
INSERT OR IGNORE INTO contactPreauth (ownerScreenName, authorizedScreenName, createdAt)
SELECT f.screenName, LOWER(REPLACE(f.name, ' ', '')), UNIXEPOCH()
FROM feedbag f
JOIN users owner ON owner.identScreenName = f.screenName
JOIN users buddy ON buddy.identScreenName = LOWER(REPLACE(f.name, ' ', ''))
WHERE f.classID = 0
  AND f.authPending = 0
  AND owner.isICQ = 0
  AND buddy.isICQ = 0;
