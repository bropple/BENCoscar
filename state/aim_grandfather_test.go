package state

// BENCO: verifies migration 0037 grandfathers pre-existing AIM buddy
// relationships into the pre-authorization store, in both directions, without
// widening ICQ or pending relationships. A wrong migration here would lock
// existing accounts out of messaging each other once AIM authorization is on,
// so this is a load-bearing test.

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestMigration0037_GrandfatherAIMPreauth(t *testing.T) {
	const dbFile = "aim_grandfather_test.db"
	ctx := context.Background()
	defer func() { assert.NoError(t, os.Remove(dbFile)) }()

	// NewSQLiteUserStore runs every migration, including 0037, on the (empty)
	// DB. With no feedbag rows yet it seeds nothing, which lets us insert the
	// "pre-existing" relationships below and then re-run the 0037 SQL to prove
	// it grandfathers them.
	f, err := NewSQLiteUserStore(dbFile)
	require.NoError(t, err)

	alice := NewIdentScreenName("alice")
	bob := NewIdentScreenName("bob")
	carol := NewIdentScreenName("carol")
	icq := NewIdentScreenName("123456")

	// AIM accounts (isICQ=false). authRequired defaults to true (migration 0028).
	for _, sn := range []IdentScreenName{alice, bob, carol} {
		require.NoError(t, f.InsertUser(ctx, User{
			IdentScreenName:   sn,
			DisplayScreenName: DisplayScreenName(sn.String()),
		}))
	}
	// An ICQ account, to prove aim→icq edges are NOT grandfathered here.
	require.NoError(t, f.InsertUser(ctx, User{
		IdentScreenName:   icq,
		DisplayScreenName: DisplayScreenName("123456"),
		IsICQ:             true,
	}))

	// alice's pre-existing buddy list: bob (aim→aim, accepted), the ICQ user
	// (aim→icq), and carol added but still pending (unauthorized).
	require.NoError(t, f.FeedbagUpsert(ctx, alice, []wire.FeedbagItem{
		{GroupID: 1, ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
		{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "123456"},
		{GroupID: 1, ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, Name: "carol",
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}),
			}}},
	}))

	// Before grandfathering: every add still requires authorization.
	requires := func(owner, requester IdentScreenName) bool {
		blocked, err := f.RequiresAuthorization(ctx, owner, requester)
		require.NoError(t, err)
		return blocked
	}
	require.True(t, requires(bob, alice), "precondition: bob→alice needs auth")
	require.True(t, requires(alice, bob), "precondition: alice→bob needs auth")

	// Re-run the actual migration 0037 SQL against the seeded DB.
	sqlBytes, err := os.ReadFile("migrations/0037_aim_grandfather_preauth.up.sql")
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, string(sqlBytes))
	require.NoError(t, err)

	// The aim→aim relationship is now authorized in BOTH directions.
	assert.False(t, requires(bob, alice), "alice may add/message bob")
	assert.False(t, requires(alice, bob), "bob may add/message alice")

	// The aim→icq edge is left to ICQ's own flow (not grandfathered).
	assert.True(t, requires(icq, alice), "aim→icq must not be grandfathered")
	assert.True(t, requires(alice, icq), "icq→aim must not be grandfathered")

	// A pending (unauthorized) edge is excluded from grandfathering.
	assert.True(t, requires(carol, alice), "pending alice→carol must stay unauthorized")
	assert.True(t, requires(alice, carol), "pending carol→alice must stay unauthorized")
}
