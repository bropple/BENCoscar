package state

// BENCO addition. Nothing in this file exists upstream.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequireExistingDB(t *testing.T) {
	t.Run("refuses a database that does not exist", func(t *testing.T) {
		// Simulates the motivating failure: a data volume that did not mount,
		// leaving an empty directory where the database should be.
		emptyMountpoint := t.TempDir()
		missing := filepath.Join(emptyMountpoint, "oscar.sqlite")

		err := RequireExistingDB(missing)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrDatabaseMissing)
		// The error has to name the path, or an operator cannot tell which
		// mount failed.
		assert.Contains(t, err.Error(), missing)
		// ...and nothing may have been created by the check itself.
		_, statErr := os.Stat(missing)
		assert.True(t, errors.Is(statErr, os.ErrNotExist))
	})

	t.Run("permits a database that exists", func(t *testing.T) {
		dir := t.TempDir()
		present := filepath.Join(dir, "oscar.sqlite")

		store, err := NewSQLiteUserStore(present)
		assert.NoError(t, err)
		assert.NotNil(t, store)

		assert.NoError(t, RequireExistingDB(present))
	})

	t.Run("permits an existing but empty file", func(t *testing.T) {
		// The guard is about existence, not contents. A zero-byte file is a
		// mounted volume as far as this check is concerned; migrations then
		// run over it exactly as they do today.
		dir := t.TempDir()
		present := filepath.Join(dir, "oscar.sqlite")
		f, err := os.Create(present)
		assert.NoError(t, err)
		assert.NoError(t, f.Close())

		assert.NoError(t, RequireExistingDB(present))
	})
}
