package state

// BENCO addition. Nothing in this file exists upstream.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrDatabaseMissing is returned by RequireExistingDB when the database file
// the operator said would be there is not there.
var ErrDatabaseMissing = errors.New("database file does not exist")

// RequireExistingDB reports whether the SQLite database at dbFilePath already
// exists, and returns ErrDatabaseMissing if it does not.
//
// BENCO: NewSQLiteUserStore opens SQLite and runs migrations, so a missing file
// is silently created as a fresh, fully-migrated, empty database. That is right
// on first run and dangerous every time after. The motivating case is a data
// volume that fails to mount (see docs/at-rest-encryption.md section 6): the
// mountpoint is left as an empty directory, SQLite creates a new database in
// it, the server starts healthy with no accounts, the first sign-on is told the
// password is wrong, and the next backup overwrites a good file with the empty
// one. Nothing errors anywhere along that path. This applies to any failed
// mount, encrypted or not.
//
// Call this BEFORE NewSQLiteUserStore, since sql.Open is what creates the file.
func RequireExistingDB(dbFilePath string) error {
	_, err := os.Stat(dbFilePath)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: expected a SQLite database at %q, and DB_REQUIRE_EXISTING "+
			"is set, so the server will not create one. The likeliest cause is a data volume "+
			"that failed to mount, leaving an empty directory where the database should be -- "+
			"check the mount before doing anything else, because starting without it would "+
			"come up with no accounts and let a backup overwrite the real database. If this "+
			"really is a first run, create the database with DB_REQUIRE_EXISTING unset",
			ErrDatabaseMissing, dbFilePath)
	default:
		return fmt.Errorf("cannot stat database file %q: %w", dbFilePath, err)
	}
}
