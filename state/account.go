package state

import (
	"context"
)

// CreateAccountFunc creates a new user account in the database.
//
// Possible errors:
//   - ErrAIMHandleInvalidFormat: screen name doesn't start with a letter, ends with a space, or contains invalid
//     characters
//   - ErrAIMHandleLength: screen name has less than 3 non-space characters or more than 16 characters
//   - ErrICQUINInvalidFormat: UIN is not a number or is not in the valid range (10000-2147483646)
//   - ErrPasswordInvalid: password length is invalid (AIM: 4-16 chars, ICQ: 6-8 chars)
//   - ErrDupUser: a user with the same screen name already exists
//   - Other errors from the underlying user store (e.g., database errors)
type CreateAccountFunc func(ctx context.Context, screenName DisplayScreenName, password string) error

// NewAccountCreator returns an account creation function.
func NewAccountCreator(insertUser func(ctx context.Context, u User) error) CreateAccountFunc {
	return func(ctx context.Context, screenName DisplayScreenName, password string) error {
		if screenName.IsUIN() {
			if err := screenName.ValidateUIN(); err != nil {
				return err
			}
		} else {
			if err := screenName.ValidateAIMHandle(); err != nil {
				return err
			}
		}

		// No AuthKey: argon2id generates a fresh random salt inside each hash
		// rather than reusing a per-user value stored beside it.
		user := User{
			DisplayScreenName: screenName,
			IdentScreenName:   screenName.IdentScreenName(),
			IsICQ:             screenName.IsUIN(),
		}
		if err := user.HashPassword(password); err != nil {
			return err
		}

		if err := insertUser(ctx, user); err != nil {
			return err
		}

		return nil
	}
}
