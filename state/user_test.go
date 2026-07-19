package state

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

// passwordHash returns the argon2id hash of password in PHC string format. Each
// call produces a different string even for the same password, because the salt
// is random — tests must therefore verify passwords rather than compare hashes.
func passwordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := NewPasswordHash(password)
	require.NoError(t, err)
	return hash
}

// userWithPassword returns a User whose PasswordHash is the argon2id hash of
// password. It replaces the old AuthKey/WeakMD5Pass/StrongMD5Pass fixtures.
func userWithPassword(t *testing.T, password string) User {
	t.Helper()
	return User{PasswordHash: passwordHash(t, password)}
}

func TestUser_HashPassword(t *testing.T) {
	tests := []struct {
		name      string
		user      User
		password  string
		wantError bool
	}{
		{
			name:      "Valid AIM password",
			user:      User{IsICQ: false},
			password:  "validPassword",
			wantError: false,
		},
		{
			name:      "Empty AIM password",
			user:      User{IsICQ: false},
			password:  "",
			wantError: true,
		},
		{
			name:      "AIM password too short",
			user:      User{IsICQ: false},
			password:  "abc",
			wantError: true,
		},
		{
			// BENCO widened the bounds to 8-128, so upstream's 21-character
			// "too long" fixture is now valid. Kept as a passing case rather
			// than deleted: a passphrase is exactly what the wider ceiling
			// exists to allow, so this is the behaviour worth asserting.
			name:      "AIM passphrase is accepted",
			user:      User{IsICQ: false},
			password:  "thispasswordistoolong",
			wantError: false,
		},
		{
			name:      "AIM password one under the minimum",
			user:      User{IsICQ: false},
			password:  "1234567",
			wantError: true,
		},
		{
			name:      "AIM password at the minimum",
			user:      User{IsICQ: false},
			password:  "12345678",
			wantError: false,
		},
		{
			name:      "AIM password at the maximum",
			user:      User{IsICQ: false},
			password:  strings.Repeat("a", 128),
			wantError: false,
		},
		{
			// The ceiling bounds work done on an unauthenticated request:
			// without it a huge input would make the server hash megabytes.
			name:      "AIM password over the maximum",
			user:      User{IsICQ: false},
			password:  strings.Repeat("a", 129),
			wantError: true,
		},
		{
			name:      "Valid ICQ password",
			user:      User{IsICQ: true},
			password:  "validICQ",
			wantError: false,
		},
		{
			name:      "Empty ICQ password",
			user:      User{IsICQ: true},
			password:  "",
			wantError: true,
		},
		{
			name:      "ICQ password too long",
			user:      User{IsICQ: true},
			password:  "icqpass89",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.HashPassword(tt.password)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// The hash embeds a random salt, so its exact bytes can't be
			// asserted the way the old MD5 equivalents could. Assert the
			// properties that actually matter instead: it's a well-formed
			// argon2id hash, and it accepts exactly the right password.
			require.NotEmpty(t, tt.user.PasswordHash)
			_, salt, key, err := ParsePasswordHash(tt.user.PasswordHash)
			require.NoError(t, err)
			assert.NotEmpty(t, salt)
			assert.NotEmpty(t, key)

			assert.True(t, tt.user.ValidatePlaintextPass([]byte(tt.password)))
			assert.False(t, tt.user.ValidatePlaintextPass([]byte(tt.password+"wrong")))
		})
	}
}

func TestAge(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		timeNow     func() time.Time
		expectedAge uint16
	}{
		{
			name: "Valid birthday, only year is set",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear: 1990,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 34,
		},
		{
			name: "Valid birthday, birthday passed this year",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  1990,
						BirthMonth: 5,
						BirthDay:   10,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 34,
		},
		{
			name: "Valid birthday, birthday not yet passed this year",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  1990,
						BirthMonth: 12,
						BirthDay:   10,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 33,
		},
		{
			name: "Birthday is today",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  1990,
						BirthMonth: 8,
						BirthDay:   1,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 34,
		},
		{
			name: "Invalid birthday, year is zero",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  0,
						BirthMonth: 8,
						BirthDay:   1,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 0,
		},
		{
			name: "Invalid birthday, day is zero",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  1990,
						BirthMonth: 8,
						BirthDay:   0,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 0,
		},
		{
			name: "Invalid birthday, month is zero",
			user: User{
				ICQInfo: ICQInfo{
					More: ICQMoreInfo{
						BirthYear:  1990,
						BirthMonth: 0,
						BirthDay:   1,
					},
				},
			},
			timeNow: func() time.Time {
				return time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)
			},
			expectedAge: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			age := tt.user.Age(tt.timeNow)
			if age != tt.expectedAge {
				t.Errorf("expected age %d, got %d", tt.expectedAge, age)
			}
		})
	}
}

func TestDisplayScreenName_ValidateAIMHandle(t *testing.T) {
	tests := []struct {
		name    string
		input   DisplayScreenName
		wantErr error
	}{
		{"Valid handle no spaces", "User123", nil},
		{"Valid handle with min character count and space", "U SR", nil},
		{"Valid handle with min character including letters and numbers", "dj3520", nil},
		{"Valid handle with max character count", "JustTheRightSize", nil},
		{"Valid handle with max character count and spaces", "Just   RightSize", nil},
		{"Too short", "Us", ErrAIMHandleLength},
		{"Too short due to spaces", "U S", ErrAIMHandleLength},
		{"Too long", "ThisIsAReallyLongScreenName", ErrAIMHandleLength},
		{"Too many spaces", "User           123 ", ErrAIMHandleLength},
		{"Starts with number", "1User", ErrAIMHandleInvalidFormat},
		{"Ends with space", "User123 ", ErrAIMHandleInvalidFormat},
		{"Contains invalid character", "User@123", ErrAIMHandleInvalidFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.ValidateAIMHandle()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr, "ValidateAIMHandle() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				assert.NoError(t, err, "ValidateAIMHandle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDisplayScreenName_ValidateICQHandle(t *testing.T) {
	tests := []struct {
		name    string
		input   DisplayScreenName
		wantErr error
	}{
		{"Valid UIN", "123456", nil},
		{"Too low", "9999", ErrICQUINInvalidFormat},
		{"Too high", "2147483647", ErrICQUINInvalidFormat},
		{"Non-numeric", "abcd", ErrICQUINInvalidFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.ValidateUIN()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr, "ValidateUIN() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				assert.NoError(t, err, "ValidateUIN() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUser_ValidateRoastedPass(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		roastedPass []byte
		expected    bool
	}{
		{
			name:        "Valid roasted password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARPassword([]byte("testPassword")),
			expected:    true,
		},
		{
			name:        "Invalid roasted password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARPassword([]byte("wrongPassword")),
			expected:    false,
		},
		{
			name:        "Empty roasted password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARPassword([]byte("")),
			expected:    false,
		},
		{
			name: "Empty stored password",
			// No stored hash at all: VerifyPassword rejects an empty
			// PasswordHash, so every credential must fail.
			user:        User{},
			roastedPass: wire.RoastOSCARPassword([]byte("testPassword")),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ValidateRoastedPass(tt.roastedPass)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUser_ValidateRoastedJavaPass(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		roastedPass []byte
		expected    bool
	}{
		{
			name:        "Valid roasted Java password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARJavaPassword([]byte("testPassword")),
			expected:    true,
		},
		{
			name:        "Invalid roasted Java password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARJavaPassword([]byte("wrongPassword")),
			expected:    false,
		},
		{
			name:        "Empty roasted Java password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastOSCARJavaPassword([]byte("")),
			expected:    false,
		},
		{
			name: "Empty stored password",
			// No stored hash at all: VerifyPassword rejects an empty
			// PasswordHash, so every credential must fail.
			user:        User{},
			roastedPass: wire.RoastOSCARJavaPassword([]byte("testPassword")),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ValidateRoastedJavaPass(tt.roastedPass)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUser_ValidateRoastedTOCPass(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		roastedPass []byte
		expected    bool
	}{
		{
			name:        "Valid roasted TOC password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastTOCPassword([]byte("testPassword")),
			expected:    true,
		},
		{
			name:        "Invalid roasted TOC password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastTOCPassword([]byte("wrongPassword")),
			expected:    false,
		},
		{
			name:        "Empty roasted TOC password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastTOCPassword([]byte("")),
			expected:    false,
		},
		{
			name: "Empty stored password",
			// No stored hash at all: VerifyPassword rejects an empty
			// PasswordHash, so every credential must fail.
			user:        User{},
			roastedPass: wire.RoastTOCPassword([]byte("testPassword")),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ValidateRoastedTOCPass(tt.roastedPass)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUser_ValidatePlaintextPass(t *testing.T) {
	tests := []struct {
		name          string
		user          User
		plaintextPass []byte
		expected      bool
	}{
		{
			name:          "Valid plaintext password",
			user:          userWithPassword(t, "testPassword"),
			plaintextPass: []byte("testPassword"),
			expected:      true,
		},
		{
			name:          "Invalid plaintext password",
			user:          userWithPassword(t, "testPassword"),
			plaintextPass: []byte("wrongPassword"),
			expected:      false,
		},
		{
			name:          "Empty plaintext password",
			user:          userWithPassword(t, "testPassword"),
			plaintextPass: []byte(""),
			expected:      false,
		},
		{
			name: "Empty stored password",
			// No stored hash at all: VerifyPassword rejects an empty
			// PasswordHash, so every credential must fail.
			user:          User{},
			plaintextPass: []byte("testPassword"),
			expected:      false,
		},
		{
			name:          "Password with special characters",
			user:          userWithPassword(t, "test@123!"),
			plaintextPass: []byte("test@123!"),
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ValidatePlaintextPass(tt.plaintextPass)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUser_ValidateRoastedKerberosPass(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		roastedPass []byte
		expected    bool
	}{
		{
			name:        "Valid roasted Kerberos password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastKerberosPassword([]byte("testPassword")),
			expected:    true,
		},
		{
			name:        "Invalid roasted Kerberos password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastKerberosPassword([]byte("wrongPassword")),
			expected:    false,
		},
		{
			name:        "Empty roasted Kerberos password",
			user:        userWithPassword(t, "testPassword"),
			roastedPass: wire.RoastKerberosPassword([]byte("")),
			expected:    false,
		},
		{
			name: "Empty stored password",
			// No stored hash at all: VerifyPassword rejects an empty
			// PasswordHash, so every credential must fail.
			user:        User{},
			roastedPass: wire.RoastKerberosPassword([]byte("testPassword")),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ValidateRoastedKerberosPass(tt.roastedPass)
			assert.Equal(t, tt.expected, result)
		})
	}
}
