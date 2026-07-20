package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUIN(t *testing.T) {
	tests := []struct {
		screenName string
		want       bool
	}{
		{"100000", true},
		{"12345678", true},
		{"chattingchuck", false},
		{"user123", false},
		{"123abc", false},
		{"", false},
		{"12 34", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isUIN(tt.screenName), "isUIN(%q)", tt.screenName)
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		password   string
		wantErr    string
	}{
		{
			name:       "AIM password at minimum length",
			screenName: "chattingchuck",
			password:   strings.Repeat("a", minAIMPasswordLen),
		},
		{
			name:       "AIM password at maximum length",
			screenName: "chattingchuck",
			password:   strings.Repeat("a", maxAIMPasswordLen),
		},
		{
			name:       "AIM password one short of the minimum",
			screenName: "chattingchuck",
			password:   strings.Repeat("a", minAIMPasswordLen-1),
			wantErr:    "between 8 and 128",
		},
		{
			name:       "AIM password one over the maximum",
			screenName: "chattingchuck",
			password:   strings.Repeat("a", maxAIMPasswordLen+1),
			wantErr:    "between 8 and 128",
		},
		{
			name:       "empty AIM password",
			screenName: "chattingchuck",
			password:   "",
			wantErr:    "between 8 and 128",
		},
		{
			name:       "ICQ password within the narrower UIN bounds",
			screenName: "100000",
			password:   "secret7",
		},
		{
			// An 8-char maximum applies to UINs even though the same password
			// would be too short for an AIM account.
			name:       "ICQ password at the 8 character cap",
			screenName: "100000",
			password:   "12345678",
		},
		{
			name:       "ICQ password over the 8 character cap",
			screenName: "100000",
			password:   "123456789",
			wantErr:    "between 6 and 8",
		},
		{
			name:       "ICQ password under the 6 character floor",
			screenName: "100000",
			password:   "short",
			wantErr:    "between 6 and 8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.screenName, tt.password)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestGeneratedPasswordsPassLocalValidation is the check that matters: a
// generated password must never be rejected by the bounds this tool enforces,
// or --generate would mint secrets the server then refuses.
func TestGeneratedPasswordsPassLocalValidation(t *testing.T) {
	for _, screenName := range []string{"chattingchuck", "100000"} {
		t.Run(screenName, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				pw, bits, err := generatePassword(screenName)
				require.NoError(t, err)
				assert.NoError(t, validatePassword(screenName, pw), "generated %q", pw)
				assert.Positive(t, bits)
			}
		})
	}
}

func TestGeneratePasswordAIM(t *testing.T) {
	pw, bits, err := generatePassword("chattingchuck")
	require.NoError(t, err)

	assert.Equal(t, aimPasswordBits, bits)
	assert.Equal(t, 120, bits, "24 symbols from a 32-symbol alphabet is 120 bits")

	groups := strings.Split(pw, groupSeparator)
	assert.Len(t, groups, genAIMSymbols/genGroupSize)
	for _, g := range groups {
		assert.Len(t, g, genGroupSize)
	}

	// Every symbol must come from the unambiguous alphabet, so a password read
	// off a piece of paper types back correctly.
	for _, r := range strings.ReplaceAll(pw, groupSeparator, "") {
		assert.Contains(t, pwAlphabet, string(r))
	}
	assert.NotContains(t, pw, "0")
	assert.NotContains(t, pw, "O")
	assert.NotContains(t, pw, "1")
	assert.NotContains(t, pw, "I")
}

func TestGeneratePasswordICQ(t *testing.T) {
	pw, bits, err := generatePassword("100000")
	require.NoError(t, err)

	// UIN passwords cannot be grouped or padded: the server's 8-character cap
	// leaves no room, which is why this path is weaker by construction.
	assert.Len(t, pw, maxICQPasswordLen)
	assert.NotContains(t, pw, groupSeparator)
	assert.Equal(t, 40, bits)
}

func TestGeneratePasswordIsRandom(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		pw, _, err := generatePassword("chattingchuck")
		require.NoError(t, err)
		assert.False(t, seen[pw], "generated a duplicate password: %q", pw)
		seen[pw] = true
	}
}

func TestPasswordAlphabetIsExactlyFiveBits(t *testing.T) {
	// The modulo in randomSymbols is only unbiased because 256 is an exact
	// multiple of the alphabet length. If the alphabet changes size, the
	// generator needs rejection sampling instead.
	assert.Len(t, pwAlphabet, 32)
	assert.Zero(t, 256%len(pwAlphabet))

	// No duplicate symbols, which would skew the distribution.
	seen := make(map[rune]bool)
	for _, r := range pwAlphabet {
		assert.False(t, seen[r], "duplicate symbol %q in alphabet", r)
		seen[r] = true
	}
}

func TestReadToken(t *testing.T) {
	t.Run("from file, trimming the trailing newline an editor adds", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(path, []byte("s3cret-token\n"), 0o600))

		got, err := readToken(path)
		require.NoError(t, err)
		assert.Equal(t, "s3cret-token", got)
	})

	t.Run("from the environment when no file is given", func(t *testing.T) {
		t.Setenv(tokenEnvVar, "env-token")
		got, err := readToken("")
		require.NoError(t, err)
		assert.Equal(t, "env-token", got)
	})

	t.Run("file wins over the environment", func(t *testing.T) {
		t.Setenv(tokenEnvVar, "env-token")
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(path, []byte("file-token"), 0o600))

		got, err := readToken(path)
		require.NoError(t, err)
		assert.Equal(t, "file-token", got)
	})

	t.Run("missing file is an error rather than an empty token", func(t *testing.T) {
		_, err := readToken(filepath.Join(t.TempDir(), "does-not-exist"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading token file")
	})

	t.Run("absent everywhere yields an empty token", func(t *testing.T) {
		t.Setenv(tokenEnvVar, "")
		got, err := readToken("")
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// TestReadNewPasswordFromPipe covers the scripted path: stdin is not a
// terminal, so exactly one line is read and no confirmation is requested.
func TestReadNewPasswordFromPipe(t *testing.T) {
	withPipedStdin(t, "hunter2hunter2\nnot-consumed\n")

	got, err := readNewPassword("chattingchuck")
	require.NoError(t, err)
	assert.Equal(t, "hunter2hunter2", got)
}

func TestReadNewPasswordFromPipeWithoutTrailingNewline(t *testing.T) {
	withPipedStdin(t, "hunter2hunter2")

	got, err := readNewPassword("chattingchuck")
	require.NoError(t, err)
	assert.Equal(t, "hunter2hunter2", got)
}

func TestReadNewPasswordRejectsEmpty(t *testing.T) {
	withPipedStdin(t, "\n")

	_, err := readNewPassword("chattingchuck")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestReadNewPasswordOnTerminalRequiresMatch(t *testing.T) {
	restore := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = restore })

	answers := []string{"hunter2hunter2", "hunter3hunter3"}
	restoreRead := readPasswordFn
	readPasswordFn = func() (string, error) {
		next := answers[0]
		answers = answers[1:]
		return next, nil
	}
	t.Cleanup(func() { readPasswordFn = restoreRead })

	_, err := readNewPassword("chattingchuck")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "do not match")
}

func TestReadNewPasswordOnTerminalAcceptsMatch(t *testing.T) {
	restore := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = restore })

	restoreRead := readPasswordFn
	readPasswordFn = func() (string, error) { return "hunter2hunter2", nil }
	t.Cleanup(func() { readPasswordFn = restoreRead })

	got, err := readNewPassword("chattingchuck")
	require.NoError(t, err)
	assert.Equal(t, "hunter2hunter2", got)
}
