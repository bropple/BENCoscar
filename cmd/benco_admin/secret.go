package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/term"
)

// Why no --password flag exists, anywhere in this tool:
//
// A value passed in argv is visible in `ps` output to every other user on the
// box for the lifetime of the process, and it is written verbatim into the
// shell's history file, where it survives indefinitely. Administering this
// server with `curl -d '{"password":"..."}'` leaked credentials by both routes
// every single time, which is the specific problem this tool exists to fix.
//
// Adding a --password flag "just for scripting" would reintroduce it, and a flag
// that exists will be used -- copied out of a runbook, pasted from a blog post,
// typed once in a hurry. So the flag does not exist. Passwords come from the
// terminal with echo disabled, or from stdin when stdin is a pipe. The same rule
// applies to the API token: --token-file names a file, never the secret itself.

// stdin is shared so that a buffered read for one prompt does not swallow input
// intended for the next.
var stdin = bufio.NewReader(os.Stdin)

// stdinIsTerminal is a variable so tests can exercise the piped path.
var stdinIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readPasswordFn is indirected for tests; the real one disables terminal echo.
var readPasswordFn = func() (string, error) {
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	// ReadPassword consumes the newline but does not echo one, so the next
	// thing printed would otherwise land on the prompt line.
	fmt.Fprintln(os.Stderr)
	return string(b), nil
}

// promptSecret reads one secret. On a terminal it prompts with echo disabled; on
// a pipe it reads a single line, so the tool stays usable from a script without
// ever accepting the secret as an argument.
//
// The prompt goes to stderr so that stdout stays clean for piping.
func promptSecret(prompt string) (string, error) {
	if !stdinIsTerminal() {
		line, err := stdin.ReadString('\n')
		if err != nil && (!errors.Is(err, io.EOF) || line == "") {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	return readPasswordFn()
}

// readNewPassword obtains a password for a password-setting operation.
//
// On a terminal it asks twice and compares, because a mistyped password that is
// never echoed is otherwise only discovered at the next sign-in. On a pipe it
// reads once: a script has no second copy to offer, and asking twice would just
// consume an unrelated line.
func readNewPassword(screenName string) (string, error) {
	first, err := promptSecret(fmt.Sprintf("New password for %s: ", screenName))
	if err != nil {
		return "", err
	}
	if stdinIsTerminal() {
		second, err := promptSecret("Retype new password: ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", errors.New("passwords do not match")
		}
	}
	if first == "" {
		return "", errors.New("password is empty")
	}
	return first, nil
}

// readToken resolves the management API token without ever accepting it as a
// flag value. A file is preferred over the environment because file permissions
// are enforceable and an environment variable is readable from /proc on some
// systems and leaks into child processes.
func readToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(tokenEnvVar)), nil
}

const tokenEnvVar = "BENCO_ADMIN_TOKEN"

// Password bounds, mirrored from state/user.go so a bad password is rejected
// here instead of after a round trip. They are duplicated rather than imported
// because the constants there are unexported; passwordBoundsMatchServer in the
// tests is the guard against them drifting apart.
const (
	minAIMPasswordLen = 8
	maxAIMPasswordLen = 128
	minICQPasswordLen = 6
	maxICQPasswordLen = 8
)

// isUIN reports whether a screen name is an ICQ UIN, matching
// state.DisplayScreenName.IsUIN. It decides which password bounds apply, since
// ICQ accounts are held to the old client's 6-8 character limit.
func isUIN(screenName string) bool {
	if screenName == "" {
		return false
	}
	for _, r := range screenName {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func passwordBounds(screenName string) (minLen int, maxLen int) {
	if isUIN(screenName) {
		return minICQPasswordLen, maxICQPasswordLen
	}
	return minAIMPasswordLen, maxAIMPasswordLen
}

func validatePassword(screenName string, password string) error {
	minLen, maxLen := passwordBounds(screenName)
	if len(password) < minLen || len(password) > maxLen {
		kind := "AIM"
		if isUIN(screenName) {
			kind = "ICQ"
		}
		return fmt.Errorf("password length must be between %d and %d characters (%s account, got %d)",
			minLen, maxLen, kind, len(password))
	}
	return nil
}

// pwAlphabet omits 0/O and 1/I/L so a generated password survives being written
// on paper and typed back. 32 symbols is exactly 5 bits per character, which
// also makes the modulo below unbiased.
const pwAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// Generated AIM passwords are 24 symbols -- 120 bits -- grouped in fours for
// transcription. The groups are part of the password; 29 characters total is
// well inside the 128 the server accepts.
const (
	genAIMSymbols   = 24
	genGroupSize    = 4
	genICQSymbols   = maxICQPasswordLen
	bitsPerSymbol   = 5
	groupSeparator  = "-"
	aimPasswordBits = genAIMSymbols * bitsPerSymbol
	icqPasswordBits = genICQSymbols * bitsPerSymbol
)

// generatePassword mints a password for screenName and reports its entropy.
//
// A generated secret beats a human-chosen one: "write this down" is a smaller
// ask than "invent something strong", and it removes the operator's habits from
// the threat model entirely.
//
// ICQ accounts are the unhappy case. The server caps UIN passwords at 8
// characters, so the best available is 40 bits -- weak by any modern standard,
// and a limit inherited from 1990s ICQ clients rather than a choice made here.
// The caller surfaces that rather than quietly issuing a weak secret.
func generatePassword(screenName string) (password string, bits int, err error) {
	if isUIN(screenName) {
		p, err := randomSymbols(genICQSymbols)
		return p, icqPasswordBits, err
	}
	raw, err := randomSymbols(genAIMSymbols)
	if err != nil {
		return "", 0, err
	}
	var groups []string
	for i := 0; i < len(raw); i += genGroupSize {
		groups = append(groups, raw[i:i+genGroupSize])
	}
	return strings.Join(groups, groupSeparator), aimPasswordBits, nil
}

func randomSymbols(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}
	out := make([]byte, n)
	for i, b := range buf {
		// 256 is an exact multiple of 32, so this modulo is uniform and needs
		// no rejection sampling.
		out[i] = pwAlphabet[int(b)%len(pwAlphabet)]
	}
	return string(out), nil
}
