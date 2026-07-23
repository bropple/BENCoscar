// benco_admin administers a BENCoscar server through its management API.
//
// It exists to keep credentials out of shell history and out of `ps` output:
// the same jobs done with `curl -d '{"password":"..."}'` put the password in
// both places every time. No secret is ever accepted as a command-line
// argument -- see the comment at the top of secret.go.
//
// Usage: benco_admin <group> <command> [options]
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		// The command already ran, in a child process that had the admin group
		// this one lacked. It has printed whatever it had to print; all that is
		// left is to wear its exit status.
		var retried *retriedError
		if errors.As(err, &retried) {
			os.Exit(retried.code)
		}
		if errors.Is(err, errUsage) {
			// The usage text has already been written; exit non-zero so a
			// mistyped command in a script does not read as success.
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printUsage()
		return errUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "user":
		return runUser(args[1:], stdout)
	case "session":
		return runSession(args[1:], stdout)
	case "room":
		return runRoom(args[1:], stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command group: %s\n\n", args[0])
		printUsage()
		return errUsage
	}
}

func printUsage() {
	fmt.Println("benco_admin -- administer a BENCoscar server via its management API")
	fmt.Println("\nUsage: benco_admin <group> <command> [options]")
	fmt.Println("\nUser commands:")
	fmt.Println("  user list                 List all accounts")
	fmt.Println("  user add <screenname>     Create an account")
	fmt.Println("  user passwd <screenname>  Reset an account password")
	fmt.Println("  user rm <screenname>      Delete an account")
	fmt.Println("  user devices clear <screenname>")
	fmt.Println("                            Reset an account's encryption identity (clears")
	fmt.Println("                            every device and the backup; password auth alone")
	fmt.Println("                            after). Recovery for a lost-all-devices account.")
	fmt.Println("\nSession commands:")
	fmt.Println("  session list              Show who is online")
	fmt.Println("  session kick <screenname> Disconnect a signed-in user")
	fmt.Println("\nChat room commands:")
	fmt.Println("  room list                 List public and private rooms")
	fmt.Println("  room rm <name>            Delete a public room")
	fmt.Println("\nOptions:")
	fmt.Printf("  --api ADDR                Management API socket or address (default %s)\n", defaultAPIAddr)
	fmt.Println("                            unix:/PATH/TO.sock, or HOST:PORT for a TCP listener")
	fmt.Println("  --token-file PATH         File containing the API token")
	fmt.Println("  --generate                Mint a strong random password (user add, user passwd)")
	fmt.Println("  --yes                     Skip the confirmation prompt on destructive commands")
	fmt.Println("\nSecrets:")
	fmt.Println("  Passwords are never taken as arguments -- there is deliberately no")
	fmt.Println("  --password flag. argv is visible in `ps` to every user on the machine and")
	fmt.Println("  is recorded in shell history. Passwords are prompted for with echo")
	fmt.Println("  disabled, or read from stdin when stdin is a pipe:")
	fmt.Println()
	fmt.Println("      benco_admin user add someone < /path/to/password-file")
	fmt.Println()
	fmt.Printf("  The API token is read from $%s or from --token-file. The\n", tokenEnvVar)
	fmt.Println("  token itself is never a flag value, for the same reason.")
	fmt.Println("\nReaching the server:")
	fmt.Printf("  By default this talks to a unix socket at %s, which is\n", strings.TrimPrefix(defaultAPIAddr, unixPrefix))
	fmt.Println("  where the access control lives. The socket sits in a directory only the")
	fmt.Printf("  %s group can open, so the kernel decides who may connect\n", defaultAdminGroup)
	fmt.Println("  before the server reads a byte. Being in that group IS the credential;")
	fmt.Println("  there is no password or token to hold. Add yourself with:")
	fmt.Println()
	fmt.Printf("      sudo usermod -aG %s $USER    # then log out and back in\n", defaultAdminGroup)
	fmt.Println()
	fmt.Println("  This tool therefore runs on the server itself. To administer from a")
	fmt.Println("  workstation, run it over ssh:")
	fmt.Println()
	fmt.Println("      ssh -t user@server benco_admin user list")
	fmt.Println()
	fmt.Println("  A TCP listener (--api HOST:PORT) is still supported for older setups. The")
	fmt.Println("  management API performs NO authentication over TCP -- anything that can")
	fmt.Println("  reach the port has full administrative control -- so it must stay on")
	fmt.Println("  loopback, reached through a tunnel:")
	fmt.Println()
	fmt.Println("      ssh -N -L 8080:127.0.0.1:8080 user@server")
	fmt.Println()
	fmt.Println("  The token above is sent as a Bearer header for deployments that front the")
	fmt.Println("  API with an authenticating reverse proxy; without such a proxy, or over the")
	fmt.Println("  unix socket, it has no effect.")
}

// commonOpts are the flags every command accepts. They are parsed by hand
// rather than with a flag.FlagSet per subcommand so that they may appear before
// or after the positional argument, which is what an operator will type.
type commonOpts struct {
	api       string
	tokenFile string
	generate  bool
	yes       bool
}

// parseArgs splits flags from positional arguments. It rejects --password
// explicitly rather than as an unknown flag, so that anyone who reaches for it
// learns why it is absent instead of assuming a typo.
func parseArgs(args []string) (opts commonOpts, positional []string, err error) {
	opts.api = defaultAPIAddr

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Support --flag=value as well as --flag value.
		name, inlineValue, hasInline := strings.Cut(arg, "=")

		// Flags that take a value accept both --flag=value and --flag value.
		// The value is resolved up front so the switch below stays flat.
		value := inlineValue
		valueOK := hasInline
		if !hasInline && (name == "--api" || name == "--token-file") {
			if i+1 < len(args) {
				i++
				value = args[i]
				valueOK = true
			}
		}

		switch name {
		case "--password", "-p", "--pass", "--token", "--api-token":
			return commonOpts{}, nil, fmt.Errorf(
				"%s is not a valid flag, and never will be: secrets passed in argv are visible in `ps` "+
					"and recorded in shell history. Passwords are prompted for, or read from stdin when "+
					"stdin is a pipe; the API token comes from $%s or --token-file", name, tokenEnvVar)
		case "--api":
			if !valueOK {
				return commonOpts{}, nil, errors.New("--api requires a value")
			}
			opts.api = value
		case "--token-file":
			if !valueOK {
				return commonOpts{}, nil, errors.New("--token-file requires a value")
			}
			opts.tokenFile = value
		case "--generate":
			opts.generate = true
		case "--yes", "-y":
			opts.yes = true
		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return commonOpts{}, nil, fmt.Errorf("unknown flag: %s", arg)
			}
			positional = append(positional, arg)
		}
	}
	return opts, positional, nil
}

// clientFor builds an API client, resolving the token from the environment or a
// file -- never from argv.
func clientFor(opts commonOpts) (*apiClient, error) {
	token, err := readToken(opts.tokenFile)
	if err != nil {
		return nil, err
	}
	c := newAPIClient(opts.api, token)

	// Check reachability here, before any command prompts for a password or
	// reads one from a pipe. A permission failure may re-execute this process
	// under sg, and that has to happen while stdin is still untouched.
	if c.socketPath != "" {
		if err := probeSocket(c.socketPath); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func urlPathEscape(s string) string {
	return url.PathEscape(s)
}

// confirm requires the operator to type "yes" before a destructive action.
//
// When stdin is not a terminal it refuses rather than assuming consent: a
// script that forgot --yes should stop, not delete an account because a prompt
// read EOF.
func confirm(prompt string, opts commonOpts) error {
	if opts.yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errors.New("refusing to act without confirmation: stdin is not a terminal, pass --yes to proceed")
	}
	fmt.Fprintf(os.Stderr, "%s\nType 'yes' to confirm: ", prompt)
	line, err := stdin.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if strings.TrimSpace(line) != "yes" {
		return errors.New("aborted")
	}
	return nil
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

// --- user ---------------------------------------------------------------

func runUser(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printUsage()
		return errUsage
	}
	sub := args[0]
	opts, positional, err := parseArgs(args[1:])
	if err != nil {
		return err
	}

	switch sub {
	case "list", "ls":
		return userList(opts, stdout)
	case "add":
		if len(positional) != 1 {
			return errors.New("usage: benco_admin user add <screenname>")
		}
		return userAdd(opts, positional[0])
	case "passwd":
		if len(positional) != 1 {
			return errors.New("usage: benco_admin user passwd <screenname>")
		}
		return userPasswd(opts, positional[0])
	case "rm", "delete":
		if len(positional) != 1 {
			return errors.New("usage: benco_admin user rm <screenname>")
		}
		return userRm(opts, positional[0])
	case "devices":
		return runUserDevices(positional, opts)
	default:
		return fmt.Errorf("unknown user command: %s", sub)
	}
}

// runUserDevices dispatches the `user devices ...` subcommands. Only `clear`
// exists today; it is here as a group rather than a flat `user clear-devices`
// so that adding `user devices list` later needs no rename.
func runUserDevices(positional []string, opts commonOpts) error {
	if len(positional) == 0 {
		return errors.New("usage: benco_admin user devices clear <screenname>")
	}
	switch positional[0] {
	case "clear":
		if len(positional) != 2 {
			return errors.New("usage: benco_admin user devices clear <screenname>")
		}
		return userDevicesClear(opts, positional[1])
	default:
		return fmt.Errorf("unknown devices command: %s", positional[0])
	}
}

// userDevicesClear resets an account's encryption identity, the recovery path
// for an account that has lost every device. It is deliberately loud: this is
// the operation that lets an identity be replaced, so the confirmation spells
// out that it clears the backup too and moves every contact's safety number.
func userDevicesClear(opts commonOpts, screenName string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	if err := confirm(fmt.Sprintf(
		"This resets %q's encryption identity. It clears every enrolled device AND the "+
			"identity backup, so the account returns to having no devices and can sign in with "+
			"its password alone. The next device to sign in bootstraps a NEW identity, which "+
			"moves the safety number every contact holds for this account, and nothing sent "+
			"under the old identity will be readable by the new one. Use it only when the account "+
			"has lost access to all of its devices.", screenName), opts); err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	if err := c.clearKeyDirectory(cx, screenName); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Cleared %s's key directory. It can now sign in with its password and "+
		"set up a fresh identity.\n", screenName)
	return nil
}

func userList(opts commonOpts, stdout io.Writer) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	users, err := c.listUsers(cx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		_, _ = fmt.Fprintln(stdout, "No accounts.")
		return nil
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SCREEN NAME\tTYPE\tSTATUS\tBOT")
	for _, u := range users {
		kind := "AIM"
		if u.IsICQ {
			kind = "ICQ"
		}
		status := u.SuspendedStatus
		if status == "" {
			status = "active"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", u.ScreenName, kind, status, u.IsBot)
	}
	return w.Flush()
}

// newPassword resolves the password for a create-or-reset, either generated or
// prompted, and validates it locally so a length violation is caught before a
// round trip rather than as a 400 afterwards.
func newPassword(opts commonOpts, screenName string) (string, error) {
	var password string
	var err error

	if opts.generate {
		var bits int
		password, bits, err = generatePassword(screenName)
		if err != nil {
			return "", err
		}
		// Printed once, to stdout, and never stored anywhere by this tool.
		fmt.Fprintf(os.Stderr, "Generated password for %s (%d bits of entropy) -- shown once, write it down now:\n\n", screenName, bits)
		fmt.Printf("    %s\n\n", password)
		if isUIN(screenName) {
			fmt.Fprintf(os.Stderr,
				"warning: %s is an ICQ UIN, and the server caps UIN passwords at %d characters,\n"+
					"so %d bits is the strongest password this account can hold.\n\n",
				screenName, maxICQPasswordLen, bits)
		}
	} else {
		password, err = readNewPassword(screenName)
		if err != nil {
			return "", err
		}
	}

	if err := validatePassword(screenName, password); err != nil {
		return "", err
	}
	return password, nil
}

func userAdd(opts commonOpts, screenName string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	password, err := newPassword(opts, screenName)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	if err := c.addUser(cx, screenName, password); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Created account %s.\n", screenName)
	return nil
}

func userPasswd(opts commonOpts, screenName string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	password, err := newPassword(opts, screenName)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	if err := c.setPassword(cx, screenName, password); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Password reset for %s.\n", screenName)
	return nil
}

func userRm(opts commonOpts, screenName string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	if err := confirm(fmt.Sprintf(
		"This will permanently delete the account %q and everything the server holds for it.", screenName), opts); err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	if err := c.deleteUser(cx, screenName); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Deleted account %s.\n", screenName)
	return nil
}

// --- session ------------------------------------------------------------

func runSession(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printUsage()
		return errUsage
	}
	sub := args[0]
	opts, positional, err := parseArgs(args[1:])
	if err != nil {
		return err
	}

	switch sub {
	case "list", "ls":
		return sessionList(opts, stdout)
	case "kick":
		if len(positional) != 1 {
			return errors.New("usage: benco_admin session kick <screenname>")
		}
		return sessionKick(opts, positional[0])
	default:
		return fmt.Errorf("unknown session command: %s", sub)
	}
}

func sessionList(opts commonOpts, stdout io.Writer) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	out, err := c.listSessions(cx)
	if err != nil {
		return err
	}
	if out.Count == 0 {
		_, _ = fmt.Fprintln(stdout, "Nobody is online.")
		return nil
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SCREEN NAME\tTYPE\tONLINE\tIDLE\tPRESENCE\tDEVICES")
	for _, s := range out.Sessions {
		kind := "AIM"
		if s.IsICQ {
			kind = "ICQ"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
			s.ScreenName, kind, humanDuration(s.OnlineSeconds), humanDuration(s.IdleSeconds),
			presence(s), s.InstanceCount)
	}
	return w.Flush()
}

func presence(s sessionHandle) string {
	var parts []string
	if s.IsAway {
		parts = append(parts, "away")
	}
	if s.IsInvisible {
		parts = append(parts, "invisible")
	}
	if len(parts) == 0 {
		return "online"
	}
	return strings.Join(parts, "+")
}

func humanDuration(seconds int) string {
	if seconds <= 0 {
		return "-"
	}
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func sessionKick(opts commonOpts, screenName string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	// Look the session up first so the confirmation can name exactly what is
	// about to be disconnected, including how many devices that is.
	found, err := c.session(cx, screenName)
	if err != nil {
		return err
	}

	desc := fmt.Sprintf("This will disconnect %q.", screenName)
	if len(found.Sessions) == 1 {
		s := found.Sessions[0]
		desc = fmt.Sprintf("This will disconnect %s (%d device(s), online %s). Unsent messages may be lost.",
			s.ScreenName, s.InstanceCount, humanDuration(s.OnlineSeconds))
	}
	if err := confirm(desc, opts); err != nil {
		return err
	}

	if err := c.kickSession(cx, screenName); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Disconnected %s.\n", screenName)
	return nil
}

// --- room ---------------------------------------------------------------

func runRoom(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		printUsage()
		return errUsage
	}
	sub := args[0]
	opts, positional, err := parseArgs(args[1:])
	if err != nil {
		return err
	}

	switch sub {
	case "list", "ls":
		return roomList(opts, stdout)
	case "rm", "delete":
		if len(positional) != 1 {
			return errors.New("usage: benco_admin room rm <name>")
		}
		return roomRm(opts, positional[0])
	default:
		return fmt.Errorf("unknown room command: %s", sub)
	}
}

func roomList(opts commonOpts, stdout io.Writer) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	public, err := c.listRooms(cx, "public")
	if err != nil {
		return err
	}
	private, err := c.listRooms(cx, "private")
	if err != nil {
		return err
	}

	if len(public) == 0 && len(private) == 0 {
		_, _ = fmt.Fprintln(stdout, "No chat rooms.")
		return nil
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tEXCHANGE\tOCCUPANTS\tCREATED\tCREATOR")
	for _, r := range public {
		_, _ = fmt.Fprintf(w, "%s\tpublic\t%d\t%s\t%s\n",
			r.Name, len(r.Participants), r.CreateTime.Format("2006-01-02"), dash(r.CreatorID))
	}
	for _, r := range private {
		_, _ = fmt.Fprintf(w, "%s\tprivate\t%d\t%s\t%s\n",
			r.Name, len(r.Participants), r.CreateTime.Format("2006-01-02"), dash(r.CreatorID))
	}
	return w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func roomRm(opts commonOpts, name string) error {
	c, err := clientFor(opts)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()

	// Check the private exchange first. Deleting a private room is not
	// something this tool can do, and saying so plainly beats issuing a delete
	// against the public exchange that reports success while changing nothing.
	private, err := c.listRooms(cx, "private")
	if err != nil {
		return err
	}
	for _, r := range private {
		if strings.EqualFold(r.Name, name) {
			return fmt.Errorf(
				"%q is a private chat room, and the management API cannot delete it.\n"+
					"  The API exposes DELETE only for the public exchange (DELETE /chat/room/public);\n"+
					"  there is no private-exchange equivalent, so no client of the API -- this tool\n"+
					"  included -- can remove it. The server's store does implement deletion for the\n"+
					"  private exchange, it is simply not routed.\n"+
					"\n"+
					// No trailing period: ST1005. The message is long-form operator
					// guidance rather than a composable error fragment, but the
					// convention still applies because it may be wrapped.
					"  Removing it means acting on the server's database directly. The BENCchat\n"+
					"  repository ships scripts/purge-rooms.sh for exactly this",
				name)
		}
	}

	public, err := c.listRooms(cx, "public")
	if err != nil {
		return err
	}
	var match *chatRoom
	for i := range public {
		if strings.EqualFold(public[i].Name, name) {
			match = &public[i]
			break
		}
	}
	if match == nil {
		return fmt.Errorf("no public chat room named %q", name)
	}

	desc := fmt.Sprintf("This will delete the public chat room %q.", match.Name)
	if n := len(match.Participants); n > 0 {
		desc = fmt.Sprintf("This will delete the public chat room %q, which has %d occupant(s) in it right now.", match.Name, n)
	}
	if err := confirm(desc, opts); err != nil {
		return err
	}

	if err := c.deletePublicRoom(cx, match.Name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Deleted public chat room %s.\n", match.Name)
	return nil
}
