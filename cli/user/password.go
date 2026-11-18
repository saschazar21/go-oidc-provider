package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/utils"
	"golang.org/x/term"
)

type passwordOptions struct {
	userID uuid.UUID
	remove bool
}

func parsePasswordOptions(args []string, output io.Writer) (passwordOptions, error) {
	flags := flag.NewFlagSet("user", flag.ContinueOnError)
	flags.SetOutput(output)
	user := flags.String("password-user", "", "UUID of existing user whose password should be set/replaced")
	remove := flags.Bool("remove-password", false, "remove password (requires --password-user)")
	if err := flags.Parse(args); err != nil {
		return passwordOptions{}, err
	}
	if flags.NArg() != 0 {
		// Do not echo unrecognized arguments: they might contain a secret.
		return passwordOptions{}, errors.New("unexpected positional arguments; passwords must be entered at the hidden prompt")
	}
	options := passwordOptions{remove: *remove}
	if *user != "" {
		id, err := uuid.Parse(*user)
		if err != nil || id == uuid.Nil {
			return options, errors.New("--password-user requires a nonzero UUID")
		}
		options.userID = id
	}
	if options.remove && options.userID == uuid.Nil {
		return options, errors.New("--remove-password requires --password-user")
	}
	return options, nil
}

// Refuse piped input rather than accidentally echoing a password. ReadPassword
// removes only the terminal line ending; spaces and Unicode remain byte-exact.
func terminalPasswordReader() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("password input requires an interactive terminal")
	}
	return term.ReadPassword(fd)
}

func readConfirmedPassword(output io.Writer, read func() ([]byte, error)) (string, error) {
	fmt.Fprint(output, "Password: ")
	password, err := read()
	defer clear(password)
	fmt.Fprintln(output)
	if err != nil {
		return "", errors.New("password input cancelled or unavailable")
	}
	if len(password) == 0 || len(password) > utils.MaxPasswordBytes {
		return "", utils.ErrInvalidPassword
	}
	fmt.Fprint(output, "Confirm password: ")
	confirmation, err := read()
	defer clear(confirmation)
	fmt.Fprintln(output)
	if err != nil {
		return "", errors.New("password confirmation cancelled or unavailable")
	}
	if !bytes.Equal(password, confirmation) {
		return "", errors.New("password confirmation does not match")
	}
	return string(password), nil
}