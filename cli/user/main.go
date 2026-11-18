package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/cli"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	options, err := parsePasswordOptions(args, os.Stdout)
	if err != nil {
		return err
	}
	var user models.User

	ctx := context.Background()
	conn := db.Connect(ctx)
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)
	if options.userID != uuid.Nil {
		if options.remove {
			confirmed, err := cli.ReadYN(reader, "Remove password and revoke this user's sessions and grants?")
			if err != nil {
				return err
			}
			if !confirmed {
				return nil
			}
			if err := helpers.RemovePassword(ctx, conn, options.userID); err != nil {
				return err
			}
		} else {
			password, err := readConfirmedPassword(os.Stdout, terminalPasswordReader)
			if err != nil {
				return err
			}
			if err := helpers.SetPassword(ctx, conn, options.userID, password); err != nil {
				return err
			}
		}
		fmt.Println("Password updated; previous authentication evidence revoked.")
		return nil
	}

	fmt.Println("\nCreate new OpenID Connect user")
	fmt.Println("------------------------------")

	readPrimary(reader, &user)

	wantsNameInfo, err := cli.ReadYN(reader, "Do you want to enter user's name details?")
	if wantsNameInfo && err == nil {
		readSecondary(reader, &user)
	}

	wantsProfileInfo, err := cli.ReadYN(reader, "Do you want to enter user's profile details?")
	if wantsProfileInfo && err == nil {
		readTertiary(reader, &user)
	}

	wantsAddressInfo, err := cli.ReadYN(reader, "Do you want to enter user's address details?")
	if wantsAddressInfo && err == nil {
		readAddress(reader, &user)
	}

	wantsPhoneInfo, err := cli.ReadYN(reader, "Do you want to enter user's phone number?")
	if wantsPhoneInfo && err == nil {
		readPhoneNumber(reader, &user)
	}

	wantsPassword, err := cli.ReadYN(reader, "Do you want to set a password for this user?")
	if err != nil {
		return err
	}
	var encoded string
	if wantsPassword {
		password, err := readConfirmedPassword(os.Stdout, terminalPasswordReader)
		if err != nil {
			return err
		}
		encoded, err = utils.HashPasswordContext(ctx, password)
		if err != nil {
			return err
		}
	}

	if err := user.Validate(); err != nil {
		fmt.Printf("User validation failed: %v\n", err)
		os.Exit(1)
	}

	enc, err := json.MarshalIndent(user, "", "    ")
	if err != nil {
		fmt.Printf("Error marshalling user to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nUser Summary:")
	fmt.Println("-------------")
	fmt.Printf("%s\n\n", string(enc))

	wantsUserCreated, err := cli.ReadYN(reader, "Do you want to store the user in the database?")
	if wantsUserCreated && err == nil {
		err := conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			if err := user.Save(ctx, tx); err != nil {
				return err
			}
			if encoded != "" {
				return helpers.SetEncodedPasswordInTx(ctx, tx, user.ID, encoded)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error storing user: %w", err)
		}
	} else if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println("User creation aborted, exiting...")
		os.Exit(0)
	}

	fmt.Printf("\nSuccessfully created user:\n%s\n\nBye...\n", user)
	return nil
}
