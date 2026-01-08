package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/saschazar21/go-oidc-provider/cli"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
)

func main() {
	var user models.User

	ctx := context.Background()
	conn := db.Connect(ctx)
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)

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
		err := user.Save(ctx, conn)
		if err != nil {
			fmt.Printf("Error storing user: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println("User creation aborted, exiting...")
		os.Exit(0)
	}

	fmt.Printf("\nSuccessfully created user:\n%s\n\nBye...\n", user)
}
