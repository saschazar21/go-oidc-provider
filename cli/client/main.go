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
	var client models.Client

	ctx := context.Background()
	conn := db.Connect(ctx)
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nCreate new OpenID Connect client")
	fmt.Println("--------------------------------")

	readOwner(ctx, conn, reader, &client)
	readPrimary(reader, &client)

	wantsAdditionalInfo, err := cli.ReadYN(reader, "Do you want to enter additional client details (pkce, grant types, response types)?")
	if wantsAdditionalInfo && err == nil {
		readSecondary(reader, &client)
	}

	wantsFineGrainedInfo, err := cli.ReadYN(reader, "Do you want to enter fine-grained client details (client metadata, lifetimes, algorithms)?")
	if wantsFineGrainedInfo && err == nil {
		readTertiary(reader, &client)
	}

	if err := client.Validate(); err != nil {
		fmt.Printf("Client validation failed: %v\n", err)
		os.Exit(1)
	}

	enc, err := json.MarshalIndent(client, "", "    ")
	if err != nil {
		fmt.Printf("Error marshalling client to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nClient Summary:")
	fmt.Println("---------------")
	fmt.Printf("%s\n\n", string(enc))

	wantsClientCreated, err := cli.ReadYN(reader, "Do you want to store the client in the database?")
	if wantsClientCreated && err == nil {
		err := client.Save(ctx, conn)
		if err != nil {
			fmt.Printf("Error storing client: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully created client:\n%s\n\nBye...\n", client)
}
