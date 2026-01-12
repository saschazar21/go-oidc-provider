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
	var magicLinkWhitelist models.MagicLinkWhitelist

	ctx := context.Background()
	conn := db.Connect(ctx)
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nCreate new Magic Link Whitelist entry")
	fmt.Println("-------------------------------------")

	readPrimary(reader, &magicLinkWhitelist)

	wantsAdditionalInfo, err := cli.ReadYN(reader, "Do you want to enter a reason or additional notes?")
	if wantsAdditionalInfo && err == nil {
		readSecondary(reader, &magicLinkWhitelist)
	}

	if err := magicLinkWhitelist.Validate(); err != nil {
		fmt.Printf("Magic Link Whitelist entry validation failed: %v\n", err)
		os.Exit(1)
	}

	enc, err := json.MarshalIndent(magicLinkWhitelist, "", "    ")
	if err != nil {
		fmt.Printf("Error marshalling Magic Link Whitelist entry to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nMagic Link Whitelist Entry Summary:")
	fmt.Println("-----------------------------------")
	fmt.Println(string(enc))

	wantsClientCreated, err := cli.ReadYN(reader, "Do you want to store the whitelisted e-mail address in the database?")
	if wantsClientCreated && err == nil {
		err := magicLinkWhitelist.Save(ctx, conn)
		if err != nil {
			fmt.Printf("Error storing Magic Link Whitelist entry: %v\n", err)
			os.Exit(1)
		}
	} else if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully created Magic Link Whitelist entry:\n%s\n\nBye...\n", magicLinkWhitelist)
}
