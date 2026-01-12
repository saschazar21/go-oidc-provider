package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/saschazar21/go-oidc-provider/cli"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func readPrimary(reader *bufio.Reader, magicLinkWhitelist *models.MagicLinkWhitelist) {
	email, err := cli.ReadLine(reader, "Enter the email address to be whitelisted")
	if err != nil {
		fmt.Errorf("Error reading E-Mail Address: %v\n", err)
		os.Exit(1)
	}
	encryptedEmail := utils.EncryptedString(email)
	magicLinkWhitelist.Email = &encryptedEmail
}

func readSecondary(reader *bufio.Reader, magicLinkWhitelist *models.MagicLinkWhitelist) {
	reason, err := cli.ReadLine(reader, "Enter reason for whitelisting (optional)")
	if err != nil {
		fmt.Errorf("Error reading Reason: %v\n", err)
		os.Exit(1)
	}
	if reason != "" {
		magicLinkWhitelist.Reason = &reason
	}

	notes, err := cli.ReadLine(reader, "Enter additional notes (optional)")
	if err != nil {
		fmt.Errorf("Error reading Notes: %v\n", err)
		os.Exit(1)
	}
	if notes != "" {
		magicLinkWhitelist.Notes = &notes
	}
}
