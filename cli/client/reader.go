package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saschazar21/go-oidc-provider/cli"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func readOwner(ctx context.Context, db bun.IDB, reader *bufio.Reader, client *models.Client) {
	var user *models.User
	for {
		email, err := cli.ReadLine(reader, "Owner (e-mail address)")
		if err != nil {
			fmt.Printf("Error reading Owner: %v\n", err)
			os.Exit(1)
		}
		if email == "" {
			fmt.Println("Owner is required, exiting...")
			os.Exit(1)
		}

		user, err = models.GetUserByEmail(ctx, db, email)
		if err != nil {
			fmt.Printf("Error fetching user by e-mail address: %v\nCheck your input and try again...\n", email)
		} else {
			break
		}
	}

	client.OwnerID = user.ID
	client.Owner = user
}

func readPrimary(reader *bufio.Reader, client *models.Client) {
	name, err := cli.ReadLine(reader, "Client Name")
	if err != nil {
		fmt.Printf("Error reading Client Name: %v\n", err)
		os.Exit(1)
	}
	if name == "" {
		fmt.Println("Client Name is required, exiting...")
		os.Exit(1)
	}

	client.Name = name

	redirectURI, err := cli.ReadLine(reader, "Redirect URI (comma-separated for multiple)")
	if err != nil {
		fmt.Printf("Error reading Redirect URI: %v\n", err)
		os.Exit(1)
	}
	if redirectURI == "" {
		fmt.Println("Redirect URI is required, exiting...")
		os.Exit(1)
	}

	client.RedirectURIs = []string{}
	for _, uri := range strings.Split(redirectURI, ",") {
		client.RedirectURIs = append(client.RedirectURIs, strings.TrimSpace(uri))
	}
}

func readSecondary(reader *bufio.Reader, client *models.Client) {
	clientType, err := cli.ReadLine(reader, "Client Type", "confidential", "public")
	if err != nil {
		fmt.Printf("Error reading Client Type: %v\n", err)
		os.Exit(1)
	}
	if clientType == "" {
		fmt.Println("Client Type is required, exiting...")
		os.Exit(1)
	}

	var isConfidential bool
	var isPKCERequired bool
	if clientType == "confidential" {
		isConfidential = true
		isPKCERequired = false
	} else {
		isPKCERequired = true
		isConfidential = false
	}

	if isConfidential {
		isPKCERequired, err = cli.ReadYN(reader, "Is PKCE required for this confidential client?")
		if err != nil {
			fmt.Printf("Error reading PKCE requirement: %v\n", err)
			os.Exit(1)
		}
	}

	client.IsConfidential = &isConfidential
	client.IsPKCERequired = &isPKCERequired

	grantTypes, err := cli.ReadLine(reader, "Allowed Grant Types (comma-separated for multiple)", "authorization_code", "implicit", "client_credentials", "refresh_token")
	if err != nil {
		fmt.Printf("Error reading Grant Types: %v\n", err)
		os.Exit(1)
	}
	if grantTypes == "" {
		fmt.Println("At least one Grant Type is required, exiting...")
		os.Exit(1)
	}

	grantTypeList := []utils.GrantType{}
	for _, gt := range strings.Split(grantTypes, ",") {
		grantType := utils.GrantType(strings.TrimSpace(gt))
		grantTypeList = append(grantTypeList, grantType)
	}
	client.GrantTypes = &grantTypeList

	responseTypes, err := cli.ReadLine(reader, "Allowed Response Types (comma-separated for multiple)", "code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token")
	if err != nil {
		fmt.Printf("Error reading Response Types: %v\n", err)
		os.Exit(1)
	}
	if responseTypes == "" {
		fmt.Println("At least one Response Type is required, exiting...")
		os.Exit(1)
	}

	responseTypeList := []utils.ResponseType{}
	for _, rt := range strings.Split(responseTypes, ",") {
		responseType := utils.ResponseType(strings.TrimSpace(rt))
		responseTypeList = append(responseTypeList, responseType)
	}
	client.ResponseTypes = &responseTypeList
}

func readTertiary(reader *bufio.Reader, client *models.Client) {
	clientDescription, err := cli.ReadLine(reader, "Client Description (optional)")
	if err != nil {
		fmt.Printf("Error reading Client Description: %v\n", err)
		os.Exit(1)
	}
	if clientDescription != "" {
		client.Description = &clientDescription
	}

	clientUri, err := cli.ReadLine(reader, "Client URI (optional)")
	if err != nil {
		fmt.Printf("Error reading Client URI: %v\n", err)
		os.Exit(1)
	}
	if clientUri != "" {
		client.URI = &clientUri
	}

	logoUri, err := cli.ReadLine(reader, "Logo URI (optional)")
	if err != nil {
		fmt.Printf("Error reading Logo URI: %v\n", err)
		os.Exit(1)
	}
	if logoUri != "" {
		client.Logo = &logoUri
	}

	postLogoutUris, err := cli.ReadLine(reader, "Post Logout Redirect URIs (comma-separated for multiple, optional)")
	if err != nil {
		fmt.Printf("Error reading Post Logout Redirect URIs: %v\n", err)
		os.Exit(1)
	}
	if postLogoutUris != "" {
		client.PostLogoutRedirectURIs = []string{}
		for _, uri := range strings.Split(postLogoutUris, ",") {
			client.PostLogoutRedirectURIs = append(client.PostLogoutRedirectURIs, strings.TrimSpace(uri))
		}
	}

	accessTokenLifetimeStr, err := cli.ReadLine(reader, "Access Token Lifetime in seconds (optional, press Enter to skip)")
	if err != nil {
		fmt.Printf("Error reading Access Token Lifetime: %v\n", err)
		os.Exit(1)
	}
	if accessTokenLifetimeStr != "" {
		var accessTokenLifetime int64
		_, err := fmt.Sscanf(accessTokenLifetimeStr, "%d", &accessTokenLifetime)
		if err != nil || accessTokenLifetime <= 0 {
			fmt.Println("Invalid Access Token Lifetime, exiting...")
			os.Exit(1)
		}
		client.AccessTokenLifetime = accessTokenLifetime
	}

	if client.GrantTypes == nil || utils.ContainsValue(*client.GrantTypes, utils.GrantType("refresh_token")) {
		refreshTokenLifetimeStr, err := cli.ReadLine(reader, "Refresh Token Lifetime in seconds (optional, press Enter to skip)")
		if err != nil {
			fmt.Printf("Error reading Refresh Token Lifetime: %v\n", err)
			os.Exit(1)
		}
		if refreshTokenLifetimeStr != "" {
			var refreshTokenLifetime int64
			_, err := fmt.Sscanf(refreshTokenLifetimeStr, "%d", &refreshTokenLifetime)
			if err != nil || refreshTokenLifetime <= 0 {
				fmt.Println("Invalid Refresh Token Lifetime, exiting...")
				os.Exit(1)
			}
			client.RefreshTokenLifetime = refreshTokenLifetime
		}
	}

	idTokenLifetimeStr, err := cli.ReadLine(reader, "ID Token Lifetime in seconds (optional, press Enter to skip)")
	if err != nil {
		fmt.Printf("Error reading ID Token Lifetime: %v\n", err)
		os.Exit(1)
	}
	if idTokenLifetimeStr != "" {
		var idTokenLifetime int64
		_, err := fmt.Sscanf(idTokenLifetimeStr, "%d", &idTokenLifetime)
		if err != nil || idTokenLifetime <= 0 {
			fmt.Println("Invalid ID Token Lifetime, exiting...")
			os.Exit(1)
		}
		client.IDTokenLifetime = idTokenLifetime
	}

	supportedAlgorithms := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512", "EdDSA"}
	idTokenSignedResponseAlg, err := cli.ReadLine(reader, "Preferred ID Token Signing Algorithm (optional, press Enter to skip)", supportedAlgorithms...)
	if err != nil {
		fmt.Printf("Error reading ID Token Signing Algorithm: %v\n", err)
		os.Exit(1)
	}
	if idTokenSignedResponseAlg != "" {
		alg := utils.SigningAlgorithm(idTokenSignedResponseAlg)
		client.IDTokenSignedResponseAlg = &alg
	}
}
