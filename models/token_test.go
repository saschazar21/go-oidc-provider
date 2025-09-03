package models

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const TOKEN_TEST_INIT = "token_test_init"

func TestToken(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	var authorization Authorization
	if err := test.LoadFixture("authorization_approved.json", &authorization); err != nil {
		t.Fatalf("Failed to load fixture: %v", err)
	}

	authorization.UserID = user.ID
	authorization.User = &user
	authorization.ClientID = client.ID
	authorization.Client = &client
	if err := authorization.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))

	type testStruct struct {
		Name            string
		CreateToken     func(ctx context.Context, db bun.IDB) (*Token, error)
		WantErr         bool
		WantRetrieveErr bool
	}

	tests := []testStruct{
		{
			Name: "Create Access Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
			},
			WantErr: false,
		},
		{
			Name: "Create Refresh Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			WantErr: false,
		},
		{
			Name: "Create Authorization Code Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token with User",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token for testing"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					User:        &user,
					Description: &msg,
					Scope:       &scope,
				}
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, customToken)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token with UserID",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token with UserID"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					UserID:      &user.ID,
					Description: &msg,
					Scope:       &scope,
				}
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, customToken)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token without User",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token without user"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					Description: &msg,
					Scope:       &scope,
				}
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, customToken)
			},
			WantErr: true,
		},
		{
			Name: "Create Client Credentials Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.CLIENT_CREDENTIALS_TYPE), &client)
			},
			WantErr: false,
		},
		{
			Name: "Create Token with Invalid Type",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, "invalid_type", &authorization)
			},
			WantErr: true,
		},
		{
			Name: "Create Token with Nil Authorization",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), nil)
			},
			WantErr: true,
		},
		{
			Name: "Create Client Credentials Token with Nil Client",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.CLIENT_CREDENTIALS_TYPE), nil)
			},
			WantErr: true,
		},
		{
			Name: "Create Custom Token with Nil Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				var token *Token
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, token)
			},
			WantErr: true,
		},
		{
			Name: "Create Custom Token with User",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, &user)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token with Client",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, &client)
			},
			WantErr: true,
		},
		{
			Name: "Create and Revoke Access Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				token, err := CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					return nil, err
				}

				hint := string(utils.ACCESS_TOKEN_TYPE)
				err = RevokeTokenByValue(ctx, db, string(token.Value), &hint)
				if err != nil {
					return nil, err
				}

				retrievedToken := Token{
					Value: utils.HashedString(token.Value),
				}

				if err := db.NewSelect().
					Model(&retrievedToken).
					Where("\"token\".\"token_value\" = ?", utils.HashedString(token.Value)).
					Scan(ctx); err != nil {
					return nil, err
				}

				assert.False(t, *retrievedToken.IsActive, "Token should be inactive after revocation")
				assert.NotNil(t, retrievedToken.RevocationReason, "Revocation reason should be set")

				return token, nil
			},
			WantErr:         false,
			WantRetrieveErr: true,
		},
		{
			Name: "Create and Revoke token set",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				accessToken, err := CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					return nil, err
				}
				refreshToken, err := CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
				if err != nil {
					return nil, err
				}

				err = RevokeTokenByValue(ctx, db, string(refreshToken.Value), nil)
				if err != nil {
					return nil, err
				}

				retrievedAccessToken := Token{
					Value: utils.HashedString(accessToken.Value),
				}

				if err := db.NewSelect().
					Model(&retrievedAccessToken).
					Where("\"token\".\"token_value\" = ?", utils.HashedString(accessToken.Value)).
					Scan(ctx); err != nil {
					return nil, err
				}

				assert.False(t, *retrievedAccessToken.IsActive, "Access token should be inactive after revocation")
				assert.NotNil(t, retrievedAccessToken.RevocationReason, "Revocation reason should be set for access token")

				retrievedRefreshToken := Token{
					Value: utils.HashedString(refreshToken.Value),
				}

				if err := db.NewSelect().
					Model(&retrievedRefreshToken).
					Where("\"token\".\"token_value\" = ?", utils.HashedString(refreshToken.Value)).
					Scan(ctx); err != nil {
					return nil, err
				}

				assert.False(t, *retrievedRefreshToken.IsActive, "Refresh token should be inactive after revocation")
				assert.NotNil(t, retrievedRefreshToken.RevocationReason, "Revocation reason should be set for refresh token")

				return accessToken, nil
			},
			WantErr:         false,
			WantRetrieveErr: true,
		},
		{
			Name: "Create and Revoke Authorization Code Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				token, err := CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
				if err != nil {
					return nil, err
				}
				err = RevokeTokenByValue(ctx, db, string(token.Value), nil)
				if err != nil {
					return nil, err
				}

				var retrievedToken Token
				if err := db.NewSelect().
					Model((*Token)(nil)).
					Where("\"token\".\"token_value\" = ?", utils.HashedString(token.Value)).
					Scan(ctx, &retrievedToken); err != nil {
					return nil, err
				}

				assert.False(t, *retrievedToken.IsActive, "Token should be inactive after revocation")
				assert.NotNil(t, retrievedToken.RevocationReason, "Revocation reason should be set")

				return token, nil
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			token, err := tt.CreateToken(ctx, db)
			if (err != nil) != tt.WantErr {
				t.Fatalf("CreateToken() error = %v, wantErr %v", err, tt.WantErr)
			}

			if err == nil {
				assert.NotNil(t, token, "Expected token to be non-nil")
				assert.NotEmpty(t, token.ID, "Expected token ID to be set")
				assert.NotEmpty(t, token.Value, "Expected token Value to be set")
				assert.NotEmpty(t, token.ExpiresAt.ExpiresAt, "Expected token ExpiresAt to be set")

				tokenHash, hashErr := token.GenerateTokenHash()
				if hashErr != nil {
					t.Fatalf("GenerateTokenHash() error = %v", hashErr)
				}
				assert.NotEmpty(t, tokenHash, "Expected token hash to be generated")

				var retrievedToken *Token
				retrievedToken, err = GetTokenByValue(ctx, db, string(token.Value))

				if (err != nil) != tt.WantRetrieveErr {
					t.Fatalf("GetTokenByValue() error = %v", err)
				}

				if !tt.WantRetrieveErr {
					assert.NotNil(t, retrievedToken, "Expected retrieved token to be non-nil")
					assert.Equal(t, token.ID, retrievedToken.ID, "Expected retrieved token ID to match")
					assert.Equal(t, token.Type, retrievedToken.Type, "Expected retrieved token Type to match")
				}
			} else {
				assert.Nil(t, token, "Expected token to be nil on error")
			}
		})
	}
}

func TestExchangeToken(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	isConfidential := true

	client.OwnerID = user.ID
	client.IsConfidential = &isConfidential
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	var authorization Authorization
	if err := test.LoadFixture("authorization_approved.json", &authorization); err != nil {
		t.Fatalf("Failed to load fixture: %v", err)
	}

	authorization.UserID = user.ID
	authorization.User = &user
	authorization.ClientID = client.ID
	authorization.Client = &client
	if err := authorization.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()
	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))

	type testStruct struct {
		Name             string
		PreHook          func(ctx context.Context, db bun.IDB) (*Token, error)
		Request          tokenRequest
		WantErr          bool
		WantRefreshToken bool
	}

	clientSecret := string(*client.Secret)
	invalidSecret := "invalid"
	invalidRedirectURI := "https://invalid.example.com/callback"

	tests := []testStruct{
		{
			Name: "Exchange Authorization Code Successfully",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr: false,
		},
		{
			Name: "Exchange Authorization Code with Refresh Token",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				a := Authorization{
					ID:    authorization.ID,
					Scope: append(authorization.Scope, "offline_access"),
				}

				_, _ = db.NewUpdate().
					Model(&a).
					WherePK().
					OmitZero().
					Exec(ctx)

				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr:          false,
			WantRefreshToken: true,
		},
		{
			Name: "Exchange Access Token with Access Token",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr: true,
		},
		{
			Name: "Exchange Authorization Code with Invalid Token",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return &Token{Value: utils.HashedString("invalid")}, nil
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test,
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr: true,
		},
		{
			Name: "Exchange Authorization Code with Missing Client Secret",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType: "authorization_code",
				ClientID:  client.ID,
				// ClientSecret is nil
				Code:        nil, // Will be set in the test
				RedirectURI: &authorization.RedirectURI,
			},
			WantErr: true,
		},
		{
			Name: "Exchange Authorization Code with Invalid Client Secret",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &invalidSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr: true,
		},
		{
			Name: "Exchange Authorization Code with Missing Client ID",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &authorization.RedirectURI,
			},
			WantErr: true,
		},
		{
			Name: "Exchange Authorization Code with Invalid Redirect URI",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "authorization_code",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				Code:         nil, // Will be set in the test
				RedirectURI:  &invalidRedirectURI,
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			token, err := tt.PreHook(ctx, db)
			if err != nil {
				t.Fatalf("PreHook() error = %v", err)
			}
			if token == nil {
				t.Fatalf("PreHook() returned nil token")
			}

			tt.Request.Code = (*string)(&token.Value)

			tokens, err := ExchangeToken(ctx, db, &tt.Request)
			if (err != nil) != tt.WantErr {
				t.Fatalf("ExchangeToken() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, tokens, "Expected tokens to be non-nil")
				assert.NotNil(t, tokens[utils.ACCESS_TOKEN_TYPE], "Expected access token to be set")

				if tt.WantRefreshToken {
					assert.NotNil(t, tokens[utils.REFRESH_TOKEN_TYPE], "Expected refresh token to be set")
				}

				token := Token{
					Value: utils.HashedString(token.Value),
				}

				if err := db.NewSelect().
					Model(&token).
					Where("\"token\".\"token_value\" = ?", utils.HashedString(token.Value)).
					Scan(ctx); err != nil {
					t.Fatalf("Failed to retrieve authorization code")
				}

				assert.NotNil(t, token.ConsumedAt, "Expected authorization code to be marked as consumed")
				assert.NotNil(t, token.RevocationReason, "Expected authorization code to have revocation reason set")
				assert.Equal(t, token.ConsumedAt, token.RevokedAt, "Expected authorization code ConsumedAt to match RevokedAt")
				assert.False(t, *token.IsActive, "Expected authorization code to be inactive after exchange")
			} else {
				assert.Nil(t, tokens, "Expected tokens to be nil on error")
			}
		})
	}
}

func TestRotateToken(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	isConfidential := true

	client.OwnerID = user.ID
	client.IsConfidential = &isConfidential
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	var authorization Authorization
	if err := test.LoadFixture("authorization_approved.json", &authorization); err != nil {
		t.Fatalf("Failed to load fixture: %v", err)
	}

	authorization.UserID = user.ID
	authorization.User = &user
	authorization.ClientID = client.ID
	authorization.Client = &client
	if err := authorization.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()
	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))

	type testStruct struct {
		Name    string
		PreHook func(ctx context.Context, db bun.IDB) (*Token, error)
		Request tokenRequest
		WantErr bool
	}

	clientSecret := string(*client.Secret)
	invalidClientSecret := "invalid"

	tests := []testStruct{
		{
			Name: "Rotate Refresh Token Successfully",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: false,
		},
		{
			Name: "Rotate Refresh Token with Access Token",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: true,
		},
		{
			Name: "Rotate Refresh Token with Invalid Token",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return &Token{Value: utils.HashedString("invalid")}, nil
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     client.ID,
				ClientSecret: &clientSecret,
				RefreshToken: nil, // Will be set in the test,
			},
			WantErr: true,
		},
		{
			Name: "Rotate Refresh Token with Missing Client Secret",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType: "refresh_token",
				ClientID:  client.ID,
				// ClientSecret is nil
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: true,
		},
		{
			Name: "Rotate Refresh Token with Invalid Client Secret",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     client.ID,
				ClientSecret: &invalidClientSecret,
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: true,
		},
		{
			Name: "Rotate Refresh Token with Missing Client ID",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientSecret: &clientSecret,
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: true,
		},
		{
			Name: "Rotate Refresh Token with Invalid Code Verifier",
			PreHook: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
			},
			Request: tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     client.ID,
				CodeVerifier: &invalidClientSecret,
				RefreshToken: nil, // Will be set in the test
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			preToken, err := tt.PreHook(ctx, db)
			if err != nil {
				t.Fatalf("PreHook() error = %v", err)
			}

			var tokenValue *string
			if preToken != nil {
				v := string(preToken.Value)
				tokenValue = &v
			}

			tt.Request.RefreshToken = tokenValue

			tokens, err := RotateToken(ctx, db, &tt.Request)
			if (err != nil) != tt.WantErr {
				t.Fatalf("RotateToken() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, tokens, "Expected tokens to be non-nil")
				assert.NotNil(t, tokens[utils.ACCESS_TOKEN_TYPE], "Expected AccessToken to be set")
				assert.NotNil(t, tokens[utils.REFRESH_TOKEN_TYPE], "Expected RefreshToken to be set")
				assert.NotEqual(t, authorization.ID, tokens[utils.ACCESS_TOKEN_TYPE].AuthorizationID, "Expected new AccessToken to have different AuthorizationID")

				authorization := Authorization{
					ID: *tokens[utils.ACCESS_TOKEN_TYPE].AuthorizationID,
				}
				err := db.NewSelect().
					Model(&authorization).
					WherePK().
					Relation("ReplacedAuthorization").
					Scan(ctx)
				if err != nil {
					t.Fatalf("Failed to retrieve new authorization: %v", err)
				}
				assert.NotNil(t, authorization.ReplacedAuthorization, "Expected new Authorization to have ReplacedAuthorization set")
			} else {
				assert.Nil(t, tokens, "Expected tokens to be nil on error")
			}
		})
	}
}
