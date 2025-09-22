package helpers

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	TOKEN_TEST_INIT = "token_test_init"
)

func TestExchangeToken(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client models.Client
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

	var authorization models.Authorization
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
		PreHook          func(ctx context.Context, db bun.IDB) (*models.Token, error)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				a := models.Authorization{
					ID:    authorization.ID,
					Scope: append(authorization.Scope, "offline_access"),
				}

				_, _ = db.NewUpdate().
					Model(&a).
					WherePK().
					OmitZero().
					Exec(ctx)

				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return &models.Token{Value: utils.HashedString("invalid")}, nil
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
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

			tokens, err := tt.Request.HandleRequest(ctx, db)
			if (err != nil) != tt.WantErr {
				t.Fatalf("HandleRequest() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, tokens, "Expected tokens to be non-nil")
				assert.NotNil(t, tokens[utils.ACCESS_TOKEN_TYPE], "Expected access token to be set")

				if tt.WantRefreshToken {
					assert.NotNil(t, tokens[utils.REFRESH_TOKEN_TYPE], "Expected refresh token to be set")
				}

				token := models.Token{
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

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client models.Client
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

	var authorization models.Authorization
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
		PreHook func(ctx context.Context, db bun.IDB) (*models.Token, error)
		Request tokenRequest
		WantErr bool
	}

	clientSecret := string(*client.Secret)
	invalidClientSecret := "invalid"

	tests := []testStruct{
		{
			Name: "Rotate Refresh Token Successfully",
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return &models.Token{Value: utils.HashedString("invalid")}, nil
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
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
			PreHook: func(ctx context.Context, db bun.IDB) (*models.Token, error) {
				return models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
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

			tokens, err := tt.Request.HandleRequest(ctx, db)
			if (err != nil) != tt.WantErr {
				t.Fatalf("HandleRequest() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, tokens, "Expected tokens to be non-nil")
				assert.NotNil(t, tokens[utils.ACCESS_TOKEN_TYPE], "Expected AccessToken to be set")
				assert.NotNil(t, tokens[utils.REFRESH_TOKEN_TYPE], "Expected RefreshToken to be set")
				assert.NotEqual(t, authorization.ID, tokens[utils.ACCESS_TOKEN_TYPE].AuthorizationID, "Expected new AccessToken to have different AuthorizationID")

				authorization := models.Authorization{
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

func TestTokenRequest(t *testing.T) {
	type testStruct struct {
		Name    string
		Request http.Request
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Valid Request with Basic Auth",
			Request: http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic dGVzdC1pZDpwYXNzd29yZA=="}, // base64 for "test-id:password"
					"Content-Type":  []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":   []string{"authorization_code"},
					"code":         []string{"valid-code"},
					"redirect_uri": []string{"https://client.example.com/callback"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with Client Credentials in Body",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"authorization_code"},
					"code":          []string{"valid-code"},
					"redirect_uri":  []string{"https://client.example.com/callback"},
					"client_id":     []string{"test-id"},
					"client_secret": []string{"password"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with PKCE",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"authorization_code"},
					"code":          []string{"valid-code"},
					"redirect_uri":  []string{"https://client.example.com/callback"},
					"client_id":     []string{"test-id"},
					"code_verifier": []string{"valid-code-verifier"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with Refresh Token",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"refresh_token"},
					"refresh_token": []string{"valid-refresh-token"},
					"client_id":     []string{"test-id"},
					"client_secret": []string{"password"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Invalid Method",
			Request: http.Request{
				Method: http.MethodGet,
			},
			WantErr: true,
		},
		{
			Name: "Missing Required Fields",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type": []string{"authorization_code"},
					// Missing 'code' and 'redirect_uri'
				},
				Method: http.MethodPost,
			},
			WantErr: true,
		},
		{
			Name: "Invalid Content Type",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body:   io.NopCloser(strings.NewReader(`{"grant_type":"authorization_code","code":"valid-code","redirect_uri":"https://client.example.com/callback"}`)),
				Method: http.MethodPost,
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			req := &tt.Request

			// If the request body is set, read it into PostForm
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("Failed to read request body: %v", err)
				}
				req.PostForm, err = url.ParseQuery(string(bodyBytes))
				if err != nil {
					t.Fatalf("Failed to parse request body: %v", err)
				}
			} else {
				req.PostForm = req.Form
			}

			_, err := ParseTokenRequest(req)
			if (err != nil) != tt.WantErr {
				t.Errorf("ParseTokenRequest() error = %v, wantErr %v", err, tt.WantErr)
			}
		})
	}
}
