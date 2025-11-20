package endpoints

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	TI_SNAPSHOT_INIT = "ti_snapshot_init"
)

func TestHandleTokenIntrospection(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://oidc-provider.test")
	t.Setenv("KEY_HS256", "dGVzdAo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create test container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("Failed to load authorization fixture: %v", err)
	}

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	client.OwnerID = user.ID

	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	auth.UserID = user.ID
	auth.User = &user
	auth.ClientID = client.ID
	auth.Client = &client

	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TI_SNAPSHOT_INIT))

	type testStruct struct {
		name            string
		preHook         func(ctx context.Context, conn bun.IDB) (tokenString string)
		generateRequest func(tokenString string, serverURL string) *http.Request
		wantActive      bool
		wantStatus      int
	}

	tests := []testStruct{
		{
			name: "Valid token introspection request",
			preHook: func(ctx context.Context, conn bun.IDB) (tokenString string) {
				token, err := models.CreateToken(ctx, conn, string(utils.ACCESS_TOKEN_TYPE), &auth)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				return string(token.Value)
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				body := url.Values{
					"token": []string{tokenString},
				}
				req, _ := http.NewRequest("POST", serverURL+helpers.TOKEN_INTROSPECTION_ENDPOINT, strings.NewReader(body.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantActive: true,
			wantStatus: 200,
		},
		{
			name: "Invalid token introspection request with inactive token",
			preHook: func(ctx context.Context, conn bun.IDB) (tokenString string) {
				token, err := models.CreateToken(ctx, conn, string(utils.ACCESS_TOKEN_TYPE), &auth)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				if _, err := conn.NewUpdate().
					Model(&models.Token{}).
					Set("is_active = FALSE").
					Where("token_value = ?", token.Value).
					Exec(ctx); err != nil {
					t.Fatalf("Failed to deactivate token: %v", err)
				}

				return string(token.Value)
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				credentials := base64.StdEncoding.EncodeToString([]byte(client.ID + ":" + string(*client.Secret)))
				body := url.Values{
					"token": []string{tokenString},
				}
				req, _ := http.NewRequest("POST", serverURL+helpers.TOKEN_INTROSPECTION_ENDPOINT, strings.NewReader(body.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Authorization", "Basic "+credentials)
				return req
			},
			wantActive: false,
			wantStatus: 200,
		},
		{
			name: "Invalid request using GET method",
			preHook: func(ctx context.Context, conn bun.IDB) (tokenString string) {
				return ""
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				credentials := base64.StdEncoding.EncodeToString([]byte(client.ID + ":" + string(*client.Secret)))
				req, _ := http.NewRequest("GET", serverURL+helpers.TOKEN_INTROSPECTION_ENDPOINT, nil)
				req.Header.Set("Authorization", "Basic "+credentials)
				return req
			},
			wantActive: false,
			wantStatus: 405,
		},
		{
			name: "Preflight CORS request using OPTIONS method",
			preHook: func(ctx context.Context, conn bun.IDB) (tokenString string) {
				return ""
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("OPTIONS", serverURL+helpers.TOKEN_INTROSPECTION_ENDPOINT, nil)
				req.Header.Set("Origin", "https://example.com")
				req.Header.Set("Access-Control-Request-Method", "POST")
				return req
			},
			wantActive: false,
			wantStatus: 204,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleTokenIntrospection))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close db connection: %v", err)
				}

				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TI_SNAPSHOT_INIT))
			})

			tokenString := tt.preHook(ctx, conn)
			req := tt.generateRequest(tokenString, server.URL)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if resp.StatusCode == http.StatusOK {
				var introspectionResponse struct {
					Active    bool             `json:"active"`
					Scope     utils.ScopeSlice `json:"scope,omitempty"`
					Client    string           `json:"client_id,omitempty"`
					Sub       string           `json:"sub,omitempty"`
					Issuer    string           `json:"iss,omitempty"`
					TokenType utils.TokenType  `json:"token_type,omitempty"`
				}

				if err := json.NewDecoder(resp.Body).Decode(&introspectionResponse); err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}

				assert.Equal(t, tt.wantActive, introspectionResponse.Active, "Token active status does not match")

				if tt.wantActive {
					str := ""
					token, err := models.GetTokenByValue(ctx, conn, tokenString)
					if err != nil {
						t.Fatalf("Failed to fetch token from database: %v", err)
					}

					clientId := token.ClientID
					if token.Authorization != nil {
						clientId = &token.Authorization.ClientID
					}
					if clientId == nil {
						clientId = &str
					}

					scope := token.Scope
					if token.Authorization != nil {
						scope = &token.Authorization.Scope
					}

					var sub string
					userId := token.UserID
					if token.Authorization != nil {
						userId = &token.Authorization.UserID
					}
					if userId != nil {
						sub = userId.String()
					}

					assert.Equal(t, utils.ScopeSlice(*scope), introspectionResponse.Scope, "Token scope does not match")
					assert.Equal(t, *clientId, introspectionResponse.Client, "Client ID does not match")
					assert.Equal(t, sub, introspectionResponse.Sub, "Subject does not match")
					assert.Equal(t, token.Type, introspectionResponse.TokenType, "Token type does not match")
				}
			}
		})
	}
}
