package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	USERINFO_SNAPSHOT_INIT = "userinfo_snapshot_init"
)

func TestHandleUserinfo(t *testing.T) {
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

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(USERINFO_SNAPSHOT_INIT))

	type testStruct struct {
		name            string
		preHook         func(ctx context.Context, conn bun.IDB) string
		generateRequest func(tokenString string, serverURL string) *http.Request
		wantStatus      int
	}

	tests := []testStruct{
		{
			name: "Valid bearer token",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				token, err := models.CreateToken(ctx, conn, string(utils.ACCESS_TOKEN_TYPE), &auth)
				if err != nil {
					t.Fatalf("Failed to create bearer token: %v", err)
				}
				return string(token.Value)
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("GET", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid client-credentials token",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				token, err := models.CreateToken(ctx, conn, string(utils.CLIENT_CREDENTIALS_TYPE), &client)
				if err != nil {
					t.Fatalf("Failed to create client-credentials token: %v", err)
				}
				return string(token.Value)
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("GET", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Valid custom token",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				token, err := models.CreateToken(ctx, conn, string(utils.CUSTOM_TOKEN_TYPE), &user)
				if err != nil {
					t.Fatalf("Failed to create custom token: %v", err)
				}
				return string(token.Value)
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("POST", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Valid JWT bearer token",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				jwtToken, err := idtoken.NewSignedJWTFromAuthorization(&auth)
				if err != nil {
					t.Fatalf("Failed to create JWT bearer token: %v", err)
				}
				return jwtToken
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("GET", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "Invalid bearer token",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				return "invalidtoken"
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("GET", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Preflight OPTIONS request",
			preHook: func(ctx context.Context, conn bun.IDB) string {
				return ""
			},
			generateRequest: func(tokenString string, serverURL string) *http.Request {
				req, _ := http.NewRequest("OPTIONS", serverURL+helpers.USERINFO_ENDPOINT, nil)
				req.Header.Set("Origin", "https://example.com")
				req.Header.Set("Access-Control-Request-Method", "POST")
				return req
			},
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleUserinfo))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(USERINFO_SNAPSHOT_INIT))
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

			if tt.wantStatus == http.StatusOK {
				var u models.User
				if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}

				assert.Equal(t, user.ID, u.ID, "User ID does not match")
			}
		})
	}
}
