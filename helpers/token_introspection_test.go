package helpers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/idtoken"
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

func TestParseTokenIntrospectionRequest(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "http://localhost:8080")
	t.Setenv("KEY_HS256", "dGVzdAo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("Failed to load client fixture: %v", err)
	}

	var authorization models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &authorization); err != nil {
		t.Fatalf("Failed to load authorization fixture: %v", err)
	}

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	isConfidential := true
	client.IsConfidential = &isConfidential
	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	authorization.UserID = user.ID
	authorization.User = &user
	authorization.ClientID = client.ID
	authorization.Client = &client
	if err := authorization.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TI_SNAPSHOT_INIT))

	type testStruct struct {
		name          string
		preHook       func(ctx context.Context, db bun.IDB) (string, error) // returns token
		createHeaders func(ctx context.Context, db bun.IDB) map[string]string
		wantStatus    int
		wantActive    bool
	}

	tests := []testStruct{
		{
			name: "valid token introspection request",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				var token *models.Token
				var err error
				if token, err = models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization); err != nil {
					return "", err
				}
				return string(token.Value), nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				plain := fmt.Sprintf("%s:%s", client.ID, client.Secret)
				enc := base64.StdEncoding.EncodeToString([]byte(plain))

				headers := map[string]string{"Authorization": "Basic " + enc, "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: true,
		},
		{
			name: "valid token introspection request - bearer token",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				var token *models.Token
				var err error
				if token, err = models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization); err != nil {
					return "", err
				}
				return string(token.Value), nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				var token *models.Token
				var err error
				if token, err = models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization); err != nil {
					return nil
				}

				headers := map[string]string{"Authorization": "Bearer " + string(token.Value), "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: true,
		},
		{
			name: "valid token introspection request - client_credentials token",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				var token *models.Token
				var err error
				if token, err = models.CreateToken(ctx, db, string(utils.CLIENT_CREDENTIALS_TYPE), &client); err != nil {
					return "", err
				}
				return string(token.Value), nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				plain := fmt.Sprintf("%s:%s", client.ID, client.Secret)
				enc := base64.StdEncoding.EncodeToString([]byte(plain))

				headers := map[string]string{"Authorization": "Basic " + enc, "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: true,
		},
		{
			name: "valid token introspection request - jwt token",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				jwt, err := idtoken.NewSignedJWTFromAuthorization(&authorization)
				if err != nil {
					return "", err
				}

				return jwt, nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				plain := fmt.Sprintf("%s:%s", client.ID, client.Secret)
				enc := base64.StdEncoding.EncodeToString([]byte(plain))

				headers := map[string]string{"Authorization": "Basic " + enc, "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: true,
		},
		{
			name: "valid token introspection request - jwt token with bearer",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				jwt, err := idtoken.NewSignedJWTFromAuthorization(&authorization)
				if err != nil {
					return "", err
				}

				return jwt, nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				jwt, err := idtoken.NewSignedJWTFromAuthorization(&authorization)
				if err != nil {
					return nil
				}

				headers := map[string]string{"Authorization": "Bearer " + jwt, "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: true,
		},
		{
			name: "invalid token introspection request - missing authorization",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				var token *models.Token
				var err error
				if token, err = models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization); err != nil {
					return "", err
				}
				return string(token.Value), nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 401,
			wantActive: false,
		},
		{
			name: "invalid token introspection request - invalid token",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				return "invalidtokenvalue", nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				plain := fmt.Sprintf("%s:%s", client.ID, client.Secret)
				enc := base64.StdEncoding.EncodeToString([]byte(plain))

				headers := map[string]string{"Authorization": "Basic " + enc, "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 200,
			wantActive: false,
		},
		{
			name: "invalid token introspection request - invalid bearer token",
			preHook: func(ctx context.Context, db bun.IDB) (string, error) {
				return "invalidtokenvalue", nil
			},
			createHeaders: func(ctx context.Context, db bun.IDB) map[string]string {
				headers := map[string]string{"Authorization": "Bearer invalidtokenvalue", "Content-Type": "application/x-www-form-urlencoded"}
				return headers
			},
			wantStatus: 401,
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn := db.Connect(ctx)
				defer conn.Close()
				parsedReq, err := ParseTokenIntrospectionRequest(r.Context(), conn, r)
				if err != nil {
					err.Write(w)
					return
				}
				if err := parsedReq.CreateResponse(r.Context(), conn).Write(w); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}))

			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close DB connection: %v", err)
				}
				server.Close()
				pgContainer.Restore(ctx, postgres.WithSnapshotName(TI_SNAPSHOT_INIT))
			})

			var token string
			var err error
			if tt.preHook != nil {
				token, err = tt.preHook(ctx, conn)
				if err != nil {
					t.Fatalf("preHook failed: %v", err)
				}
			}

			headers := tt.createHeaders(ctx, conn)

			body := url.Values{
				"token": {token},
			}

			req, err := http.NewRequest("POST", server.URL, bytes.NewBufferString(body.Encode()))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			httpClient := &http.Client{}

			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Unexpected status code: got %v, want %v", resp.StatusCode, tt.wantStatus)
			}

			if resp.StatusCode == 200 {
				var tir tokenIntrospectionResponse
				respErr := json.NewDecoder(resp.Body).Decode(&tir)
				if respErr != nil {
					t.Fatalf("Failed to decode response body: %v", respErr)
				}

				assert.Equal(t, tt.wantActive, tir.Active, "Unexpected token active status")

				if tt.wantActive {
					assert.NotEmpty(t, tir.TokenType, "Token type should not be empty for active tokens")

					claims, err := idtoken.ParseJWT(token)
					if err == nil {
						t.Logf("Successfully parsed JWT: %v", claims)
					}

					token, err := models.GetTokenByValue(ctx, conn, token)
					if err == nil {
						t.Logf("Successfully fetched token from DB: %v", token)
					}

					if token != nil {

						if token.Scope != nil {
							assert.Equal(t, utils.ScopeSlice(*token.Scope), tir.Scope, "Scope does not match")
						} else if token.Authorization != nil {
							assert.Equal(t, utils.ScopeSlice(token.Authorization.Scope), tir.Scope, "Scope does not match")
						}

						assert.Equal(t, token.CreatedAt.CreatedAt.Unix(), (*time.Time)(tir.IssuedAt).Unix(), "IssuedAt does not match token creation time")
						assert.Equal(t, token.ExpiresAt.ExpiresAt.Unix(), (*time.Time)(tir.ExpiresAt).Unix(), "ExpiresAt does not match token expiry time")
					} else if claims != nil {
						assert.Equal(t, claims.Scope, tir.Scope, "Scope does not match")
						assert.Equal(t, claims.User.ID.String(), tir.Sub, "Subject does not match")
						assert.Equal(t, claims.Audience[0], tir.Client, "Client ID does not match")
						assert.Equal(t, time.Time(claims.IssuedAt).Unix(), (*time.Time)(tir.IssuedAt).Unix(), "IssuedAt does not match")
						assert.Equal(t, time.Time(claims.ExpiresAt).Unix(), (*time.Time)(tir.ExpiresAt).Unix(), "ExpiresAt does not match")
					}
				}
			}
		})
	}
}
