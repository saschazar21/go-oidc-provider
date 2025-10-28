package endpoints

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
	TOKEN_SNAPSHOT_INIT = "token_snapshot_init"
)

func TestHandleToken(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv("KEY_HS256", "c2VjcmV0Cg==")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create test container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("failed to load authorization fixture: %v", err)
	}

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	auth.UserID = user.ID
	auth.ClientID = client.ID
	auth.User = &user
	auth.Client = &client
	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_SNAPSHOT_INIT))

	type testStruct struct {
		name               string
		preHook            func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request
		expectedStatusCode int
	}

	tests := []testStruct{
		{
			name: "Valid authorization code grant",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				a := auth
				token, err := models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &a)
				if err != nil {
					t.Fatalf("failed to create authorization code token: %v", err)
				}

				var q url.Values = make(map[string][]string)
				q.Add("grant_type", "authorization_code")
				q.Add("code", string(token.Value))
				q.Add("redirect_uri", auth.RedirectURI)

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(client.ID, string(*client.Secret))
				return req
			},
			expectedStatusCode: http.StatusOK,
		}, {
			name: "client_credentials grant",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				isConfidential := true
				client := models.Client{
					Name: "Client Credentials Client",
					RedirectURIs: []string{
						client.RedirectURIs[0],
					},
					GrantTypes:     &[]utils.GrantType{utils.CLIENT_CREDENTIALS},
					OwnerID:        user.ID,
					IsConfidential: &isConfidential,
				}
				if err := client.Save(ctx, db); err != nil {
					t.Fatalf("failed to save client: %v", err)
				}

				var q url.Values = make(map[string][]string)
				q.Add("grant_type", "client_credentials")

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(client.ID, string(*client.Secret))
				return req
			},
			expectedStatusCode: http.StatusOK,
		}, {
			name: "Invalid grant type",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				var q url.Values = make(map[string][]string)
				q.Add("grant_type", "invalid_grant_type")
				q.Add("client_id", client.ID)
				q.Add("client_secret", string(*client.Secret))

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			expectedStatusCode: http.StatusBadRequest,
		}, {
			name: "Missing client authentication",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				var q url.Values = make(map[string][]string)
				q.Add("grant_type", "authorization_code")

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		}, {
			name: "Invalid authorization code",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				var q url.Values = make(map[string][]string)
				q.Add("grant_type", "authorization_code")
				q.Add("code", "invalid_code")
				q.Add("redirect_uri", auth.RedirectURI)

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(client.ID, string(*client.Secret))
				return req
			},
			expectedStatusCode: http.StatusBadRequest,
		}, {
			name: "Unsupported grant_type",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				var q url.Values = make(map[string][]string)
				q.Add("grant_type", string(utils.CLIENT_CREDENTIALS))
				q.Add("client_id", client.ID)
				q.Add("client_secret", string(*client.Secret))

				req, httpErr := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(q.Encode()))
				if httpErr != nil {
					t.Fatalf("failed to create request: %v", httpErr)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleToken))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close database connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_SNAPSHOT_INIT))
			})

			client := &http.Client{}
			req := tt.preHook(t, ctx, conn, server.URL)

			// Perform the request
			res, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to perform request: %v", err)
			}
			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			if res.StatusCode != tt.expectedStatusCode {
				t.Fatalf("unexpected status code: got %d, want %d. Response body: %s", res.StatusCode, tt.expectedStatusCode, string(body))
			}

			contentType := res.Header.Get("Content-Type")
			assert.Equal(t, "application/json", contentType, "unexpected Content-Type header")

			if tt.expectedStatusCode == http.StatusOK {
				assert.Contains(t, string(body), "\"token_type\":\"Bearer\"", "response body does not contain token_type=Bearer")
			} else {
				assert.Contains(t, string(body), "\"error\"", "response body does not contain error field")
			}
		})
	}
}
