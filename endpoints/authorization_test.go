package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	AUTH_SNAPSHOT_INIT = "auth_snapshot_init"
)

func TestHandleAuthorization(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("failed to load client fixture: %v", err)
	}

	var pendingAuth models.Authorization
	if err := test.LoadFixture("authorization_pending.json", &pendingAuth); err != nil {
		t.Fatalf("failed to load authorization fixture: %v", err)
	}

	var approvedAuth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &approvedAuth); err != nil {
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

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(AUTH_SNAPSHOT_INIT))

	type testStruct struct {
		name              string
		preHook           func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request
		expectedCode      int
		wantErrorResponse bool
		wantStatus        utils.AuthStatus
		wantToken         bool
	}

	tests := []testStruct{
		{
			name: "Create new authorization request",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				req, err := http.NewRequest(http.MethodGet, origin+"/authorize", nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
				q := req.URL.Query()
				q.Add("response_type", "code")
				q.Add("client_id", client.ID)
				q.Add("code_challenge", "challenge")
				q.Add("redirect_uri", client.RedirectURIs[0])
				q.Add("scope", "openid")
				q.Add("state", "xyz")
				q.Add("nonce", "abc")
				req.URL.RawQuery = q.Encode()
				return req
			},
			expectedCode:      http.StatusFound,
			wantErrorResponse: false,
			wantStatus:        utils.PENDING,
			wantToken:         false,
		},
		{
			name: "Render authorization request decision form",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				session := models.Session{
					UserID: user.ID,
				}
				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				req, err := http.NewRequest(http.MethodGet, origin+"/authorize", nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
				q := req.URL.Query()
				q.Add("response_type", "code")
				q.Add("client_id", client.ID)
				q.Add("code_challenge", "challenge")
				q.Add("redirect_uri", client.RedirectURIs[0])
				q.Add("scope", "openid")
				q.Add("state", "xyz")
				q.Add("nonce", "abc")
				req.URL.RawQuery = q.Encode()

				rec := httptest.NewRecorder()

				cookies := utils.NewCookieStore()
				sessionCookie, _ := cookies.Get(req, helpers.SESSION_COOKIE_NAME)
				sessionCookie.Values[helpers.SESSION_COOKIE_ID] = session.ID.String()
				if err := sessionCookie.Save(req, rec); err != nil {
					t.Fatalf("failed to save session cookie: %v", err)
				}

				for _, cookie := range rec.Result().Cookies() {
					req.AddCookie(cookie)
				}

				return req
			},
			expectedCode:      http.StatusOK,
			wantErrorResponse: false,
			wantStatus:        utils.PENDING, // status should remain unchanged
			wantToken:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleAuthorization))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(AUTH_SNAPSHOT_INIT))
			})

			req := tt.preHook(t, ctx, conn, server.URL)

			// Perform the request
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			res, err := client.Do(req)

			if err != nil {
				t.Fatalf("failed to perform request: %v", err)
			}
			defer res.Body.Close()

			assert.Equal(t, tt.expectedCode, res.StatusCode, "unexpected status code")

			cookies := utils.NewCookieStore()
			sessionCookie, err := cookies.Get(req, helpers.SESSION_COOKIE_NAME)
			if err != nil {
				sessionId, ok := sessionCookie.Values[helpers.SESSION_COOKIE_ID].(string)
				if ok && sessionId != "" {
					session, err := models.GetSessionByID(ctx, conn, sessionId)
					if err != nil {
						t.Fatalf("failed to get session by ID: %v", err)
					}

					assert.NotNil(t, session, "session should not be nil")
					assert.NotNil(t, session.UserID, "session user should not be nil")
					assert.Equal(t, user.ID, session.UserID, "unexpected session user ID")
				}
			}

			req = httptest.NewRequest(http.MethodGet, server.URL, nil)
			for _, c := range res.Cookies() {
				req.AddCookie(c)
			}

			authCookie, err := cookies.Get(req, helpers.AUTHORIZATION_COOKIE_NAME)
			if !tt.wantToken {
				assert.Nil(t, err, "authorization cookie should not be nil")

				authId, ok := authCookie.Values[helpers.AUTHORIZATION_COOKIE_ID].(string)
				assert.True(t, ok, "authorization cookie should contain authorization ID")
				assert.NotEmpty(t, authId, "authorization ID should not be empty")

				auth, err := models.GetAuthorizationByID(ctx, conn, authId)
				if err != nil {
					t.Fatalf("failed to get authorization by ID: %v", err)
				}

				assert.Equal(t, tt.wantStatus, *auth.Status, "unexpected authorization status")
			} else {
				assert.NotNil(t, err, "authorization cookie should not be set")
			}
		})
	}
}
