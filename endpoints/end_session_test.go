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
	ES_SNAPSHOT_INIT = "es_snapshot_init"
)

func TestHandleEndSession(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	conn := db.Connect(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("failed to load authorization fixture: %v", err)
	}

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

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(ES_SNAPSHOT_INIT))

	type testStruct struct {
		name          string
		setupSession  func(ctx context.Context, db bun.IDB) *models.Session
		createRequest func(s *models.Session) (r *http.Request)
		wantErr       bool
	}

	tests := []testStruct{
		{
			name: "Valid request with session cookie",
			setupSession: func(ctx context.Context, db bun.IDB) *models.Session {
				s := models.Session{
					UserID:   user.ID,
					User:     &user,
					ClientID: &client.ID,
					Client:   &client,
				}
				if err := s.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}
				return &s
			},
			createRequest: func(s *models.Session) *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
				w := httptest.NewRecorder()

				sessionStore := utils.NewCookieStore()
				session, _ := sessionStore.New(req, helpers.SESSION_COOKIE_NAME)
				session.Values[helpers.SESSION_COOKIE_ID] = s.ID.String()
				if err := session.Save(req, w); err != nil {
					t.Fatalf("failed to save session cookie: %v", err)
				}

				req.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
				return req
			},
		},
		{
			name: "Invalid request with POST method",
			setupSession: func(ctx context.Context, db bun.IDB) *models.Session {
				return nil
			},
			createRequest: func(s *models.Session) *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "/logout", nil)
				return req
			},
			wantErr: true,
		},
		{
			name: "Request without session cookie",
			setupSession: func(ctx context.Context, db bun.IDB) *models.Session {
				return nil
			},
			createRequest: func(s *models.Session) *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
				return req
			},
		},
		{
			name: "Request with invalid post_logout_redirect_uri",
			setupSession: func(ctx context.Context, db bun.IDB) *models.Session {
				return nil
			},
			createRequest: func(s *models.Session) *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=invalid-uri", nil)
				return req
			},
			wantErr: true,
		},
		{
			name: "Request with valid post_logout_redirect_uri",
			setupSession: func(ctx context.Context, db bun.IDB) *models.Session {
				return nil
			},
			createRequest: func(s *models.Session) *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/logout?post_logout_redirect_uri=https://client.example.com/logout&state=abc", nil)
				return req
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(ES_SNAPSHOT_INIT))
			})

			session := tt.setupSession(ctx, conn)

			req := tt.createRequest(session)
			w := httptest.NewRecorder()

			HandleEndSession(w, req)

			res := w.Result()

			if !tt.wantErr {
				assert.Equal(t, http.StatusTemporaryRedirect, res.StatusCode, "expected status code to be 307 Temporary Redirect")

				assert.NotEmpty(t, w.Header().Get("Set-Cookie"), "expected Set-Cookie header to be set")
				assert.Contains(t, w.Header().Get("Set-Cookie"), helpers.SESSION_COOKIE_NAME, "expected session cookie to be set")

				if session == nil {
					return
				}

				updatedSession := models.Session{
					ID: session.ID,
				}
				conn.NewSelect().
					Model(&updatedSession).
					WherePK().
					Scan(ctx)

				assert.False(t, *updatedSession.IsActive, "expected session to be inactive")
				assert.NotNil(t, updatedSession.LogoutReason, "expected logout reason to be set")
			} else {
				assert.NotEqual(t, http.StatusTemporaryRedirect, res.StatusCode, "expected status code not to be 307 Temporary Redirect")
			}
		})
	}
}
