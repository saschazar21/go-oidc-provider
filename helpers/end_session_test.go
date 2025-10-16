package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
	ES_SNAPSHOT_INIT = "es_snapshot_init"
)

var ES_KEY_HS256 = []byte("secret")

func TestEndSession(t *testing.T) {
	t.Setenv("ISSUER_URL", "https://localhost:8080")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	t.Setenv("KEY_HS256", "c2VjcmV0Cg==")

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

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(ES_SNAPSHOT_INIT))

	type testStruct struct {
		name          string
		preHook       func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error)
		createRequest func(s *models.Session) (r *http.Request)
		wantErr       bool
		wantLogoutErr bool
	}

	tests := []testStruct{
		{
			name: "logout session by cookie",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error) {
				s = &models.Session{
					UserID:   user.ID,
					ClientID: &client.ID,
				}
				if err := s.Save(ctx, db); err != nil {
					return nil, err
				}
				return s, nil
			},
			createRequest: func(s *models.Session) (r *http.Request) {
				res := httptest.NewRecorder()
				req, _ := http.NewRequest(http.MethodGet, "/logout", nil)

				if s == nil {
					return req
				}

				sessionStore := utils.NewCookieStore()
				session, _ := sessionStore.New(req, SESSION_COOKIE_NAME)
				session.Values[SESSION_COOKIE_ID] = s.ID.String()
				session.Save(req, res)

				req.Header.Set("Cookie", res.Header().Get("Set-Cookie"))

				return req
			},
			wantErr:       false,
			wantLogoutErr: false,
		},
		{
			name: "logout sessions by id_token_hint",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error) {
				s = &models.Session{
					UserID:   user.ID,
					ClientID: &client.ID,
				}
				if err := s.Save(ctx, db); err != nil {
					return nil, err
				}
				return s, nil
			},
			createRequest: func(s *models.Session) (r *http.Request) {
				a := auth
				idtoken, err := idtoken.NewSignedJWTFromAuthorization(&a)
				if err != nil {
					t.Fatalf("failed to create id_token: %v", err)
				}

				req, _ := http.NewRequest(http.MethodGet, "/logout?id_token_hint="+idtoken, nil)
				return req
			},
			wantErr:       false,
			wantLogoutErr: false,
		},
		{
			name: "no session to logout",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error) {
				return nil, nil
			},
			createRequest: func(s *models.Session) (r *http.Request) {
				req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
				return req
			},
			wantErr:       false,
			wantLogoutErr: false,
		},
		{
			name: "invalid id_token_hint",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error) {
				return nil, nil
			},
			createRequest: func(s *models.Session) (r *http.Request) {
				req, _ := http.NewRequest(http.MethodGet, "/logout?id_token_hint=invalid", nil)
				return req
			},
			wantErr:       false,
			wantLogoutErr: true,
		},
		{
			name: "id_token_hint without user info",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB) (s *models.Session, err error) {
				return nil, nil
			},
			createRequest: func(s *models.Session) (r *http.Request) {
				idtoken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				req, _ := http.NewRequest(http.MethodGet, "/logout?id_token_hint="+idtoken, nil)
				return req
			},
			wantErr:       false,
			wantLogoutErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close db connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(ES_SNAPSHOT_INIT))
			})

			s, err := tt.preHook(t, ctx, conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("preHook() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			req := tt.createRequest(s)

			ers, err := ParseEndSessionRequest(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEndSessionRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			res := httptest.NewRecorder()

			if err := ers.LogoutSessions(ctx, conn, res); (err != nil) != tt.wantLogoutErr {
				t.Errorf("LogoutSessions() error = %v, wantLogoutErr %v", err, tt.wantLogoutErr)
				return
			}

			if s != nil {
				// verify session is logged out
				s2 := models.Session{
					ID: s.ID,
				}

				conn.NewSelect().
					Model(&s2).
					WherePK().
					Scan(ctx)

				assert.False(t, *s2.IsActive, "logged-out session should not be active")
				assert.NotNil(t, s2.LogoutReason, "logged-out session should have a logout reason")
			}
		})
	}
}
