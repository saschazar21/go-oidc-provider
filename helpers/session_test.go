package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	SESSION_SNAPSHOT_INIT = "session_init"
)

func TestSaveSession(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "TURJME5aOGI0OWEwYjFjN2QzZWM1YTdkNGYxYjZlM2E5NTY0Nzg5MjNhYmM0NTZkZWY3ODkwMTIzNDU2Nzg5MA==") // 64 bytes for SHA-512
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	user := loadUserFixture(t)
	client := loadClientFixture(t)

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user fixture: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client fixture: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(SESSION_SNAPSHOT_INIT))

	type testStruct struct {
		Name    string
		PreHook func(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request)
		Session *models.Session
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Valid session",
			Session: &models.Session{
				UserID:   user.ID,
				ClientID: &client.ID,
			},
			WantErr: false,
		},
		{
			Name: "Invalid session cookie present in request",
			PreHook: func(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) {
				invalidCookie := &http.Cookie{
					Name:  SESSION_COOKIE_NAME,
					Value: "invalid-session-id",
				}
				r.AddCookie(invalidCookie)
			},
			Session: &models.Session{
				UserID:   user.ID,
				ClientID: &client.ID,
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(SESSION_SNAPSHOT_INIT))
			})

			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			w := httptest.NewRecorder()

			if tt.PreHook != nil {
				tt.PreHook(ctx, conn, w, req)
			}

			if err := tt.Session.Save(ctx, conn); err != nil {
				t.Fatalf("Failed to save session fixture: %v", err)
			}

			err := SaveSession(ctx, conn, w, req, tt.Session)
			if (err != nil) != tt.WantErr {
				t.Errorf("SaveSession() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, tt.Session.ID, "Expected session ID to be set after saving")

				// Verify that the session cookie is set in the response
				cookies := w.Result().Cookies()
				var sessionCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == SESSION_COOKIE_NAME {
						sessionCookie = cookie
						break
					}
				}

				assert.NotNil(t, sessionCookie, "Expected session cookie to be set in response")

				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
				r.AddCookie(sessionCookie)

				// Verify that the session can be retrieved using the cookie
				retrievedSession, err := ParseSession(ctx, conn, w, r)
				if err != nil {
					t.Fatalf("Failed to parse session from cookie: %v", err)
				}

				assert.Equal(t, tt.Session.ID, retrievedSession.ID, "Retrieved session ID should match saved session ID")
			}
		})
	}
}
