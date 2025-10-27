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
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	AD_SNAPSHOT_INIT = "ad_snapshot_init"
)

func TestHandleAuthorizationDecision(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")

	ctx := context.Background()
	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	conn := db.Connect(ctx)

	// Additional setup code for users, clients, and authorizations would go here
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

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(AD_SNAPSHOT_INIT))

	type testStruct struct {
		name           string
		preHook        func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session)
		method         string
		contentType    string
		payload        url.Values
		expectedStatus utils.AuthStatus
		wantStatus     int
	}

	tests := []testStruct{
		{
			name: "Approve authorization",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client

				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
				}

				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:         http.MethodPost,
			contentType:    "application/x-www-form-urlencoded",
			payload:        url.Values{"action": []string{"approved"}},
			expectedStatus: utils.APPROVED,
			wantStatus:     http.StatusSeeOther,
		},
		{
			name: "Deny authorization",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client

				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
				}

				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:         http.MethodPost,
			contentType:    "application/x-www-form-urlencoded",
			payload:        url.Values{"action": []string{"denied"}},
			expectedStatus: utils.DENIED,
			wantStatus:     http.StatusSeeOther,
		},
		{
			name: "Invalid method",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				return nil, nil
			},
			method:         http.MethodPut,
			expectedStatus: utils.APPROVED, // status should remain unchanged
			wantStatus:     http.StatusMethodNotAllowed,
		},
		{
			name: "Invalid action",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client

				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
				}

				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:         http.MethodPost,
			contentType:    "application/x-www-form-urlencoded",
			payload:        url.Values{"action": []string{"invalid_action"}},
			expectedStatus: utils.PENDING, // status should remain unchanged
			wantStatus:     http.StatusBadRequest,
		},
		{
			name: "Get authorization decision page",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				return nil, nil
			},
			method:         http.MethodGet,
			expectedStatus: utils.APPROVED, // status should remain unchanged
			wantStatus:     http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleAuthorizationDecision))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close connection: %v", err)
				}
				server.Close()
				pgContainer.Restore(ctx, postgres.WithSnapshotName(AD_SNAPSHOT_INIT))
			})

			auth, session := tt.preHook(ctx, conn)

			rec := httptest.NewRecorder()
			cookieStore := utils.NewCookieStore()

			if auth != nil {
				assert.NotEmpty(t, auth.ID, "preHook should create an authorization with an ID")

				cookie, _ := cookieStore.New(&http.Request{}, helpers.AUTHORIZATION_COOKIE_NAME)
				cookie.Values[helpers.AUTHORIZATION_COOKIE_ID] = auth.ID.String()
				cookie.Save(&http.Request{}, rec)
			}
			if session != nil {
				assert.NotEmpty(t, session.ID, "preHook should create a session with an ID")

				cookie, _ := cookieStore.New(&http.Request{}, helpers.SESSION_COOKIE_NAME)
				cookie.Values[helpers.SESSION_COOKIE_ID] = session.ID.String()
				cookie.Save(&http.Request{}, rec)
			}

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			req, err := http.NewRequest(tt.method, server.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			for _, cookie := range rec.Result().Cookies() {
				req.AddCookie(cookie)
			}

			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			if tt.method == http.MethodPost && tt.payload != nil {
				req.PostForm = tt.payload

				body := io.NopCloser(strings.NewReader(tt.payload.Encode()))
				req.Body = body
			}

			res, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to perform request: %v", err)
			}

			assert.Equal(t, tt.wantStatus, res.StatusCode, "unexpected status code")

			if tt.method == http.MethodPost && auth != nil {
				// Verify that authorization status has been updated in the database
				updatedAuth, err := models.GetAuthorizationByID(ctx, conn, auth.ID.String())
				if err != nil {
					t.Fatalf("failed to get authorization by ID: %v", err)
				}

				assert.Equal(t, tt.expectedStatus, *updatedAuth.Status, "authorization status not updated correctly")
			}
		})
	}
}
