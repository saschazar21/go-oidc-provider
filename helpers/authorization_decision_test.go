package helpers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/db"
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
			name: "Approve pending authorization",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client
				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
					User:   &user,
				}
				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:      http.MethodPost,
			contentType: "application/x-www-form-urlencoded",
			payload: url.Values{
				"action": []string{string(utils.APPROVED)},
			},
			expectedStatus: utils.APPROVED,
			wantStatus:     http.StatusSeeOther,
		},
		{
			name: "Deny pending authorization",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client
				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
					User:   &user,
				}
				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:      http.MethodPost,
			contentType: "application/x-www-form-urlencoded",
			payload: url.Values{
				"action": []string{string(utils.DENIED)},
			},
			expectedStatus: utils.DENIED,
			wantStatus:     http.StatusSeeOther,
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
		{
			name: "Unsupported Content-Type",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				return nil, nil
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: utils.APPROVED, // status should remain unchanged
			wantStatus:     http.StatusUnsupportedMediaType,
		},
		{
			name: "Unsupported authorization status",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				auth := pendingAuth
				auth.ClientID = client.ID
				auth.Client = &client
				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("failed to save authorization: %v", err)
				}

				session := models.Session{
					UserID: user.ID,
					User:   &user,
				}
				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				return &auth, &session
			},
			method:      http.MethodPost,
			contentType: "application/x-www-form-urlencoded",
			payload: url.Values{
				"action": []string{"invalid_status"},
			},
			expectedStatus: utils.PENDING, // status should remain unchanged
			wantStatus:     http.StatusBadRequest,
		},
		{
			name: "Missing authorization cookie",
			preHook: func(ctx context.Context, db bun.IDB) (*models.Authorization, *models.Session) {
				session := models.Session{
					UserID: user.ID,
					User:   &user,
				}

				if err := session.Save(ctx, db); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}
				return nil, &session
			},
			method: http.MethodPost,
			payload: url.Values{
				"action": []string{string(utils.APPROVED)},
			},
			contentType:    "application/x-www-form-urlencoded",
			expectedStatus: utils.APPROVED, // status should remain unchanged
			wantStatus:     http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := db.Connect(ctx)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				conn := db.Connect(ctx)
				defer conn.Close()

				res, err := HandleAuthorizationDecision(ctx, conn, r)
				if err != nil {
					err.Write(w)
					return
				}

				res.Write(w)
			}))

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close db connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(AD_SNAPSHOT_INIT))
			})

			auth, session := tt.preHook(ctx, conn)

			if auth != nil {
				assert.NotEmpty(t, auth.ID, "preHook should create an authorization with an ID")
			}
			if session != nil {
				assert.NotEmpty(t, session.ID, "preHook should create a session with an ID")
			}

			var res *http.Response
			var err error

			switch tt.method {
			case http.MethodPost:
				client := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				req, err := http.NewRequest(http.MethodPost, server.URL+"/authorization/decision", nil)
				if err != nil {
					t.Fatalf("failed to create POST request: %v", err)
				}
				req.Header.Set("Content-Type", tt.contentType)
				// add application/x-www-form-urlencoded body
				req.Body = io.NopCloser(strings.NewReader(tt.payload.Encode()))

				rec := httptest.NewRecorder()

				// Set authorization cookie
				cookieStore := utils.NewCookieStore()
				var cookie *sessions.Session

				if auth != nil {
					cookie, err = cookieStore.New(req, AUTHORIZATION_COOKIE_NAME)
					if err != nil {
						t.Fatalf("failed to create authorization cookie: %v", err)
					}
					cookie.Values[AUTHORIZATION_COOKIE_ID] = auth.ID.String()
					if err := cookieStore.Save(req, rec, cookie); err != nil {
						t.Fatalf("failed to save authorization cookie: %v", err)
					}
				}

				if session != nil {
					cookie, err = cookieStore.New(req, SESSION_COOKIE_NAME)
					if err != nil {
						t.Fatalf("failed to create session cookie: %v", err)
					}
					cookie.Values[SESSION_COOKIE_ID] = session.ID.String()
					if err := cookieStore.Save(req, rec, cookie); err != nil {
						t.Fatalf("failed to save session cookie: %v", err)
					}
				}

				for _, c := range rec.Result().Cookies() {
					req.AddCookie(c)
				}

				res, err = client.Do(req)
				if err != nil {
					t.Fatalf("failed to send POST request: %v", err)
				}
			case http.MethodGet:
				res, err = http.Get(server.URL + "/authorization/decision")
				if err != nil {
					t.Fatalf("failed to send GET request: %v", err)
				}
			default:
				t.Fatalf("unsupported method: %s", tt.method)
			}

			assert.Equal(t, tt.wantStatus, res.StatusCode, "unexpected status code")

			if tt.method == http.MethodPost && auth != nil {
				// Verify that authorization status has been updated in the database
				updatedAuth, err := models.GetAuthorizationByID(ctx, conn, auth.ID.String())
				if err != nil {
					t.Fatalf("failed to retrieve updated authorization: %v", err)
				}
				assert.Equal(t, tt.expectedStatus, *updatedAuth.Status, "authorization status not updated correctly")
			}
		})
	}
}
