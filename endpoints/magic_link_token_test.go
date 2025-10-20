package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
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
	MLT_SNAPSHOT_INIT = "mlt_snapshot_init"
)

func TestHandleMagicLinkToken(t *testing.T) {
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

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(MLT_SNAPSHOT_INIT))

	type testStruct struct {
		name         string
		method       string
		contentType  string
		preHook      func(ctx context.Context, db bun.IDB) (*models.MagicLinkToken, error)
		formHook     func(mlt *models.MagicLinkToken) url.Values
		wantRedirect string
		wantStatus   int
	}

	tests := []testStruct{
		{
			name:        "Render magic link form with GET method",
			method:      "GET",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusOK,
			formHook: func(mlt *models.MagicLinkToken) url.Values {
				return url.Values{}
			},
		},
		{
			name:        "Create magic link token with valid email",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusSeeOther,
			preHook: func(ctx context.Context, db bun.IDB) (*models.MagicLinkToken, error) {
				return models.CreateMagicLinkToken(ctx, db, string(*user.Email))
			},
			formHook: func(mlt *models.MagicLinkToken) url.Values {
				if mlt == nil {
					return url.Values{}
				}

				return url.Values{
					"id":    []string{mlt.ID.String()},
					"token": []string{string(*mlt.Token)},
				}
			},
		},
		{
			name:        "Create magic link token with invalid email",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusBadRequest,
			preHook: func(ctx context.Context, db bun.IDB) (*models.MagicLinkToken, error) {
				token := utils.HashedString("000000")

				return &models.MagicLinkToken{
					ID:    uuid.New(),
					Token: &token,
				}, nil
			},
			formHook: func(mlt *models.MagicLinkToken) url.Values {
				if mlt == nil {
					return url.Values{}
				}
				return url.Values{
					"id":    []string{mlt.ID.String()},
					"token": []string{string(*mlt.Token)},
				}
			},
		},
		{
			name:        "Create magic link token with missing form values",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusBadRequest,
			formHook: func(mlt *models.MagicLinkToken) url.Values {
				return url.Values{}
			},
		},
		{
			name:        "Create magic link token with invalid content type",
			method:      "POST",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			formHook: func(mlt *models.MagicLinkToken) url.Values {
				return url.Values{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleMagicLinkToken))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close db connection: %v", err)
				}

				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(MLT_SNAPSHOT_INIT))
			})

			var preCreatedMLT *models.MagicLinkToken
			var err error
			if tt.preHook != nil {
				preCreatedMLT, err = tt.preHook(ctx, conn)
				if err != nil {
					t.Fatalf("preHook failed: %v", err)
				}
			}

			redirect := "/"
			if tt.wantRedirect != "" {
				redirect = tt.wantRedirect
			}

			formValues := url.Values{}
			if tt.formHook != nil {
				formValues = tt.formHook(preCreatedMLT)
			}

			var resp *http.Response

			switch tt.method {
			case "GET":
				resp, err = http.Get(server.URL + "/magic_link_token")
				if err != nil {
					t.Fatalf("failed to send GET request: %v", err)
				}
			case "POST":
				client := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err = client.PostForm(server.URL+"/magic_link_token", formValues)
				if err != nil {
					t.Fatalf("failed to send POST request: %v", err)
				}
			default:
				t.Fatalf("unsupported method: %s", tt.method)
			}

			defer resp.Body.Close()

			assert.Equal(t, tt.wantStatus, resp.StatusCode, "unexpected status code")

			if tt.method == "POST" {
				if resp.StatusCode == http.StatusSeeOther {
					location, err := resp.Location()
					if err != nil {
						t.Fatalf("failed to get redirect location: %v", err)
					}

					assert.Equal(t, redirect, location.Path, "unexpected redirect path")

					var mlt models.MagicLinkToken
					conn.NewSelect().
						Model(&mlt).
						Where("token_id = ?", preCreatedMLT.ID).
						Scan(ctx)

					assert.NotNil(t, mlt.ConsumedAt, "expected magic link token to be consumed")
					assert.Equal(t, preCreatedMLT.ID, mlt.ID, "expected magic link token IDs to match")
					assert.False(t, *mlt.IsActive, "expected magic link token to be inactive")

					req, _ := http.NewRequest("GET", location.String(), nil)

					cookies := resp.Cookies()
					for _, cookie := range cookies {
						req.AddCookie(cookie)
					}

					sessionStore := utils.NewCookieStore()
					magicLinkCookie, err := sessionStore.Get(req, helpers.SESSION_COOKIE_NAME)
					if err != nil {
						t.Fatalf("failed to get magic link cookie: %v", err)
					}

					id, ok := magicLinkCookie.Values[helpers.SESSION_COOKIE_ID].(string)

					if !ok || id == "" {
						t.Fatalf("failed to get session ID from cookie")
					}

					assert.NotEmpty(t, id, "expected session ID in cookie")

					var session models.Session
					err = conn.NewSelect().
						Model(&session).
						Where("session_id = ?", id).
						Scan(ctx)

					if err != nil {
						t.Fatalf("failed to get session by ID: %v", err)
					}

					assert.Equal(t, user.ID, session.UserID, "expected session user ID to match")
				}
			}
		})
	}
}
