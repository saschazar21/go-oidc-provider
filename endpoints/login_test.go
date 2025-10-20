package endpoints

import (
	"context"
	"fmt"
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
)

const (
	LOGIN_SNAPSHOT_INIT = "login_snapshot_init"
)

func TestHandleLogin(t *testing.T) {
	t.Setenv("DEMO_MODE", "true")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	t.Setenv(utils.ISSUER_URL_ENV, "http://localhost:8080")

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

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(LOGIN_SNAPSHOT_INIT))

	type testStruct struct {
		name              string
		method            string
		formValues        map[string]string
		wantRealMagicLink bool
		wantStatus        int
	}

	tests := []testStruct{
		{
			name:       "GET method",
			method:     "GET",
			wantStatus: 200,
		},
		{
			name:              "POST method with valid email",
			method:            "POST",
			formValues:        map[string]string{"email": fmt.Sprintf(" %s ", string(*user.Email))},
			wantRealMagicLink: true,
			wantStatus:        http.StatusSeeOther,
		},
		{
			name:              "POST method with invalid email",
			method:            "POST",
			formValues:        map[string]string{"email": "invalid@example.com"},
			wantRealMagicLink: false,
			wantStatus:        http.StatusSeeOther,
		},
		{
			name:       "HEAD method",
			method:     "HEAD",
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST method with missing email",
			method:     "POST",
			formValues: map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(HandleLogin))
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				server.Close()
				if err := conn.Close(); err != nil {
					t.Fatalf("failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(LOGIN_SNAPSHOT_INIT))
			})

			var rr *http.Response
			var err error
			switch tt.method {
			case "HEAD":
				rr, err = http.Head(server.URL + "/login")
			case "GET":
				rr, err = http.Get(server.URL + "/login")
			case "POST":
				form := url.Values{}
				for key, value := range tt.formValues {
					form.Set(key, value)
				}

				client := &http.Client{
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				rr, err = client.Post(server.URL+"/login", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
			default:
				t.Fatalf("unsupported method: %s", tt.method)
			}

			if err != nil {
				t.Fatalf("failed to make %s request: %v", tt.method, err)
			}

			if rr.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.StatusCode)
			}

			if tt.method == "POST" {
				if tt.wantStatus == http.StatusSeeOther {
					location := rr.Header.Get("Location")
					if location == "" {
						t.Errorf("expected redirect location, got none")
					}

					parsedURL, err := url.Parse(location)
					if err != nil {
						t.Errorf("failed to parse redirect URL: %v", err)
					}

					req, _ := http.NewRequest("GET", location, nil)
					cookies := rr.Cookies()
					for _, cookie := range cookies {
						req.AddCookie(cookie)
					}

					sessionStore := utils.NewCookieStore()
					magicLinkCookie, _ := sessionStore.Get(req, helpers.MAGIC_LINK_COOKIE_NAME)
					id, ok := magicLinkCookie.Values[helpers.MAGIC_LINK_ID].(string)
					if !ok || id == "" {
						t.Errorf("failed to get magic link ID from cookie")
					}

					var magicLinkToken models.MagicLinkToken

					err = conn.NewSelect().
						Model(&magicLinkToken).
						Where("token_id = ?", id).
						Scan(ctx)

					if tt.wantRealMagicLink {
						assert.Equal(t, id, parsedURL.Query().Get("id"), "expected id in redirect URL")

						token := parsedURL.Query().Get("token")
						id := parsedURL.Query().Get("id")

						assert.NotEmpty(t, token, "expected token in redirect URL")
						assert.NotEmpty(t, id, "expected id in redirect URL")
						assert.Nil(t, err, "expected to find magic link token in database")
					} else {
						assert.NotNil(t, err, "expected not to find magic link token in database")
					}
				}
			}
		})
	}
}
