package helpers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
)

func loadUserFixture(t *testing.T) *models.User {
	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}
	return &user
}

func TestCreateMagicLinkToken(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "TURJME5aOGI0OWEwYjFjN2QzZWM1YTdkNGYxYjZlM2E5NTY0Nzg5MjNhYmM0NTZkZWY3ODkwMTIzNDU2Nzg5MA==") // 64 bytes for SHA-512
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name          string
		PreHook       func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error)
		CreateRequest func() *http.Request
		WantErr       bool
		WantToken     bool
	}

	tests := []testStruct{
		{
			Name: "Valid Magic Link Token based on registered user",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				user := loadUserFixture(t)
				if err := user.Save(ctx, db); err != nil {
					return nil, err
				}
				return &user, nil
			},
			CreateRequest: func() *http.Request {
				values := url.Values{
					"email": {
						"janedoe@example.com",
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			WantErr:   false,
			WantToken: true,
		},
		{
			Name: "Valid Magic Link Token based on whitelisted email",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				user := loadUserFixture(t)
				mlw := &models.MagicLinkWhitelist{
					Email: user.Email,
				}
				if err := mlw.Save(ctx, db); err != nil {
					return nil, err
				}
				return &user, nil
			},
			CreateRequest: func() *http.Request {
				values := url.Values{
					"email": {
						"janedoe@example.com",
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			WantErr:   false,
			WantToken: true,
		},
		{
			Name: "Invalid Magic Link Token based on non-registered and non-whitelisted email",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				return nil, nil
			},
			CreateRequest: func() *http.Request {
				values := url.Values{
					"email": {
						"janedoe@example.com",
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			WantErr:   false,
			WantToken: false,
		},
		{
			Name: "Invalid Magic Link Token based on missing email",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				return nil, nil
			},
			CreateRequest: func() *http.Request {
				values := url.Values{}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return req
			},
			WantErr:   true,
			WantToken: false,
		},
		{
			Name: "Wrong HTTP method",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				return nil, nil
			},
			CreateRequest: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/magic-link", nil)
				return req
			},
			WantErr:   true,
			WantToken: false,
		},
		{
			Name: "Invalid Content-Type",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (interface{}, error) {
				return nil, nil
			},
			CreateRequest: func() *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			WantErr:   true,
			WantToken: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx)
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			if tc.PreHook != nil {
				if _, err := tc.PreHook(ctx, db, t); err != nil {
					t.Fatalf("PreHook failed: %v", err)
				}
			}

			r := tc.CreateRequest()
			w := httptest.NewRecorder()

			token, err := CreateMagicLinkToken(ctx, db, w, r)
			if (err != nil) != tc.WantErr {
				t.Fatalf("ExchangeMagicLinkToken() error = %v, wantErr %v", err, tc.WantErr)
			}
			if err == nil {
				if !tc.WantToken {
					assert.Nil(t, token, "Expected token to be nil")
				} else {
					assert.NotNil(t, token, "Expected token to be non-nil")
					assert.NotNil(t, token.Token, "Expected token string to be non-empty")
				}

				res := w.Result()
				cookies := res.Cookies()
				var cookie *http.Cookie
				for _, c := range cookies {
					if c.Name == MAGIC_LINK_COOKIE_NAME {
						cookie = c
						break
					}
				}

				if cookie == nil {
					t.Fatalf("Expected magic link cookie to be set")
				}

				if !tc.WantToken {
					return
				}

				r = httptest.NewRequest(http.MethodGet, "/create-magic-link", nil)
				r.AddCookie(cookie)

				magicLinkCookie, err := utils.NewCookieStore().Get(r, MAGIC_LINK_COOKIE_NAME)

				if err != nil {
					t.Fatalf("Failed to retrieve magic link cookie: %v", err)
				}

				id, _ := magicLinkCookie.Values[MAGIC_LINK_ID].(string)
				email, _ := magicLinkCookie.Values[MAGIC_LINK_EMAIL].(string)

				assert.Equal(t, token.ID.String(), id, "Cookie ID should match token ID")
				assert.Equal(t, string(*token.Email), email, "Cookie email should match token email")
			}
		})
	}
}

func TestConsumeMagicLinkToken(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "TURJME5aOGI0OWEwYjFjN2QzZWM1YTdkNGYxYjZlM2E5NTY0Nzg5MjNhYmM0NTZkZWY3ODkwMTIzNDU2Nzg5MA==") // 64 bytes for SHA-512
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name          string
		PreHook       func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error)
		CreateRequest func(token string, cookie ...*http.Cookie) *http.Request
		WantErr       bool
	}

	tests := []testStruct{
		{
			Name: "Valid Magic Link Token consumption with cookie",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				user := loadUserFixture(t)
				if err := user.Save(ctx, db); err != nil {
					return nil, err
				}
				token, err := models.CreateMagicLinkToken(ctx, db, string(*user.Email))

				if err != nil {
					return nil, err
				}
				return token, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				values := url.Values{
					"token": {
						token,
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(cookie[0])
				return req
			},
			WantErr: false,
		},
		{
			Name: "Valid Magic Link Token consumption with form data",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				user := loadUserFixture(t)
				if err := user.Save(ctx, db); err != nil {
					return nil, err
				}
				token, err := models.CreateMagicLinkToken(ctx, db, string(*user.Email))

				if err != nil {
					return nil, err
				}
				return token, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				values := url.Values{
					"token": {
						token,
					},
					"id": {
						cookie[1].Value,
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			WantErr: false,
		},
		{
			Name: "Invalid Magic Link Token consumption with missing token",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				email := utils.HashedString("notoken@mail.com")
				token := utils.HashedString("sometoken")
				return &models.MagicLinkToken{
					ID:    uuid.New(),
					Email: &email,
					Token: &token,
				}, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				values := url.Values{}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			WantErr: true,
		},
		{
			Name: "Invalid Magic Link Token consumption with wrong token",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				email := utils.HashedString("notoken@mail.com")
				token := utils.HashedString("sometoken")
				return &models.MagicLinkToken{
					ID:    uuid.New(),
					Email: &email,
					Token: &token,
				}, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				values := url.Values{
					"token": {
						"invalid-token",
					},
					"id": {
						cookie[1].Value,
					},
				}
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", bytes.NewBuffer([]byte(values.Encode())))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			WantErr: true,
		},
		{
			Name: "Wrong HTTP method",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				email := utils.HashedString("notoken@mail.com")
				token := utils.HashedString("sometoken")
				return &models.MagicLinkToken{
					ID:    uuid.New(),
					Email: &email,
					Token: &token,
				}, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "/magic-link", nil)
				return req
			},
			WantErr: true,
		},
		{
			Name: "Invalid Content-Type",
			PreHook: func(ctx context.Context, db bun.IDB, t *testing.T) (*models.MagicLinkToken, error) {
				email := utils.HashedString("notoken@mail")
				token := utils.HashedString("sometoken")
				return &models.MagicLinkToken{
					ID:    uuid.New(),
					Email: &email,
					Token: &token,
				}, nil
			},
			CreateRequest: func(token string, cookie ...*http.Cookie) *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "/magic-link", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			WantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx)
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			var token *models.MagicLinkToken
			var err error
			token, err = tc.PreHook(ctx, db, t)
			if err != nil {
				t.Fatalf("PreHook failed: %v", err)
			}

			magicLinkCookie, _ := utils.NewCookieStore().Get(&http.Request{}, MAGIC_LINK_COOKIE_NAME)
			magicLinkCookie.Values[MAGIC_LINK_ID] = token.ID.String()
			magicLinkCookie.Values[MAGIC_LINK_EMAIL] = string(*token.Email)
			cookieWriter := httptest.NewRecorder()
			if err := magicLinkCookie.Save(nil, cookieWriter); err != nil {
				t.Fatalf("Failed to save magic link cookie: %v", err)
			}
			cookies := cookieWriter.Result().Cookies()
			var cookie *http.Cookie
			for _, c := range cookies {
				if c.Name == MAGIC_LINK_COOKIE_NAME {
					cookie = c
					break
				}
			}

			plainCookie := &http.Cookie{
				Name:  cookie.Name,
				Value: token.ID.String(),
			}

			r := tc.CreateRequest(string(*token.Token), cookie, plainCookie)
			w := httptest.NewRecorder()

			consumedToken, err := ConsumeMagicLinkToken(ctx, db, w, r)
			if (err != nil) != tc.WantErr {
				t.Fatalf("ExchangeMagicLinkToken() error = %v, wantErr %v", err, tc.WantErr)
			}
			if err == nil {
				assert.NotNil(t, consumedToken, "Expected consumed token to be non-nil")
				assert.Equal(t, token.ID, consumedToken.ID, "Expected token IDs to match")

				res := w.Result()
				cookies := res.Cookies()
				var deletedCookie *http.Cookie
				for _, c := range cookies {
					if c.Name == MAGIC_LINK_COOKIE_NAME {
						deletedCookie = c
						break
					}
				}

				if deletedCookie == nil || deletedCookie.MaxAge != -1 {
					t.Fatalf("Expected magic link cookie to be deleted")
				}
			}
		})
	}
}
