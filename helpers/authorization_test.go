package helpers

import (
	"context"
	"fmt"
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

const AR_SNAPSHOT_INIT = "authorization_request_init"

func createUserSession(ctx context.Context, db bun.IDB, r *http.Request, user *models.User) error {
	w := httptest.NewRecorder()

	// No pre-hook actions needed for GET requests
	session := models.Session{
		UserID: user.ID,
	}
	if err := session.Save(ctx, db); err != nil {
		return fmt.Errorf("Failed to create session: %v", err)
	}
	if err := SaveSession(ctx, db, w, r, &session); err != nil {
		return fmt.Errorf("Failed to save session: %v", err)
	}
	cookie := w.Result().Cookies()[0]
	r.AddCookie(cookie)
	return nil
}

func TestAuthorizationRequest(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "TURJME5aOGI0OWEwYjFjN2QzZWM1YTdkNGYxYjZlM2E5NTY0Nzg5MjNhYmM0NTZkZWY3ODkwMTIzNDU2Nzg5MA==") // 64 bytes for SHA-512
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(AR_SNAPSHOT_INIT))

	type testStruct struct {
		Name        string
		Method      string
		Params      url.Values
		PreHook     func(ctx context.Context, db bun.IDB, r *http.Request)
		WantErr     bool
		WantConsent bool
	}

	tests := []testStruct{
		{
			Name:   "Valid Authorization GET Request",
			Method: http.MethodGet,
			Params: url.Values{},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				status := utils.APPROVED
				challenge := "challenge"
				challengeMethod := utils.S256

				authorization := models.Authorization{
					Client:   &client,
					ClientID: client.ID,
					User:     &user,
					UserID:   user.ID,
					Scope: []utils.Scope{
						utils.OPENID, utils.EMAIL, utils.PROFILE,
					},
					IsActive:            true,
					Status:              &status,
					RedirectURI:         client.RedirectURIs[0],
					ResponseType:        utils.CODE,
					CodeChallenge:       &challenge,
					CodeChallengeMethod: &challengeMethod,
				}

				if err := authorization.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save existing authorization: %v", err)
				}

				w := httptest.NewRecorder()
				cookieStore := utils.NewCookieStore()
				cookieSession, err := cookieStore.New(r, AUTHORIZATION_COOKIE_NAME)
				if err != nil {
					t.Fatalf("Failed to create authorization cookie: %v", err)
				}
				cookieSession.Values[AUTHORIZATION_COOKIE_ID] = authorization.ID.String()
				cookieSession.Options.HttpOnly = true
				cookieSession.Options.SameSite = http.SameSiteStrictMode
				cookieSession.Options.Secure = true

				if err := cookieSession.Save(r, w); err != nil {
					t.Fatalf("Failed to save authorization cookie: %v", err)
				}
				cookie := w.Result().Cookies()[0]
				r.AddCookie(cookie)

				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr:     false,
			WantConsent: true,
		},
		{
			Name:   "Valid Authorization POST Request",
			Method: http.MethodPost,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				status := utils.APPROVED
				challenge := "challenge"
				challengeMethod := utils.S256

				auth := models.Authorization{
					Client:   &client,
					ClientID: client.ID,
					User:     &user,
					UserID:   user.ID,
					Scope: []utils.Scope{
						utils.OPENID, utils.EMAIL, utils.PROFILE,
					},
					IsActive:            true,
					Status:              &status,
					RedirectURI:         client.RedirectURIs[0],
					ResponseType:        utils.CODE,
					CodeChallenge:       &challenge,
					CodeChallengeMethod: &challengeMethod,
				}

				if err := auth.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save existing authorization: %v", err)
				}

				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr:     false,
			WantConsent: true,
		},
		{
			Name:   "Missing Session",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				// No pre-hook actions needed for this test
			},
			WantErr: true,
		},
		{
			Name:   "Missing Consent",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				email := utils.EncryptedString("test@example.com")
				user := models.User{
					Email: &email,
				}
				if err := user.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save user: %v", err)
				}

				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: false,
		},
		{
			Name:   "Invalid Response Type",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"invalid"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Unsupported Response Type",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code id_token"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing Client ID",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing Client Secret",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing Redirect URI",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing PKCE Parameters",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type": {"code"},
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"scope":         {"openid email profile"},
				"state":         {"xyz"},
				"nonce":         {"abc"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Invalid Redirect URI",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {"invalid-uri"},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing Required Parameters",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			WantErr: true,
		},
		{
			Name:   "Invalid Client Secret",
			Method: http.MethodGet,
			Params: url.Values{
				"response_type":         {"code"},
				"client_id":             {client.ID},
				"client_secret":         {"invalid-secret"},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"openid email profile"},
				"state":                 {"xyz"},
				"nonce":                 {"abc"},
				"code_challenge":        {"challenge"},
				"code_challenge_method": {"S256"},
			},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(AR_SNAPSHOT_INIT))
			})

			var body io.Reader
			if tt.Method == http.MethodPost {
				// For POST requests, encode parameters as form data
				body = strings.NewReader(tt.Params.Encode())
			}

			r := httptest.NewRequest(tt.Method, AUTHORIZATION_GRANT_ENDPOINT, body)
			switch tt.Method {
			case http.MethodGet:
				r.URL.RawQuery = tt.Params.Encode()
			case http.MethodPost:
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			if tt.PreHook != nil {
				tt.PreHook(ctx, db, r)
			}

			w := httptest.NewRecorder()

			auth, err := HandleAuthorizationRequest(ctx, db, w, r)
			if (err != nil) != tt.WantErr {
				t.Fatalf("HandleAuthorizationRequest() error = %v, wantErr %v", err, tt.WantErr)
			}

			if err == nil && auth == nil {
				t.Fatalf("Expected valid authorization, got nil")
			}

			if !tt.WantErr {
				assert.NotNil(t, auth, "Expected valid authorization, got nil")
				assert.NotEmpty(t, auth.ID, "Expected authorization to have an ID")

				if tt.WantConsent {
					status := utils.APPROVED

					assert.NotEmpty(t, auth.ReplacedID, "Expected authorization to require consent, but it didn't")
					assert.NotNil(t, auth.ReplacedAuthorization, "Expected authorization to require consent, but it didn't")
					assert.True(t, auth.IsActive, "Expected authorization to be active")
					assert.Equal(t, auth.Status, &status, "Expected authorization status to be 'pending'")
				} else {
					status := utils.PENDING

					assert.Empty(t, auth.ReplacedID, "Did not expect authorization to require consent, but it did")
					assert.Nil(t, auth.ReplacedAuthorization, "Did not expect authorization to require consent, but it did")
					assert.False(t, auth.IsActive, "Expected authorization to not be active")
					assert.Equal(t, auth.Status, &status, "Expected authorization status to be 'approved'")
				}
			}
		})
	}
}
