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

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const AR_SNAPSHOT_INIT = "authorization_request_init"

func createParams(extra ...url.Values) url.Values {
	params := url.Values{
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {"xyz"},
		"nonce":                 {"abc"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}

	for _, e := range extra {
		for k, v := range e {
			params[k] = v
		}
	}

	return params
}

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
			Name:   "Valid Authorization GET Request using cookie",
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
			Name:   "Valid Authorization POST Request using parameters",
			Method: http.MethodPost,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
			}),
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
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
			}),
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				// No pre-hook actions needed for this test
			},
			WantErr: false,
		},
		{
			Name:   "Missing Consent",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
			}),
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
			Name:   "Scope change requiring new consent",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"scope":         {"openid email profile address"},
			}),
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
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr:     false,
			WantConsent: false,
		},
		{
			Name:   "Scope change with prompt=none",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"scope":         {"openid email profile address"},
				"prompt":        {"none"},
			}),
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
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Missing user session with prompt=none",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"prompt":        {"none"},
			}),
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				// No pre-hook actions needed for this test
				fmt.Printf("Missing user")
			},
			WantErr: true,
		},
		{
			Name:   "Missing consent with prompt=none",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"prompt":        {"none"},
			}),
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: true,
		},
		{
			Name:   "Existing Consent with prompt=consent",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"prompt":        {"consent"},
			}),
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

				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr:     false,
			WantConsent: false,
		},
		{
			Name:   "Existing session with prompt=login",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"prompt":        {"login"},
			}),
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				if err := createUserSession(ctx, db, r, &user); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}
			},
			WantErr: false,
		},
		{
			Name: "Invalid authorization cookie with empty authorization ID",
			// Using GET method to trigger cookie parsing
			Method: http.MethodGet,
			Params: url.Values{},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				w := httptest.NewRecorder()
				cookieStore := utils.NewCookieStore()
				cookieSession, err := cookieStore.New(r, AUTHORIZATION_COOKIE_NAME)
				if err != nil {
					t.Fatalf("Failed to create authorization cookie: %v", err)
				}
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
			WantErr: true,
		},
		{
			Name:   "Invalid authorization cookie with non-existing authorization ID",
			Method: http.MethodGet,
			Params: url.Values{},
			PreHook: func(ctx context.Context, db bun.IDB, r *http.Request) {
				w := httptest.NewRecorder()
				cookieStore := utils.NewCookieStore()
				cookieSession, err := cookieStore.New(r, AUTHORIZATION_COOKIE_NAME)
				if err != nil {
					t.Fatalf("Failed to create authorization cookie: %v", err)
				}
				cookieSession.Values[AUTHORIZATION_COOKIE_ID] = uuid.New().String() // Non-existing UUID
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
			WantErr: true,
		},
		{
			Name:   "Invalid Response Type",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"response_type": {"invalid_type"},
			}),
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
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"response_type": {"code id_token"},
			}),
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
			Params: createParams(url.Values{
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
			}),
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
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
			}),
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
			Params: createParams(url.Values{
				"client_id":             {client.ID},
				"client_secret":         {client.Secret.String()},
				"redirect_uri":          {client.RedirectURIs[0]},
				"code_challenge":        {},
				"code_challenge_method": {},
			}),
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
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {"invalid-uri"},
			}),
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
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {client.Secret.String()},
				"redirect_uri":  {client.RedirectURIs[0]},
				"scope":         {},
			}),
			WantErr: true,
		},
		{
			Name:   "Invalid Client Secret",
			Method: http.MethodGet,
			Params: createParams(url.Values{
				"client_id":     {client.ID},
				"client_secret": {"invalid-secret"},
				"redirect_uri":  {client.RedirectURIs[0]},
			}),
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				db := db.Connect(ctx)
				defer db.Close()

				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					tx.Rollback()
					t.Fatalf("Failed to begin transaction: %v", err)
				}

				writable, _, oidcErr := HandleAuthorizationRequest(ctx, tx, w, r)
				if oidcErr != nil {
					tx.Rollback()
					oidcErr.Write(w)
					return
				}

				if err := tx.Commit(); err != nil {
					t.Fatalf("Failed to commit transaction: %v", err)
				}

				if writable != nil {
					writable.Write(w)
					return
				}

				w.WriteHeader(http.StatusNoContent) // normally render authorization decision form if no consent yet, but valid session exists
				w.Write([]byte{})
			}))
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(AR_SNAPSHOT_INIT))
			})

			var body io.Reader
			if tt.Method == http.MethodPost {
				// For POST requests, encode parameters as form data
				body = strings.NewReader(tt.Params.Encode())
			}

			httpClient := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			req, err := http.NewRequest(tt.Method, server.URL+AUTHORIZATION_GRANT_ENDPOINT, body)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			switch tt.Method {
			case http.MethodGet:
				req.URL.RawQuery = tt.Params.Encode()
			case http.MethodPost:
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			default:
				t.Fatalf("Unsupported method: %s", tt.Method)
			}

			if tt.PreHook != nil {
				tt.PreHook(ctx, db, req)
			}

			res, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}

			defer res.Body.Close()

			if tt.WantErr {
				redirectUri := res.Header.Get("Location")
				if redirectUri == "" {
					assert.GreaterOrEqual(t, res.StatusCode, 400, "Expected error status code, got %d", res.StatusCode)
					return
				}
				u, _ := url.Parse(redirectUri)
				q := u.Query()
				assert.NotEmpty(t, q.Get("error"), "Expected error parameter in redirect URI")
			} else {
				if tt.WantConsent {
					redirectUri := res.Header.Get("Location")
					if redirectUri == "" {
						t.Fatalf("Expected redirect to client redirect URI, but got none")
					}
					u, _ := url.Parse(redirectUri)
					assert.Equal(t, client.RedirectURIs[0], fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path), "Expected redirect to client redirect URI")

					query := u.Query()
					decoder := utils.NewCustomDecoder()
					var authorizationResponse authorizationResponse
					if err := decoder.Decode(&authorizationResponse, query); err != nil {
						t.Fatalf("Failed to decode authorization response: %v", err)
					}

					tokenValue := ""

					if authorizationResponse.Code != "" {
						tokenValue = authorizationResponse.Code
					} else if authorizationResponse.AccessToken != "" {
						tokenValue = authorizationResponse.AccessToken
					}

					if tokenValue == "" {
						t.Fatalf("Expected token value in response, but got none")
					}

					token, err := models.GetTokenByValue(ctx, db, authorizationResponse.Code)
					if err != nil {
						t.Fatalf("Failed to retrieve authorization code token: %v", err)
					}
					assert.Equal(t, client.ID, (*token).Authorization.ClientID, "Token ClientID does not match")
					assert.Equal(t, user.ID, (*token).Authorization.UserID, "Token UserID does not match")
					assert.Equal(t, utils.APPROVED, *(*token).Authorization.Status, "Authorization status is not approved")
				} else {
					req := httptest.NewRequest(tt.Method, AUTHORIZATION_GRANT_ENDPOINT, nil)

					for _, c := range res.Cookies() {
						req.AddCookie(c)
					}

					cookieStore := utils.NewCookieStore()
					cookieSession, err := cookieStore.Get(req, AUTHORIZATION_COOKIE_NAME)
					if err != nil {
						t.Fatalf("Failed to get authorization cookie: %v", err)
					}

					authID, ok := cookieSession.Values[AUTHORIZATION_COOKIE_ID].(string)
					assert.True(t, ok, "Authorization ID not found in cookie")
					assert.NotEmpty(t, authID, "Authorization ID in cookie is empty")

					auth, err := models.GetAuthorizationByID(ctx, db, authID)
					if err != nil {
						t.Fatalf("Failed to retrieve authorization by ID: %v", err)
					}
					assert.Equal(t, utils.PENDING, *(*auth).Status, "Authorization status is not pending")
					assert.Equal(t, client.ID, (*auth).ClientID, "Authorization ClientID does not match")
					assert.Empty(t, (*auth).UserID, "Authorization user must not be set before consent")
				}
			}
		})
	}
}
