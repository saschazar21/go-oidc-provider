package helpers

import (
	"bytes"
	"context"
	"encoding/json"
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
	CLIENT_REGISTRATION_SNAPSHOT_INIT = "client_registration_init"
)

func TestHandleClientRegistration(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create test container: %v", err)
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

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(CLIENT_REGISTRATION_SNAPSHOT_INIT))

	type testStruct struct {
		name               string
		preHook            func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request
		expectedStatusCode int
	}

	tests := []testStruct{
		{
			name: "Valid client registration using cookie session",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				clientJSON, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("Failed to marshal client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(clientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				s := &models.Session{
					UserID: user.ID,
				}
				if err := s.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}

				w := httptest.NewRecorder()
				sessionStore := utils.NewCookieStore()
				session, _ := sessionStore.New(req, SESSION_COOKIE_NAME)

				session.Values[SESSION_COOKIE_ID] = s.ID.String()
				session.Save(req, w)

				for _, cookie := range w.Result().Cookies() {
					req.AddCookie(cookie)
				}

				return req
			},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name: "Valid client registration using active custom token",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				clientJSON, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("Failed to marshal client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(clientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				customToken, err := models.CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, &user)
				if err != nil {
					t.Fatalf("Failed to create custom token: %v", err)
				}

				req.Header.Set("Authorization", "Bearer "+string(customToken.Value))

				return req
			},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name: "Invalid client registration without authentication",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				clientJSON, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("Failed to marshal client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(clientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "Invalid client registration with malformed JSON",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				malformedJSON := []byte(`{"client_name": "Test Client", "redirect_uris": ["https://example.com/callback"],}`) // Note the trailing comma

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(malformedJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				s := &models.Session{
					UserID: user.ID,
				}
				if err := s.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}

				w := httptest.NewRecorder()
				sessionStore := utils.NewCookieStore()
				session, _ := sessionStore.New(req, SESSION_COOKIE_NAME)

				session.Values[SESSION_COOKIE_ID] = s.ID.String()
				session.Save(req, w)

				for _, cookie := range w.Result().Cookies() {
					req.AddCookie(cookie)
				}

				return req
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "Invalid client registration with missing required fields",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				invalidClient := map[string]interface{}{
					"redirect_uris": []string{"https://example.com/callback"},
				}
				invalidClientJSON, err := json.Marshal(invalidClient)
				if err != nil {
					t.Fatalf("Failed to marshal invalid client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(invalidClientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				s := &models.Session{
					UserID: user.ID,
				}
				if err := s.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}

				w := httptest.NewRecorder()
				sessionStore := utils.NewCookieStore()
				session, _ := sessionStore.New(req, SESSION_COOKIE_NAME)

				session.Values[SESSION_COOKIE_ID] = s.ID.String()
				session.Save(req, w)

				for _, cookie := range w.Result().Cookies() {
					req.AddCookie(cookie)
				}

				return req
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "Invalid client registration with inactive custom token",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				clientJSON, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("Failed to marshal client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(clientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				customToken, err := models.CreateToken(ctx, db, utils.CUSTOM_TOKEN_TYPE, &user)
				if err != nil {
					t.Fatalf("Failed to create custom token: %v", err)
				}

				// Invalidate the token
				if _, err := db.NewUpdate().
					Model(&models.Token{
						ID: customToken.ID,
					}).
					Set("is_active = FALSE").
					WherePK().
					Exec(ctx); err != nil {
					t.Fatalf("Failed to deactivate custom token: %v", err)
				}

				req.Header.Set("Authorization", "Bearer "+string(customToken.Value))

				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "Invalid HTTP method",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				req, err := http.NewRequest("GET", origin+"/register", nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				return req
			},
			expectedStatusCode: http.StatusMethodNotAllowed,
		},
		{
			name: "Invalid content type",
			preHook: func(t *testing.T, ctx context.Context, db bun.IDB, origin string) *http.Request {
				clientJSON, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("Failed to marshal client: %v", err)
				}

				req, err := http.NewRequest("POST", origin+"/register", bytes.NewBuffer(clientJSON))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				// Set an invalid content type
				req.Header.Set("Content-Type", "text/plain")

				return req
			},
			expectedStatusCode: http.StatusUnsupportedMediaType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()
				conn := db.Connect(ctx)
				defer conn.Close()

				client, err := HandleClientRegistration(ctx, conn, w, r)
				if err != nil {
					err.Write(w)
					return
				}

				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(client)
			}))
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("failed to close db connection: %v", err)
				}
				server.Close()

				pgContainer.Restore(ctx, postgres.WithSnapshotName(CLIENT_REGISTRATION_SNAPSHOT_INIT))
			})

			httpClient := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			req := tt.preHook(t, ctx, db, server.URL)
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatusCode {
				t.Fatalf("Expected status code %d, got %d", tt.expectedStatusCode, resp.StatusCode)
			}

			if tt.expectedStatusCode == http.StatusCreated {
				var registeredClient *models.Client = &models.Client{}
				if err := json.NewDecoder(resp.Body).Decode(&registeredClient); err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}

				assert.NotEmpty(t, registeredClient.ID, "Registered client ID should not be empty")
				assert.Equal(t, client.Name, registeredClient.Name, "Registered client name should match")
				assert.Equal(t, client.RedirectURIs, registeredClient.RedirectURIs, "Registered client redirect URIs should match")

				if registeredClient, err = models.GetClientByID(ctx, db, registeredClient.ID); err != nil {
					t.Fatalf("Failed to retrieve registered client from database: %v", err)
				}
				assert.Equal(t, user.ID, registeredClient.OwnerID, "Registered client owner ID should match user ID")
			}
		})
	}
}
