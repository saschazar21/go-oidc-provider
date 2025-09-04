package helpers

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const AR_SNAPSHOT_INIT = "authorization_request_init"

func TestAuthorizationRequest(t *testing.T) {
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
		Name    string
		Method  string
		Params  url.Values
		WantErr bool
	}

	tests := []testStruct{
		{
			Name:   "Valid Authorization GET Request",
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
			WantErr: false,
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

			var req *http.Request
			if tt.Method == http.MethodPost {
				req = &http.Request{
					Method:   tt.Method,
					PostForm: tt.Params,
				}
			} else {
				req = &http.Request{
					Method: tt.Method,
					URL: &url.URL{
						RawQuery: tt.Params.Encode(),
					},
				}
			}

			auth, err := ParseAuthorizationRequest(ctx, db, req)
			if (err != nil) != tt.WantErr {
				t.Fatalf("ParseAuthorizationRequest() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotNil(t, auth, "Authorization should not be nil")
				assert.NotEqual(t, auth.ID, uuid.Nil, "Authorization ID should not be nil")
			} else {
				assert.Nil(t, auth, "Authorization should be nil on error")
			}
		})
	}
}
