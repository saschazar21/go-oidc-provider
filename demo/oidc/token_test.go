package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenRequest(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"authorization_endpoint": "` + serverURL + `/authorize",
				"token_endpoint": "` + serverURL + `/token",
				"userinfo_endpoint": "` + serverURL + `/userinfo",
				"jwks_uri": "` + serverURL + `/.well-known/jwks.json"
			}`))
			return
		}

		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"access_token": "access-token-12345",
				"token_type": "Bearer",
				"expires_in": 3600,
				"id_token": "id-token-67890"
			}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	t.Setenv(ISSUER_ENV, server.URL)
	t.Setenv(NETLIFY_DEPLOY_PRIME_URL_ENV, server.URL)
	t.Setenv(OIDC_CLIENT_ID_ENV, "client-id-123")
	t.Setenv(OIDC_CLIENT_SECRET_ENV, "client-secret-xyz")

	tokenRequest := NewOIDCTokenRequest("auth-code-12345")

	assert.NotNil(t, tokenRequest, "Failed to create OIDC Token Request")
	assert.Equal(t, "authorization_code", tokenRequest.GrantType, "Grant Type mismatch")
	assert.Equal(t, "auth-code-12345", tokenRequest.Code, "Code mismatch")
	assert.Equal(t, fmt.Sprintf("%s/oidc/callback", server.URL), tokenRequest.RedirectURI, "Redirect URI mismatch")
	assert.Equal(t, "client-id-123", tokenRequest.ClientID, "Client ID mismatch")
	assert.Equal(t, "client-secret-xyz", tokenRequest.ClientSecret, "Client Secret mismatch")

	tokenResponse, err := tokenRequest.ExchangeCode()
	assert.NoError(t, err, "Failed to exchange token")
	assert.NotNil(t, tokenResponse, "Token response is nil")
	assert.Equal(t, "access-token-12345", tokenResponse.AccessToken, "Access Token mismatch")
	assert.Equal(t, "id-token-67890", tokenResponse.IDToken, "ID Token mismatch")
}
