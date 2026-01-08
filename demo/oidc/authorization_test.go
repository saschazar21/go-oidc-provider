package oidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorization(t *testing.T) {
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

		http.NotFound(w, r)
	}))
	defer server.Close()
	serverURL = server.URL

	t.Setenv(ISSUER_ENV, server.URL)
	t.Setenv(NETLIFY_DEPLOY_PRIME_URL_ENV, server.URL)
	t.Setenv(OIDC_CLIENT_ID_ENV, "client-id-123")
	t.Setenv(OIDC_CLIENT_SECRET_ENV, "client-secret-xyz")

	authorizationRequest := NewOIDCAuthorizationRequest()

	assert.NotNil(t, authorizationRequest, "Failed to create OIDC Authorization Request")
	assert.Equal(t, "client-id-123", authorizationRequest.ClientID, "Client ID mismatch")
	assert.Equal(t, "code", authorizationRequest.ResponseType, "Response Type mismatch")
	assert.Equal(t, "openid", authorizationRequest.Scope, "Scope mismatch")
	assert.Equal(t, fmt.Sprintf("%s/oidc/callback", server.URL), authorizationRequest.RedirectURI, "Redirect URI mismatch")

	authorizationRequest.WithClientID("some-other-client-id").WithScope("openid profile email")

	assert.Equal(t, "some-other-client-id", authorizationRequest.ClientID, "Client ID mismatch after update")
	assert.Equal(t, "openid profile email", authorizationRequest.Scope, "Scope mismatch after update")

	authorizationURL := authorizationRequest.BuildURL()
	assert.NotEmpty(t, authorizationURL, "Failed to build authorization URL")

	t.Logf("Authorization URL: %s", authorizationURL)
	assert.Contains(t, authorizationURL, "client_id=some-other-client-id", "Authorization URL missing client_id")
	assert.Contains(t, authorizationURL, "scope=openid+profile+email", "Authorization URL missing scope")
	assert.Contains(t, authorizationURL, "response_type=code", "Authorization URL missing response_type")
	assert.Contains(t, authorizationURL, fmt.Sprintf("redirect_uri=%s", url.QueryEscape(fmt.Sprintf("%s/oidc/callback", server.URL))), "Authorization URL missing redirect_uri")
}
