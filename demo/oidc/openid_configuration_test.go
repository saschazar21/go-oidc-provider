package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenIDConfiguration(t *testing.T) {
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

	config, err := FetchOpenIDConfiguration()
	assert.NoError(t, err, "Failed to fetch OpenID Configuration")
	assert.NotNil(t, config, "OpenID Configuration is nil")
	assert.Equal(t, server.URL+"/authorize", config.GetAuthorizationEndpoint().String(), "Authorization Endpoint mismatch")
	assert.Equal(t, server.URL+"/token", config.TokenEndpoint, "Token Endpoint mismatch")
	assert.Equal(t, server.URL+"/userinfo", config.UserinfoEndpoint, "Userinfo Endpoint mismatch")
	assert.Equal(t, server.URL+"/.well-known/jwks.json", config.JwksURI, "JWKS URI mismatch")

	t.Logf("Fetched OpenID Configuration: %+v", config)
}
