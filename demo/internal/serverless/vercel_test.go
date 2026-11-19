//go:build vercel

package serverless

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saschazar21/go-oidc-demo/endpoints"
	"github.com/stretchr/testify/require"
	"github.com/vercel/go-bridge/go/bridge"
)

func TestVercelRequestResponse(t *testing.T) {
	request, err := bridge.ParseJsonIntoRequest(`{
		"method":"POST",
		"path":"/token?state=a%2Bb&scope=openid+email",
		"headers":{"host":"demo.example.com","content-type":"application/x-www-form-urlencoded","x-real-ip":"192.0.2.1"},
		"encoding":"base64",
		"body":"Y29kZT1hJTJCYg=="
	}`)
	require.NoError(t, err)
	response, err := bridge.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/token", r.URL.Path)
		require.Equal(t, "a+b", r.URL.Query().Get("state"))
		require.Equal(t, "openid email", r.URL.Query().Get("scope"))
		require.Equal(t, "demo.example.com", r.Host)
		require.Equal(t, "192.0.2.1", r.RemoteAddr)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, "code=a%2Bb", string(body))
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "first", Secure: true, HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "state", Value: "second", Secure: true, HttpOnly: true})
		http.Redirect(w, r, "/callback?state=a%2Bb", http.StatusSeeOther)
	}), &request)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, response.StatusCode)
	require.Equal(t, []string{"/callback?state=a%2Bb"}, response.Headers["Location"])
	require.Len(t, response.Headers["Set-Cookie"], 2)
	require.Equal(t, "base64", response.Encoding)
	_, err = base64.StdEncoding.DecodeString(response.Body)
	require.NoError(t, err)
}

func TestVercelHTMLResponses(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authorization_endpoint":"https://demo.example.com/authorize"}`)
	}))
	defer issuer.Close()
	t.Setenv("ISSUER_URL", issuer.URL)
	t.Setenv("OIDC_CLIENT_ID", "demo-client")

	for _, test := range []struct {
		name    string
		path    string
		handler http.HandlerFunc
		status  int
	}{
		{"index", "/", endpoints.HandleIndex, http.StatusOK},
		{"callback error", "/callback?error=access_denied", endpoints.HandleCallback, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := bridge.Serve(test.handler, &bridge.Request{Method: "GET", Path: test.path})
			require.NoError(t, err)
			require.Equal(t, test.status, response.StatusCode)
			require.Equal(t, []string{"text/html; charset=utf-8"}, response.Headers["Content-Type"])
			body, err := base64.StdEncoding.DecodeString(response.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "<html")
		})
	}
}
