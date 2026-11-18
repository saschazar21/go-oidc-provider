package endpoints

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func configuredTestHandlers(t *testing.T, password bool, limiter helpers.LoginLimiter) (*LoginHandlers, *sessions.CookieStore) {
	t.Helper()
	if limiter == nil {
		limiter = helpers.LoginLimiterFunc(func(context.Context, string) error { return errors.New("limited") })
	}
	config := helpers.LoginConfig{DB: new(bun.DB), Limiter: limiter,
		Sender:       helpers.EmailCodeSenderFunc(func(context.Context, string, string) error { return nil }),
		ChallengeKey: []byte(strings.Repeat("k", 32))}
	if password {
		config.Strategy = helpers.PasswordStrategy()
	}
	service, err := helpers.NewLoginService(config)
	require.NoError(t, err)
	store := sessions.NewCookieStore([]byte(strings.Repeat("a", 32)), []byte(strings.Repeat("e", 32)))
	h, err := NewLoginHandlers(service, store)
	require.NoError(t, err)
	return h, store
}

func configuredBrowser(t *testing.T, h *LoginHandlers) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.Login(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, w.Result().Cookies(), 1)
	cookie := w.Result().Cookies()[0]
	require.Equal(t, loginBrowserCookie, cookie.Name)
	require.True(t, cookie.Secure)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	require.Equal(t, 600, cookie.MaxAge)
	require.Equal(t, "/", cookie.Path)
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	require.Len(t, match, 2)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'")
	return cookie, match[1]
}

func configuredRequest(method, path, body string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

func configuredSignedCookie(t *testing.T, store sessions.Store, name string, values map[interface{}]interface{}) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cookie := sessions.NewSession(store, name)
	cookie.Values = values
	cookie.Options = loginCookieOptions(600)
	require.NoError(t, store.Save(r, w, cookie))
	require.Len(t, w.Result().Cookies(), 1)
	return w.Result().Cookies()[0]
}

func TestConfiguredLoginConstructor(t *testing.T) {
	h, store := configuredTestHandlers(t, false, nil)
	_, err := NewLoginHandlers(nil, store)
	require.Error(t, err)
	_, err = NewLoginHandlers(h.service, nil)
	require.Error(t, err)
	var typedNil *sessions.CookieStore
	_, err = NewLoginHandlers(h.service, typedNil)
	require.Error(t, err)
	_, err = NewLoginHandlers(new(helpers.LoginService), store)
	require.Error(t, err)
}

func TestConfiguredLoginForms(t *testing.T) {
	for _, password := range []bool{false, true} {
		h, store := configuredTestHandlers(t, password, nil)
		cookie, _ := configuredBrowser(t, h)
		r := configuredRequest(http.MethodGet, "/login?password=secret&code=123456", "", cookie)
		w := httptest.NewRecorder()
		h.Login(w, r)
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, password, strings.Contains(w.Body.String(), `type="password"`))
		require.Contains(t, w.Body.String(), `name="email"`)
		require.NotContains(t, w.Body.String(), "secret")
		require.Empty(t, w.Result().Cookies())
		decoded, err := store.Get(configuredRequest(http.MethodGet, "/", "", cookie), loginBrowserCookie)
		require.NoError(t, err)
		require.Len(t, decoded.Values, 1)
		require.True(t, validBrowserBinding(decoded.Values["binding"].(string)))
	}
}

func TestConfiguredLoginRejectsInvalidForms(t *testing.T) {
	calls := 0
	h, _ := configuredTestHandlers(t, true, helpers.LoginLimiterFunc(func(context.Context, string) error {
		calls++
		return errors.New("limited")
	}))
	cookie, csrf := configuredBrowser(t, h)
	other, otherCSRF := configuredBrowser(t, h)
	require.NotEqual(t, csrf, otherCSRF)
	good := url.Values{"email": {"person@example.com"}, "password": {"do not disclose"}, "csrf": {csrf}}.Encode()
	for _, tc := range []struct {
		name, body, contentType string
		cookies                 []*http.Cookie
	}{
		{"missing cookie", good, "", nil},
		{"missing csrf", "email=e%40example.com&password=secret", "", []*http.Cookie{cookie}},
		{"query csrf ignored", "email=e%40example.com&password=secret", "", []*http.Cookie{cookie}},
		{"wrong csrf", strings.Replace(good, csrf, csrf+"x", 1), "", []*http.Cookie{cookie}},
		{"other browser", good, "", []*http.Cookie{other}},
		{"duplicate cookies", good, "", []*http.Cookie{cookie, cookie}},
		{"tamper", good, "", []*http.Cookie{{Name: loginBrowserCookie, Value: cookie.Value + "bad"}}},
		{"wrong content type", good, "application/json", []*http.Cookie{cookie}},
		{"malformed content type", good, "application/x-www-form-urlencoded; ???", []*http.Cookie{cookie}},
		{"duplicate csrf", good + "&csrf=" + csrf, "", []*http.Cookie{cookie}},
		{"missing email", "csrf=" + csrf + "&password=secret", "", []*http.Cookie{cookie}},
		{"missing password", "csrf=" + csrf + "&email=a%40example.com", "", []*http.Cookie{cookie}},
		{"bad escape", good + "&extra=%zz", "", []*http.Cookie{cookie}},
		{"oversized", good + "&extra=" + strings.Repeat("x", loginFormLimit), "", []*http.Cookie{cookie}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := configuredRequest(http.MethodPost, "/login?csrf="+csrf, tc.body, tc.cookies...)
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			h.Login(w, r)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Empty(t, w.Result().Cookies())
			require.Empty(t, w.Header().Get("Location"))
			require.NotContains(t, w.Body.String(), "do not disclose")
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		})
	}
	require.Zero(t, calls)
	w := httptest.NewRecorder()
	h.Login(w, configuredRequest(http.MethodPost, "/login", good, cookie))
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, 1, calls, "valid MIME parameters and CSRF must reach the service limiter")
}

func TestConfiguredLoginMalformedBrowserRegeneration(t *testing.T) {
	h, store := configuredTestHandlers(t, false, nil)
	expired := make([]byte, 40)
	binary.BigEndian.PutUint64(expired[32:], uint64(time.Now().Add(-time.Minute).Unix()))
	for _, values := range []map[interface{}]interface{}{
		{}, {"binding": 12}, {"binding": "bad"},
		{"binding": base64.RawURLEncoding.EncodeToString(expired)},
	} {
		cookie := configuredSignedCookie(t, store, loginBrowserCookie, values)
		w := httptest.NewRecorder()
		h.MagicLinkToken(w, configuredRequest(http.MethodGet, "/login/magic?id="+uuid.NewString(), "", cookie))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Empty(t, w.Result().Cookies())
		w = httptest.NewRecorder()
		h.Login(w, configuredRequest(http.MethodGet, "/login", "", cookie))
		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, w.Result().Cookies(), 1)
	}
}

func TestConfiguredLoginMagicBoundAttempt(t *testing.T) {
	calls := 0
	h, store := configuredTestHandlers(t, false, helpers.LoginLimiterFunc(func(context.Context, string) error {
		calls++
		return errors.New("limited")
	}))
	binding, err := newLoginBinding()
	require.NoError(t, err)
	pending := configuredSignedCookie(t, store, loginBrowserCookie, map[interface{}]interface{}{
		"binding": binding, "attempt": uuid.NewString(),
	})
	initial, _ := configuredBrowser(t, h)
	for _, cookie := range []*http.Cookie{nil, initial, {Name: loginBrowserCookie, Value: "tampered"}} {
		r := configuredRequest(http.MethodGet, "/login/magic?id="+uuid.NewString()+"&code=123456", "")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.MagicLinkToken(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Empty(t, w.Result().Cookies())
	}
	w := httptest.NewRecorder()
	h.MagicLinkToken(w, configuredRequest(http.MethodGet, "/login/magic?id=ignored&code=123456", "", pending))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "123456")
	require.NotContains(t, w.Body.String(), `name="id"`)
	for _, body := range []string{"code=123456", "csrf=" + loginCSRF(binding) + "&action=invalid"} {
		w := httptest.NewRecorder()
		h.MagicLinkToken(w, configuredRequest(http.MethodPost, "/login/magic", body, pending))
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	require.Zero(t, calls)
	for _, action := range []string{"verify", "resend"} {
		w := httptest.NewRecorder()
		h.MagicLinkToken(w, configuredRequest(http.MethodPost, "/login/magic", "csrf="+loginCSRF(binding)+"&action="+action+"&code=123456&id="+uuid.NewString(), pending))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Empty(t, w.Result().Cookies(), "failed verification/resend preserves the pending cookie")
	}
	require.Equal(t, 2, calls)
	password, _ := configuredTestHandlers(t, true, nil)
	w = httptest.NewRecorder()
	password.MagicLinkToken(w, configuredRequest(http.MethodGet, "/login/magic", "", pending))
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConfiguredLoginContinuation(t *testing.T) {
	h, store := configuredTestHandlers(t, false, nil)
	for _, path := range []string{"/", "/account", "/account?tab=hello%20world", "/authorize"} {
		r := configuredRequest(http.MethodPost, "/login", "continuation=https://evil.example", &http.Cookie{Name: helpers.REDIRECT_COOKIE_NAME, Value: path})
		got, err := h.continuation(r)
		require.NoError(t, err)
		require.Equal(t, path, got)
	}
	for _, path := range []string{"https://evil.example", "//evil.example", "/%2fevil.example", "/%252fevil.example", "/%5cevil", "/%0aevil", "relative", "/%zz"} {
		require.False(t, safeHandlerContinuation(path), path)
	}
	authorization := configuredSignedCookie(t, store, helpers.AUTHORIZATION_COOKIE_NAME, map[interface{}]interface{}{helpers.AUTHORIZATION_COOKIE_ID: uuid.NewString()})
	got, err := h.continuation(configuredRequest(http.MethodPost, "/login", "", authorization, &http.Cookie{Name: helpers.REDIRECT_COOKIE_NAME, Value: "/other"}))
	require.NoError(t, err)
	require.Equal(t, helpers.AUTHORIZATION_GRANT_ENDPOINT, got)
	_, err = h.continuation(configuredRequest(http.MethodPost, "/login", "", &http.Cookie{Name: helpers.AUTHORIZATION_COOKIE_NAME, Value: "bad"}))
	require.Error(t, err)
}

type configuredFailingStore struct {
	sessions.Store
	failName string
}

func (s configuredFailingStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Name() == s.failName {
		return errors.New("encoding unavailable, secret error detail")
	}
	return s.Store.Save(r, w, session)
}

func TestConfiguredLoginCookieFinalization(t *testing.T) {
	h, store := configuredTestHandlers(t, false, nil)
	result := &helpers.LoginResult{Session: &models.Session{ID: uuid.New(), UserID: uuid.New()}, Continuation: "/account"}
	result.Session.ExpiresAt.ExpiresAt = time.Now().Add(time.Hour)
	for _, name := range []string{helpers.SESSION_COOKIE_NAME, loginBrowserCookie} {
		h.store = configuredFailingStore{Store: store, failName: name}
		w := httptest.NewRecorder()
		h.complete(w, configuredRequest(http.MethodPost, "/login", ""), result)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Empty(t, w.Result().Cookies(), "no partial session or pending-cookie deletion")
		require.NotContains(t, w.Body.String(), "secret error detail")
	}
	h.store = store
	w := httptest.NewRecorder()
	h.complete(w, configuredRequest(http.MethodPost, "/login", "", &http.Cookie{Name: helpers.SESSION_COOKIE_NAME, Value: "tampered"}), result)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/account", w.Header().Get("Location"))
	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == helpers.SESSION_COOKIE_NAME {
			sessionCookie = cookie
			require.InDelta(t, 3600, cookie.MaxAge, 2)
			require.True(t, cookie.Secure && cookie.HttpOnly)
		} else {
			require.Equal(t, -1, cookie.MaxAge)
		}
	}
	require.NotNil(t, sessionCookie)
	decoded, err := store.Get(configuredRequest(http.MethodGet, "/", "", sessionCookie), helpers.SESSION_COOKIE_NAME)
	require.NoError(t, err)
	require.Equal(t, result.Session.ID.String(), decoded.Values[helpers.SESSION_COOKIE_ID])
	require.Len(t, decoded.Values, 1)
	for _, bad := range []*helpers.LoginResult{nil, {AttemptID: uuid.New()}, {Session: &models.Session{}, Continuation: "/"}} {
		w := httptest.NewRecorder()
		h.complete(w, configuredRequest(http.MethodPost, "/login", ""), bad)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Empty(t, w.Result().Cookies())
	}
}

func TestConfiguredLoginProtect(t *testing.T) {
	h, _ := configuredTestHandlers(t, true, nil)
	called := false
	handler := h.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		weak := []utils.AMR{utils.AMR_EMAIL}
		strong := []utils.AMR{utils.AMR_PASSWORD}
		require.False(t, helpers.AuthenticationMethodsSatisfied(r.Context(), nil))
		require.False(t, helpers.AuthenticationMethodsSatisfied(r.Context(), &weak))
		require.True(t, helpers.AuthenticationMethodsSatisfied(r.Context(), &strong))
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/custom", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.True(t, called)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.True(t, helpers.AuthenticationMethodsSatisfied(r.Context(), nil), "original request remains unchanged")
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodHead} {
		for _, handler := range []http.HandlerFunc{h.Login, h.MagicLinkToken} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(method, "/login", nil))
			require.Equal(t, http.StatusMethodNotAllowed, w.Code)
			require.Equal(t, "GET, POST", w.Header().Get("Allow"))
		}
	}
}
