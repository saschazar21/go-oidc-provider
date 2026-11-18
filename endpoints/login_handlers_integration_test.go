package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
)

// TestConfiguredLoginPostgres exercises the actual coordinator/transaction in
// all three HTTP flows. It requires the same Docker/PostgreSQL test setup as
// the existing endpoint integration tests; no fake session IDs are minted.
func TestConfiguredLoginPostgres(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	t.Setenv("DEBUG", "0")
	t.Setenv("DEMO_MODE", "true") // Configured handlers must never leak codes.
	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	const password = " byte exact password "
	require.NoError(t, helpers.SetPassword(ctx, conn, user.ID, password))
	for _, flow := range []struct {
		name     string
		strategy helpers.LoginStrategy
		email    bool
		methods  []utils.AMR
	}{
		{"email only", helpers.EmailCodeStrategy(), false, []utils.AMR{utils.AMR_EMAIL}},
		{"password only", helpers.PasswordStrategy(), false, []utils.AMR{utils.AMR_PASSWORD}},
		{"password then email", helpers.PasswordStrategy(), true, []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}},
	} {
		t.Run(flow.name, func(t *testing.T) {
			var code string
			now := time.Now().UTC()
			service, err := helpers.NewLoginService(helpers.LoginConfig{
				DB: conn, Strategy: flow.strategy, RequireEmail: flow.email,
				Clock:   func() time.Time { return now },
				Limiter: helpers.LoginLimiterFunc(func(context.Context, string) error { return nil }),
				Sender: helpers.EmailCodeSenderFunc(func(_ context.Context, email, value string) error {
					require.Equal(t, string(*user.Email), email)
					code = value
					return nil
				}),
				ChallengeKey: []byte(strings.Repeat("k", 32)),
			})
			require.NoError(t, err)
			store := sessions.NewCookieStore([]byte(strings.Repeat("a", 32)), []byte(strings.Repeat("e", 32)))
			h, err := NewLoginHandlers(service, store)
			require.NoError(t, err)
			browser, csrf := configuredBrowser(t, h)
			continuation := &http.Cookie{Name: helpers.REDIRECT_COOKIE_NAME, Value: "/account?tab=security"}
			if flow.email {
				continuation = configuredSignedCookie(t, store, helpers.AUTHORIZATION_COOKIE_NAME,
					map[interface{}]interface{}{helpers.AUTHORIZATION_COOKIE_ID: uuid.NewString()})
			}
			countBefore, err := conn.NewSelect().Model((*models.Session)(nil)).Count(ctx)
			require.NoError(t, err)
			form := url.Values{"email": {string(*user.Email)}, "password": {password}, "csrf": {csrf},
				"continuation": {"https://evil.example/"}, "strategy": {"email"}, "require_email": {"false"}}
			w := httptest.NewRecorder()
			h.Login(w, configuredRequest(http.MethodPost, "/login", form.Encode(), browser, continuation))
			require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
			require.NotContains(t, w.Header().Get("Location"), password)
			var pending *http.Cookie
			if len(code) > 0 {
				require.Equal(t, helpers.CONSUME_MAGIC_LINK_ENDPOINT, w.Header().Get("Location"))
				require.NotContains(t, w.Header().Get("Location"), code)
				for _, cookie := range w.Result().Cookies() {
					require.NotEqual(t, helpers.SESSION_COOKIE_NAME, cookie.Name)
					if cookie.Name == loginBrowserCookie {
						pending = cookie
					}
				}
				require.NotNil(t, pending)
				countPending, err := conn.NewSelect().Model((*models.Session)(nil)).Count(ctx)
				require.NoError(t, err)
				require.Equal(t, countBefore, countPending, "no session before all configured methods")
				decoded, err := store.Get(configuredRequest(http.MethodGet, "/", "", pending), loginBrowserCookie)
				require.NoError(t, err)
				require.Len(t, decoded.Values, 2)
				attempt := decoded.Values["attempt"].(string)
				binding := decoded.Values["binding"].(string)
				require.Equal(t, csrf, loginCSRF(binding))
				// Posted IDs cannot replace the signed attempt; wrong proof must
				// preserve the browser cookie and must not issue an auth cookie.
				wrong := httptest.NewRecorder()
				h.MagicLinkToken(wrong, configuredRequest(http.MethodPost, "/login/magic",
					url.Values{"csrf": {csrf}, "code": {"wrong"}, "id": {attempt}}.Encode(), pending))
				require.Equal(t, http.StatusBadRequest, wrong.Code)
				require.Empty(t, wrong.Result().Cookies())
				// Resend has its own CSRF check and cannot create a session.
				now = now.Add(31 * time.Second)
				resend := httptest.NewRecorder()
				h.MagicLinkToken(resend, configuredRequest(http.MethodPost, "/login/magic",
					url.Values{"csrf": {csrf}, "action": {"resend"}}.Encode(), pending))
				require.Equal(t, http.StatusOK, resend.Code, resend.Body.String())
				require.Empty(t, resend.Result().Cookies())
				// Successful proof uses the cookie ID, not an attacker-supplied ID.
				w = httptest.NewRecorder()
				verify := url.Values{"csrf": {csrf}, "code": {code}, "id": {uuid.NewString()}}.Encode()
				h.MagicLinkToken(w, configuredRequest(http.MethodPost, "/login/magic", verify, pending))
				require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
				replay := httptest.NewRecorder()
				h.MagicLinkToken(replay, configuredRequest(http.MethodPost, "/login/magic", verify, pending))
				require.Equal(t, http.StatusBadRequest, replay.Code)
				require.Empty(t, replay.Result().Cookies())
			}
			expected := "/account?tab=security"
			if flow.email {
				expected = helpers.AUTHORIZATION_GRANT_ENDPOINT
			}
			require.Equal(t, expected, w.Header().Get("Location"))
			var sessionCookie *http.Cookie
			cleared := false
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == helpers.SESSION_COOKIE_NAME {
					sessionCookie = cookie
					require.Positive(t, cookie.MaxAge)
					require.True(t, cookie.Secure && cookie.HttpOnly)
				}
				if cookie.Name == loginBrowserCookie {
					cleared = cookie.MaxAge == -1
				}
			}
			require.True(t, cleared)
			require.NotNil(t, sessionCookie)
			decoded, err := store.Get(configuredRequest(http.MethodGet, "/", "", sessionCookie), helpers.SESSION_COOKIE_NAME)
			require.NoError(t, err)
			var persisted models.Session
			require.NoError(t, conn.NewSelect().Model(&persisted).Where("session_id = ?", decoded.Values[helpers.SESSION_COOKIE_ID]).Scan(ctx))
			require.Equal(t, user.ID, persisted.UserID)
			require.ElementsMatch(t, flow.methods, *persisted.AMR)
			countAfter, err := conn.NewSelect().Model((*models.Session)(nil)).Count(ctx)
			require.NoError(t, err)
			require.Equal(t, countBefore+1, countAfter)
		})
	}
}
