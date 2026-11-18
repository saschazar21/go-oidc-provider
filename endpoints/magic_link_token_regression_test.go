package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
)

func TestMagicLinkTokenRegression(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	t.Setenv("DEBUG", "0")
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	conn := db.Connect(ctx)
	defer conn.Close()
	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	create := func(t *testing.T) (*models.MagicLinkToken, string) {
		t.Helper()
		token, err := models.CreateMagicLinkToken(ctx, conn, string(*user.Email))
		require.NoError(t, err)
		return token, string(*token.Token)
	}
	post := func(t *testing.T, token *models.MagicLinkToken, code, redirect string, authorization bool) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"id": {token.ID.String()}, "token": {code}}
		r := httptest.NewRequest(http.MethodPost, "/login/magic", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if redirect != "" {
			// Use the wire header: AddCookie strips backslashes before the handler
			// can validate them, masking the actual untrusted cookie value.
			r.Header.Set("Cookie", helpers.REDIRECT_COOKIE_NAME+"="+redirect)
		}
		if authorization {
			cookie, err := utils.NewCookieStore().Get(r, helpers.AUTHORIZATION_COOKIE_NAME)
			require.NoError(t, err)
			cookie.Values[helpers.AUTHORIZATION_COOKIE_ID] = "signed-authorization"
			w := httptest.NewRecorder()
			require.NoError(t, cookie.Save(r, w))
			for _, c := range w.Result().Cookies() {
				r.AddCookie(c)
			}
		}
		w := httptest.NewRecorder()
		require.NotPanics(t, func() { HandleMagicLinkToken(w, r) })
		return w
	}
	assertNoSession := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		for _, cookie := range w.Result().Cookies() {
			require.NotEqual(t, helpers.SESSION_COOKIE_NAME, cookie.Name, "authentication cookie issued on rejection")
		}
		count, err := conn.NewSelect().TableExpr("oidc_sessions").Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
	}

	for _, outcome := range []string{"wrong", "expired", "inactive user", "locked user"} {
		t.Run(outcome+" persists terminal rejection", func(t *testing.T) {
			token, code := create(t)
			correct := code
			want := utils.FAILED
			switch outcome {
			case "wrong":
				code = "not-the-code"
			case "expired":
				want = utils.EXPIRED
				_, err := conn.NewUpdate().Model((*models.MagicLinkToken)(nil)).Set("expires_at = ?", time.Now().Add(-time.Hour)).Where("token_id = ?", token.ID).Exec(ctx)
				require.NoError(t, err)
			default:
				column, value := "is_active", false
				if outcome == "locked user" {
					column, value = "is_locked", true
				}
				_, err := conn.NewUpdate().TableExpr("oidc_users").Set(column+" = ?", value).Where("user_id = ?", user.ID).Exec(ctx)
				require.NoError(t, err)
				defer func() {
					_, err := conn.NewUpdate().TableExpr("oidc_users").Set("is_active = true").Set("is_locked = false").Where("user_id = ?", user.ID).Exec(ctx)
					require.NoError(t, err)
				}()
			}
			w := post(t, token, code, "", false)
			require.Equal(t, http.StatusBadRequest, w.Code)
			assertNoSession(t, w)
			var stored models.MagicLinkToken
			require.NoError(t, conn.NewSelect().Model(&stored).Where("token_id = ?", token.ID).Scan(ctx))
			require.NotNil(t, stored.Result)
			require.Equal(t, want, *stored.Result)
			require.False(t, *stored.IsActive)
			require.Nil(t, stored.ConsumedAt)
			w = post(t, token, correct, "", false)
			require.Equal(t, http.StatusBadRequest, w.Code)
			assertNoSession(t, w)
		})
	}

	for _, deferred := range []bool{false, true} {
		name, timing := "insert failure", ""
		if deferred {
			name, timing = "commit failure", "DEFERRABLE INITIALLY DEFERRED"
		}
		t.Run(name+" rolls back consumption and session", func(t *testing.T) {
			_, err := conn.ExecContext(ctx, `CREATE FUNCTION reject_magic_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected session failure'; END $$`)
			require.NoError(t, err)
			defer func() {
				_, err := conn.ExecContext(ctx, `DROP FUNCTION reject_magic_session() CASCADE`)
				require.NoError(t, err)
			}()
			_, err = conn.ExecContext(ctx, `CREATE CONSTRAINT TRIGGER reject_magic_session AFTER INSERT ON oidc_sessions `+timing+` FOR EACH ROW EXECUTE FUNCTION reject_magic_session()`)
			require.NoError(t, err)
			token, code := create(t)
			w := post(t, token, code, "", false)
			require.Equal(t, http.StatusInternalServerError, w.Code)
			assertNoSession(t, w)
			var stored models.MagicLinkToken
			require.NoError(t, conn.NewSelect().Model(&stored).Where("token_id = ?", token.ID).Scan(ctx))
			require.True(t, *stored.IsActive)
			require.Nil(t, stored.Result)
			require.Nil(t, stored.ConsumedAt)
		})
	}

	for _, tc := range []struct {
		redirect string
		auth     bool
		want     string
	}{
		{"/account?tab=profile", false, "/account?tab=profile"},
		{"//evil.example", false, "/"},
		{`/\evil.example`, false, "/"},
		{"https://evil.example", false, "/"},
		{"/%2fevil.example", false, "/"},
		{"/account", true, helpers.AUTHORIZATION_GRANT_ENDPOINT},
	} {
		t.Run("success redirect "+tc.redirect+tc.want, func(t *testing.T) {
			token, code := create(t)
			before := time.Now().UTC()
			w := post(t, token, code, tc.redirect, tc.auth)
			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, tc.want, w.Header().Get("Location"))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, c := range w.Result().Cookies() {
				r.AddCookie(c)
			}
			cookie, err := utils.NewCookieStore().Get(r, helpers.SESSION_COOKIE_NAME)
			require.NoError(t, err)
			id, ok := cookie.Values[helpers.SESSION_COOKIE_ID].(string)
			require.True(t, ok)
			var session models.Session
			require.NoError(t, conn.NewSelect().Model(&session).Where("session_id = ?", id).Scan(ctx))
			require.Equal(t, user.ID, session.UserID)
			require.Equal(t, []utils.AMR{utils.AMR_EMAIL}, *session.AMR)
			require.False(t, session.AuthTime.Before(before))
			require.WithinDuration(t, time.Now(), session.AuthTime, 5*time.Second)
			w = post(t, token, code, "", false)
			require.Equal(t, http.StatusBadRequest, w.Code)
			for _, c := range w.Result().Cookies() {
				require.NotEqual(t, helpers.SESSION_COOKIE_NAME, c.Name)
			}
		})
	}
}

func TestSafeMagicLinkRedirect(t *testing.T) {
	for _, value := range []string{"", "relative", "//host", `\host`, `/\host`, "https://host", "/%2fhost", "/%5chost", "/%0d%0aLocation:evil", "/\x00", "/\t/host", "/\nhost"} {
		require.False(t, isSafeMagicLinkRedirect(value), "%q", value)
	}
	for _, value := range []string{"/", "/account", "/account?next=%2Fsettings", "/account#profile"} {
		require.True(t, isSafeMagicLinkRedirect(value), "%q", value)
	}
}
