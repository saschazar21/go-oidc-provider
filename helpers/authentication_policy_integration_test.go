package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	oidcerrors "github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func policyTestCookie(t *testing.T, r *http.Request, name, key, value string) {
	t.Helper()
	cookie, err := utils.NewCookieStore().New(r, name)
	require.NoError(t, err)
	cookie.Values[key] = value
	w := httptest.NewRecorder()
	require.NoError(t, cookie.Save(r, w))
	r.AddCookie(w.Result().Cookies()[0])
}

func TestAuthenticationPolicyOIDC(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	t.Setenv(utils.ISSUER_URL_ENV, "https://issuer.example.com")
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()

	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.Nil(t, user.Save(ctx, conn))
	var client models.Client
	require.NoError(t, test.LoadFixture("client_minimal.json", &client))
	client.OwnerID = user.ID
	confidential := true
	client.IsConfidential = &confidential
	grants := []utils.GrantType{utils.AUTHORIZATION_CODE, utils.REFRESH_TOKEN, utils.CLIENT_CREDENTIALS}
	client.GrantTypes = &grants
	require.Nil(t, client.Save(ctx, conn))

	full := []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}
	email := []utils.AMR{utils.AMR_EMAIL}
	password := []utils.AMR{utils.AMR_PASSWORD}
	authTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	newAuth := func(t *testing.T, tx bun.IDB, evidence *[]utils.AMR) *models.Authorization {
		t.Helper()
		var auth models.Authorization
		require.NoError(t, test.LoadFixture("authorization_approved.json", &auth))
		auth.ClientID, auth.Client, auth.UserID, auth.User = client.ID, &client, user.ID, &user
		auth.Scope = append(auth.Scope, utils.OFFLINE_ACCESS)
		auth.AuthTime, auth.AMR = &authTime, copyAuthenticationMethods(evidence)
		require.Nil(t, auth.Save(ctx, tx))
		return &auth
	}
	newSession := func(t *testing.T, tx bun.IDB, evidence *[]utils.AMR, at time.Time) *models.Session {
		t.Helper()
		session := &models.Session{UserID: user.ID, User: &user, AMR: copyAuthenticationMethods(evidence), AuthTime: at}
		require.Nil(t, session.Save(ctx, tx))
		return session
	}
	withFixtures := func(t *testing.T) bun.IDB {
		t.Helper()
		// Session/Token.AfterSelect use query.DB(), not the selecting transaction.
		// Commit fixtures so those hooks exercise real behavior rather than failing
		// to find uncommitted rows. This container is private to this serial suite.
		t.Cleanup(func() {
			for _, table := range []string{"oidc_tokens", "oidc_authorizations", "oidc_sessions"} {
				_, err := conn.NewDelete().Table(table).Where("1 = 1").Exec(ctx)
				require.NoError(t, err)
			}
		})
		return conn
	}

	for _, tt := range []struct {
		name     string
		evidence *[]utils.AMR
		allowed  bool
	}{
		{name: "unknown"}, {name: "weak", evidence: &email},
		{name: "password only", evidence: &password}, {name: "complete", evidence: &full, allowed: true},
	} {
		t.Run("approved cookie/"+tt.name, func(t *testing.T) {
			tx := withFixtures(t)
			auth := newAuth(t, tx, &full)
			session := newSession(t, tx, tt.evidence, authTime)
			r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodGet, "/authorize", nil), full)
			policyTestCookie(t, r, AUTHORIZATION_COOKIE_NAME, AUTHORIZATION_COOKIE_ID, auth.ID.String())
			policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
			response, consent, err := HandleAuthorizationRequest(ctx, tx, httptest.NewRecorder(), r)
			require.Nil(t, err)
			require.Nil(t, consent)
			require.NotNil(t, response)
			if tt.allowed {
				require.IsType(t, &authorizationResponse{}, response)
			} else {
				redirect, ok := response.(oidcerrors.InternalRedirectError)
				require.True(t, ok)
				require.Equal(t, LOGIN_ENDPOINT, redirect.Location)
				stored := &models.Authorization{ID: auth.ID}
				require.NoError(t, tx.NewSelect().Model(stored).WherePK().Scan(ctx))
				require.False(t, stored.IsApproved())
				require.Equal(t, uuid.Nil, stored.UserID)
				require.Nil(t, stored.AMR)
			}
		})

		t.Run("silent request/"+tt.name, func(t *testing.T) {
			tx := withFixtures(t)
			auth := newAuth(t, tx, &full)
			session := newSession(t, tx, tt.evidence, authTime)
			params := createParams(url.Values{"client_id": {client.ID}, "client_secret": {client.Secret.String()}, "redirect_uri": {auth.RedirectURI}, "prompt": {"none"}})
			r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil), full)
			policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
			_, _, err := HandleAuthorizationRequest(ctx, tx, httptest.NewRecorder(), r)
			if tt.allowed {
				require.Nil(t, err)
			} else {
				require.IsType(t, oidcerrors.OIDCErrorResponse{}, err)
				require.Equal(t, oidcerrors.LOGIN_REQUIRED, err.(oidcerrors.OIDCErrorResponse).ErrorCode)
			}
		})

		t.Run("direct consent/"+tt.name, func(t *testing.T) {
			tx := withFixtures(t)
			auth := newAuth(t, tx, nil)
			_, err := tx.NewUpdate().Model(auth).WherePK().
				Set("is_active = FALSE").Set("status = 'pending'").
				Set("user_id = NULL").Set("auth_time = NULL").Set("amr = NULL").Exec(ctx)
			require.NoError(t, err)
			session := newSession(t, tx, tt.evidence, authTime)
			r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader("action=approved")), full)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			policyTestCookie(t, r, AUTHORIZATION_COOKIE_NAME, AUTHORIZATION_COOKIE_ID, auth.ID.String())
			policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
			_, oidcErr := HandleAuthorizationDecision(ctx, tx, r)
			stored := &models.Authorization{ID: auth.ID}
			require.NoError(t, tx.NewSelect().Model(stored).WherePK().Scan(ctx))
			if tt.allowed {
				require.Nil(t, oidcErr)
				require.True(t, stored.IsApproved())
				require.Equal(t, full, *stored.AMR)
				require.True(t, stored.AuthTime.Equal(authTime))
			} else {
				require.NotNil(t, oidcErr)
				require.False(t, stored.IsApproved())
				require.Nil(t, stored.AMR)
			}
		})

		for _, grant := range []utils.GrantType{utils.AUTHORIZATION_CODE, utils.REFRESH_TOKEN} {
			t.Run(string(grant)+"/"+tt.name, func(t *testing.T) {
				tx := withFixtures(t)
				auth := newAuth(t, tx, tt.evidence)
				tokenType := utils.AUTHORIZATION_CODE_TYPE
				if grant == utils.REFRESH_TOKEN {
					tokenType = utils.REFRESH_TOKEN_TYPE
				}
				token, err := models.CreateToken(ctx, tx, string(tokenType), auth)
				require.Nil(t, err)
				params := url.Values{"grant_type": {string(grant)}, "client_id": {client.ID}, "client_secret": {client.Secret.String()}, "redirect_uri": {auth.RedirectURI}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
				if grant == utils.REFRESH_TOKEN {
					params.Set("refresh_token", token.Value.String())
				} else {
					params.Set("code", token.Value.String())
				}
				r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(params.Encode())), full)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				tr, err := ParseTokenRequest(r)
				require.Nil(t, err)
				tokens, err := tr.HandleRequest(ctx, tx) // Explicit context intentionally lacks request policy.
				if tt.allowed {
					require.Nil(t, err)
					require.NotNil(t, tokens[utils.ACCESS_TOKEN_TYPE])
					require.NotNil(t, tokens[utils.REFRESH_TOKEN_TYPE])
					for _, minted := range tokens {
						require.Equal(t, full, *minted.Authorization.AMR)
						require.True(t, minted.Authorization.AuthTime.Equal(authTime))
					}
					claims, claimErr := idtoken.NewClaimsFromTokens(&tokens)
					require.NoError(t, claimErr)
					require.Equal(t, full, claims.AMR)
					require.Equal(t, authTime.Unix(), claims.AuthTime.Unix())
				} else {
					require.IsType(t, oidcerrors.JSONError{}, err)
					require.Equal(t, oidcerrors.INVALID_GRANT, err.(oidcerrors.JSONError).ErrorCode)
					stored := &models.Token{ID: token.ID}
					// A model SELECT would itself set LastUsedAt, hiding mutations
					// caused by the request under test.
					require.NoError(t, tx.NewRaw("SELECT * FROM oidc_tokens WHERE token_id = ?", token.ID).Scan(ctx, stored))
					require.Nil(t, stored.ConsumedAt)
					require.Nil(t, stored.RevokedAt)
					require.Nil(t, stored.LastUsedAt, "policy rejection must precede the token usage hook")
					require.True(t, *stored.IsActive)
					count, countErr := tx.NewSelect().Model((*models.Authorization)(nil)).Count(ctx)
					require.NoError(t, countErr)
					require.Equal(t, 1, count, "policy rejection must not create another grant")
				}
			})
		}
	}

	for _, tt := range []struct {
		name     string
		evidence *[]utils.AMR
	}{
		{name: "unknown"}, {name: "email", evidence: &email},
	} {
		t.Run("legacy approved cookie/"+tt.name, func(t *testing.T) {
			tx := withFixtures(t)
			auth := newAuth(t, tx, nil)
			session := newSession(t, tx, tt.evidence, authTime)
			r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
			policyTestCookie(t, r, AUTHORIZATION_COOKIE_NAME, AUTHORIZATION_COOKIE_ID, auth.ID.String())
			policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
			response, consent, err := HandleAuthorizationRequest(ctx, tx, httptest.NewRecorder(), r)
			require.Nil(t, err)
			require.Nil(t, consent)
			require.IsType(t, &authorizationResponse{}, response, "absent policy must retain legacy session reuse")
			stored := &models.Authorization{ID: auth.ID}
			require.NoError(t, tx.NewSelect().Model(stored).WherePK().Scan(ctx))
			require.True(t, stored.IsApproved())
			require.Equal(t, user.ID, stored.UserID)
			require.Equal(t, tt.evidence, stored.AMR, "legacy reuse must not invent stronger evidence")
		})
	}

	t.Run("client credentials has no end-user policy", func(t *testing.T) {
		tx := withFixtures(t)
		r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "client_id": {client.ID}, "client_secret": {client.Secret.String()}}.Encode())), nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tr, err := ParseTokenRequest(r)
		require.Nil(t, err)
		tokens, err := tr.HandleRequest(ctx, tx)
		require.Nil(t, err)
		require.NotNil(t, tokens[utils.CLIENT_CREDENTIALS_TYPE])
	})

	for _, params := range []url.Values{{"prompt": {"login"}}, {"max_age": {"0"}}, {"max_age": {"1"}}} {
		t.Run("reauthentication/"+params.Encode(), func(t *testing.T) {
			tx := withFixtures(t)
			auth := newAuth(t, tx, &full)
			old := newSession(t, tx, &full, authTime)
			values := createParams(url.Values{"client_id": {client.ID}, "client_secret": {client.Secret.String()}, "redirect_uri": {auth.RedirectURI}})
			for key, value := range params {
				values[key] = value
			}
			r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil), full)
			policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, old.ID.String())
			w := httptest.NewRecorder()
			response, _, err := HandleAuthorizationRequest(ctx, tx, w, r)
			require.Nil(t, err)
			require.IsType(t, oidcerrors.InternalRedirectError{}, response)
			var continuation *http.Cookie
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == AUTHORIZATION_COOKIE_NAME {
					continuation = cookie
				}
			}
			require.NotNil(t, continuation)
			resume := func(session *models.Session, method string) *http.Request {
				r := WithAuthenticationPolicy(httptest.NewRequest(method, "/authorize", strings.NewReader("action=approved")), full)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.AddCookie(continuation)
				policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
				return r
			}
			response, _, err = HandleAuthorizationRequest(ctx, tx, httptest.NewRecorder(), resume(old, http.MethodGet))
			require.Nil(t, err)
			require.IsType(t, oidcerrors.InternalRedirectError{}, response, "old evidence must not complete forced reauthentication")
			_, err = HandleAuthorizationDecision(ctx, tx, resume(old, http.MethodPost))
			require.IsType(t, oidcerrors.OIDCErrorResponse{}, err)
			require.Equal(t, oidcerrors.LOGIN_REQUIRED, err.(oidcerrors.OIDCErrorResponse).ErrorCode)
			fresh := newSession(t, tx, &full, time.Now().UTC())
			response, consent, err := HandleAuthorizationRequest(ctx, tx, httptest.NewRecorder(), resume(fresh, http.MethodGet))
			require.Nil(t, err)
			_, redirected := response.(oidcerrors.InternalRedirectError)
			require.False(t, redirected, "successful fresh login must not loop back to login")
			require.True(t, response != nil || consent != nil)
		})
	}
}
