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
	oidcerrors "github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

func TestAuthenticationMethodsSatisfied(t *testing.T) {
	empty := []utils.AMR{}
	email := []utils.AMR{utils.AMR_EMAIL}
	password := []utils.AMR{utils.AMR_PASSWORD}
	combined := []utils.AMR{utils.AMR_EMAIL, utils.AMR_PASSWORD, utils.AMR_OTP}
	for _, tt := range []struct {
		name       string
		configured bool
		required   []utils.AMR
		evidence   *[]utils.AMR
		want       bool
	}{
		{name: "legacy unknown evidence", want: true},
		{name: "legacy empty evidence", evidence: &empty, want: true},
		{name: "configured nil policy fails closed", configured: true, evidence: &combined},
		{name: "configured empty policy fails closed", configured: true, required: empty, evidence: &combined},
		{name: "empty method fails closed", configured: true, required: []utils.AMR{""}, evidence: &combined},
		{name: "unknown evidence", configured: true, required: password},
		{name: "empty evidence", configured: true, required: password, evidence: &empty},
		{name: "email is not password", configured: true, required: password, evidence: &email},
		{name: "password evidence", configured: true, required: password, evidence: &password, want: true},
		{name: "one factor insufficient", configured: true, required: []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}, evidence: &password},
		{name: "all methods independent of order", configured: true, required: []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}, evidence: &combined, want: true},
		{name: "duplicate requirement is membership", configured: true, required: []utils.AMR{utils.AMR_PASSWORD, utils.AMR_PASSWORD}, evidence: &password, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.configured {
				r = WithAuthenticationPolicy(r, tt.required)
			}
			require.Equal(t, tt.want, AuthenticationMethodsSatisfied(r.Context(), tt.evidence))
		})
	}
}

func TestWithAuthenticationPolicyCopiesMethods(t *testing.T) {
	methods := []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}
	original := httptest.NewRequest(http.MethodGet, "/", nil)
	configured := WithAuthenticationPolicy(original, methods)
	methods[0] = utils.AMR_EMAIL
	emailOnly := []utils.AMR{utils.AMR_EMAIL}
	require.False(t, AuthenticationMethodsSatisfied(configured.Context(), &emailOnly))
	require.True(t, AuthenticationMethodsSatisfied(original.Context(), nil), "original request must remain unconfigured")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	merged := authenticationPolicyContext(ctx, configured)
	require.ErrorIs(t, merged.Err(), context.Canceled)
	require.False(t, AuthenticationMethodsSatisfied(merged, &emailOnly))

	other := WithAuthenticationPolicy(original, emailOnly)
	require.True(t, AuthenticationMethodsSatisfied(other.Context(), &emailOnly))
	require.False(t, AuthenticationMethodsSatisfied(configured.Context(), &emailOnly), "provider instances must remain isolated")
}

func TestCopyAuthenticationMethods(t *testing.T) {
	require.Nil(t, copyAuthenticationMethods(nil))
	methods := []utils.AMR{utils.AMR_PASSWORD}
	copied := copyAuthenticationMethods(&methods)
	methods[0] = utils.AMR_EMAIL
	require.Equal(t, []utils.AMR{utils.AMR_PASSWORD}, *copied)
}

func TestParseTokenRequestRetainsAuthenticationPolicy(t *testing.T) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh"}, "client_id": {"client"}}
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = WithAuthenticationPolicy(r, []utils.AMR{utils.AMR_PASSWORD})
	tr, err := ParseTokenRequest(r)
	require.Nil(t, err)
	require.NotNil(t, tr.policy)
	require.Equal(t, []utils.AMR{utils.AMR_PASSWORD}, tr.policy.methods)
}

func TestAuthorizationRequestCannotSupplyAMR(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/authorize?client_id=client&amr=pwd&amr=email", nil)
	ar, err := parseAuthorizationRequest(httptest.NewRecorder(), r)
	require.NotNil(t, err, "request-supplied AMR must be rejected, never trusted")
	require.Nil(t, ar)
}

func TestAuthorizationForcedLoginClearsPriorApproval(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "configured"}[configured], func(t *testing.T) {
			prompt, approved := utils.LOGIN, utils.APPROVED
			methods := []utils.AMR{utils.AMR_PASSWORD}
			at := time.Now().Add(-time.Hour)
			auth := &models.Authorization{
				UserID: uuid.New(), User: &models.User{}, Prompt: &prompt,
				Status: &approved, IsActive: true, AuthTime: &at, AMR: &methods,
			}
			r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
			if configured {
				r = WithAuthenticationPolicy(r, methods)
			}
			ar := &authorizationRequest{r: r, w: httptest.NewRecorder(), authorization: auth}
			err := ar.HandleAuthorizationRequest(context.Background(), nil)
			require.IsType(t, oidcerrors.InternalRedirectError{}, err)
			require.False(t, auth.IsApproved())
			require.Nil(t, auth.User)
			require.Equal(t, uuid.Nil, auth.UserID)
			require.Nil(t, auth.AuthTime)
			require.Nil(t, auth.AMR)
			if configured {
				require.NotNil(t, ar.reauthenticateAfter)
			} else {
				require.Nil(t, ar.reauthenticateAfter)
			}
		})
	}
}

func TestConsentPolicyFailureDoesNotMutateAuthorization(t *testing.T) {
	methods := []utils.AMR{utils.AMR_EMAIL}
	auth := &models.Authorization{UserID: uuid.New()}
	before := *auth
	approved := utils.APPROVED
	decision := authorizationDecision{
		Action: &approved, auth: auth,
		session: &models.Session{UserID: uuid.New(), AMR: &methods},
	}
	r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/decision", nil), []utils.AMR{utils.AMR_PASSWORD})
	err := decision.updateAuthorization(r.Context(), nil)
	require.IsType(t, oidcerrors.OIDCErrorResponse{}, err)
	require.Equal(t, oidcerrors.LOGIN_REQUIRED, err.(oidcerrors.OIDCErrorResponse).ErrorCode)
	require.Equal(t, before, *auth)
}

func TestAuthorizationReauthenticationCookieBinding(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	id := uuid.New()
	after := time.Now().UTC().Truncate(time.Microsecond)
	cookie, err := utils.NewCookieStore().New(r, AUTHORIZATION_COOKIE_NAME)
	require.NoError(t, err)
	cookie.Values[AUTHORIZATION_COOKIE_ID] = id.String()
	cookie.Values[authorizationReauthenticateAfter] = after.UnixMicro()
	w := httptest.NewRecorder()
	require.NoError(t, cookie.Save(r, w))
	r.AddCookie(w.Result().Cookies()[0])
	parsed := authorizationReauthenticationTime(r, id)
	require.NotNil(t, parsed)
	require.True(t, after.Equal(*parsed))
	require.Nil(t, authorizationReauthenticationTime(r, uuid.New()), "freshness must be bound to the authorization")
}

func TestTokenPolicyFiltersBeforeUsageHook(t *testing.T) {
	db := bun.NewDB(nil, pgdialect.New())
	query := func(ctx context.Context) string {
		selectQuery := models.NewTokenQuery(db, "code", string(utils.AUTHORIZATION_CODE_TYPE)).
			PopulateAuthorization(true, true, "Authorization", "authorization", "token").GetQuery()
		return filterTokenAuthenticationPolicy(ctx, selectQuery).String()
	}
	legacy := query(context.Background())
	require.NotContains(t, legacy, "ANY(")
	for _, methods := range [][]utils.AMR{nil, {}, {""}} {
		r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/token", nil), methods)
		require.Contains(t, query(r.Context()), "(FALSE)")
	}
	r := WithAuthenticationPolicy(httptest.NewRequest(http.MethodPost, "/token", nil), []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL})
	sql := query(r.Context())
	require.Contains(t, sql, `'pwd' = ANY("authorization"."amr"::text[])`)
	require.Contains(t, sql, `'email' = ANY("authorization"."amr"::text[])`)
}

