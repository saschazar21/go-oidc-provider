package helpers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	oidcerrors "github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

type issuanceReadBarrierKey struct{}

type issuanceReadBarrier struct {
	table   string
	read    chan struct{}
	release chan struct{}
	once    sync.Once
}

// Test-only hook: stop after the first evidence SELECT has completed, but
// before the helper can acquire the user lock or accept the loaded evidence.
// No sleeps or production test seams determine the interleaving.
type issuanceReadBarrierHook struct{}

func (issuanceReadBarrierHook) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (issuanceReadBarrierHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	barrier, _ := ctx.Value(issuanceReadBarrierKey{}).(*issuanceReadBarrier)
	if barrier == nil || event.Err != nil || event.Operation() != "SELECT" || !strings.Contains(event.Query, barrier.table) {
		return
	}
	barrier.once.Do(func() {
		close(barrier.read)
		select {
		case <-barrier.release:
		case <-ctx.Done():
		}
	})
}

type issuanceRaceResult struct {
	issued bool
	err    oidcerrors.OIDCError
}

// Each operation invokes the full public helper, not a bespoke test issuance
// path. Session and token fixtures are committed, so the legacy pooled hooks
// would run normally and the pre-fix stale-evidence race is reproducible.
func issuanceRaceOperation(t *testing.T, conn *bun.DB, user *models.User, client *models.Client, path string, configured bool) (func(context.Context, bun.IDB) issuanceRaceResult, string) {
	t.Helper()
	ctx := context.Background()
	methods := []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}
	var auth models.Authorization
	require.NoError(t, test.LoadFixture("authorization_approved.json", &auth))
	auth.ClientID, auth.Client, auth.UserID, auth.User = client.ID, client, user.ID, user
	auth.Scope = append(auth.Scope, utils.OFFLINE_ACCESS)
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	auth.AuthTime, auth.AMR = &at, &methods
	require.Nil(t, auth.Save(ctx, conn))
	var r *http.Request
	var tr *tokenRequest
	if path == "refresh" || path == "code" {
		kind, grant := utils.REFRESH_TOKEN_TYPE, utils.REFRESH_TOKEN
		if path == "code" {
			kind, grant = utils.AUTHORIZATION_CODE_TYPE, utils.AUTHORIZATION_CODE
		}
		token, err := models.CreateToken(ctx, conn, string(kind), &auth)
		require.Nil(t, err)
		params := url.Values{"grant_type": {string(grant)}, "client_id": {client.ID}, "client_secret": {client.Secret.String()}, "redirect_uri": {auth.RedirectURI}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
		if path == "code" {
			params.Set("code", token.Value.String())
		} else {
			params.Set("refresh_token", token.Value.String())
		}
		r = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(params.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		session := &models.Session{UserID: user.ID, User: user, AMR: &methods, AuthTime: at}
		require.Nil(t, session.Save(ctx, conn))
		if path == "consent" {
			_, err := conn.NewUpdate().Model(&auth).WherePK().Set("is_active = FALSE").Set("status = 'pending'").
				Set("user_id = NULL").Set("auth_time = NULL").Set("amr = NULL").Exec(ctx)
			require.NoError(t, err)
			r = httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader("action=approved"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			policyTestCookie(t, r, AUTHORIZATION_COOKIE_NAME, AUTHORIZATION_COOKIE_ID, auth.ID.String())
		} else {
			params := createParams(url.Values{"client_id": {client.ID}, "client_secret": {client.Secret.String()}, "redirect_uri": {auth.RedirectURI}})
			r = httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
		}
		policyTestCookie(t, r, SESSION_COOKIE_NAME, SESSION_COOKIE_ID, session.ID.String())
	}
	if configured {
		r = WithAuthenticationPolicy(r, methods)
	}
	if path == "refresh" || path == "code" {
		var err oidcerrors.OIDCError
		tr, err = ParseTokenRequest(r)
		require.Nil(t, err)
		return func(ctx context.Context, db bun.IDB) issuanceRaceResult {
			tokens, err := tr.HandleRequest(ctx, db)
			return issuanceRaceResult{len(tokens) > 0, err}
		}, `FROM "oidc_tokens" AS "token"`
	}
	return func(ctx context.Context, db bun.IDB) issuanceRaceResult {
		request := r.WithContext(authenticationPolicyContext(ctx, r))
		if path == "consent" {
			response, err := HandleAuthorizationDecision(ctx, db, request)
			_, issued := response.(*authorizationResponse)
			return issuanceRaceResult{issued, err}
		}
		response, _, err := HandleAuthorizationRequest(ctx, db, httptest.NewRecorder(), request)
		_, issued := response.(*authorizationResponse)
		return issuanceRaceResult{issued, err}
	}, `FROM "oidc_sessions" AS "session"`
}

func requireNoLiveIssuanceEvidence(t *testing.T, ctx context.Context, conn *bun.DB) {
	t.Helper()
	for _, query := range []string{
		"SELECT count(*) FROM oidc_tokens WHERE is_active = TRUE",
		"SELECT count(*) FROM oidc_authorizations WHERE is_active = TRUE OR status = 'approved'",
		"SELECT count(*) FROM oidc_sessions WHERE is_active = TRUE",
	} {
		var count int
		require.NoError(t, conn.NewRaw(query).Scan(ctx, &count))
		require.Zero(t, count, query)
	}
}

func TestIssuanceSerializesPasswordRevocation(t *testing.T) {
	t.Setenv(utils.COOKIE_AUTH_KEY_ENV, "o54wWmZD1feHQAoYFp59fecpWaQ83+It2/Ko3fiyrzo=")
	t.Setenv(utils.ISSUER_URL_ENV, "https://issuer.example.com")
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	conn.AddQueryHook(issuanceReadBarrierHook{})
	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.Nil(t, user.Save(ctx, conn))
	var client models.Client
	require.NoError(t, test.LoadFixture("client_minimal.json", &client))
	client.OwnerID = user.ID
	confidential := true
	client.IsConfidential = &confidential
	grants := []utils.GrantType{utils.AUTHORIZATION_CODE, utils.REFRESH_TOKEN}
	client.GrantTypes = &grants
	require.Nil(t, client.Save(ctx, conn))
	encoded, err := utils.HashPassword("replacement password")
	require.NoError(t, err)
	setup := func(t *testing.T) context.Context {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(cancel)
		for _, table := range []string{"oidc_tokens", "oidc_authorizations", "oidc_sessions"} {
			_, err := conn.NewDelete().Table(table).Where("1 = 1").Exec(ctx)
			require.NoError(t, err)
		}
		require.NoError(t, conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			return SetEncodedPasswordInTx(ctx, tx, user.ID, encoded)
		}))
		return ctx
	}

	for _, path := range []string{"refresh", "code", "consent", "reuse"} {
		for _, configured := range []bool{false, true} {
			policyName := "legacy"
			if configured {
				policyName = "configured"
			}
			for _, mutation := range []string{"replace", "remove"} {
				t.Run(path+"/"+policyName+"/password "+mutation+" wins", func(t *testing.T) {
					ctx := setup(t)
					issue, table := issuanceRaceOperation(t, conn, &user, &client, path, configured)
					barrier := &issuanceReadBarrier{table: table, read: make(chan struct{}), release: make(chan struct{})}
					var release sync.Once
					defer release.Do(func() { close(barrier.release) })
					// Exercise DB, Conn and *Conn auto-transaction boundaries.
					var handle bun.IDB = conn
					if configured {
						dedicated, err := conn.Conn(ctx)
						require.NoError(t, err)
						defer dedicated.Close()
						handle = dedicated
						if mutation == "remove" {
							handle = &dedicated
						}
					}
					done := make(chan issuanceRaceResult, 1)
					go func() { done <- issue(context.WithValue(ctx, issuanceReadBarrierKey{}, barrier), handle) }()
					select {
					case <-barrier.read:
					case result := <-done:
						t.Fatalf("issuance returned before reading evidence: %+v", result)
					case <-ctx.Done():
						t.Fatal("issuance did not reach preliminary evidence read")
					}
					if mutation == "remove" {
						require.NoError(t, RemovePassword(ctx, conn, user.ID))
					} else {
						require.NoError(t, conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
							return SetEncodedPasswordInTx(ctx, tx, user.ID, encoded)
						}))
					}
					release.Do(func() { close(barrier.release) })
					select {
					case result := <-done:
						require.False(t, result.issued, "revoked evidence minted credentials")
						if path == "refresh" || path == "code" {
							require.IsType(t, oidcerrors.JSONError{}, result.err)
							require.Equal(t, oidcerrors.INVALID_GRANT, result.err.(oidcerrors.JSONError).ErrorCode)
						} else if path == "consent" {
							require.NotNil(t, result.err)
						} else {
							require.Nil(t, result.err) // successful redirect to login, not approval
						}
					case <-ctx.Done():
						t.Fatal("issuance did not finish after password mutation")
					}
					requireNoLiveIssuanceEvidence(t, ctx, conn)
					var used int
					require.NoError(t, conn.NewRaw("SELECT count(*) FROM oidc_tokens WHERE last_used_at IS NOT NULL OR consumed_at IS NOT NULL").Scan(ctx, &used))
					require.Zero(t, used, "preliminary/rejected reads must not mutate token usage")
				})
			}
		}

		for _, rollback := range []bool{false, true} {
			ending := "commit"
			if rollback {
				ending = "rollback"
			}
			t.Run(path+"/caller transaction holds lock through "+ending, func(t *testing.T) {
				ctx := setup(t)
				issue, _ := issuanceRaceOperation(t, conn, &user, &client, path, true)
				tx, err := conn.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer tx.Rollback()
				var handle bun.IDB = tx
				if rollback {
					handle = &tx
				}
				result := issue(ctx, handle)
				require.Nil(t, result.err)
				require.True(t, result.issued)
				var issuancePID int
				require.NoError(t, tx.NewRaw("SELECT pg_backend_pid()").Scan(ctx, &issuancePID))
				mutationTx, err := conn.BeginTx(ctx, &sql.TxOptions{})
				require.NoError(t, err)
				defer mutationTx.Rollback()
				var mutationPID int
				require.NoError(t, mutationTx.NewRaw("SELECT pg_backend_pid()").Scan(ctx, &mutationPID))
				done := make(chan error, 1)
				go func() { done <- SetEncodedPasswordInTx(ctx, mutationTx, user.ID, encoded) }()
				// Observe a real PostgreSQL lock wait, not merely a goroutine
				// that has not yet been scheduled. The issuer owns the user lock
				// even though the public issuance helper has already returned.
				require.Eventually(t, func() bool {
					var blocked bool
					err := conn.NewRaw("SELECT ? = ANY(pg_blocking_pids(?))", issuancePID, mutationPID).Scan(ctx, &blocked)
					return err == nil && blocked
				}, 5*time.Second, time.Millisecond)
				if rollback {
					require.NoError(t, tx.Rollback())
				} else {
					require.NoError(t, tx.Commit())
				}
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("password mutation did not resume after caller transaction ended")
				}
				require.NoError(t, mutationTx.Commit())
				requireNoLiveIssuanceEvidence(t, ctx, conn)
			})
		}
	}
}
