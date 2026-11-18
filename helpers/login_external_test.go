package helpers_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

// This package cannot set LoginIdentity.credentialHash. It exercises only the
// documented contract available to an application's custom password strategy.
type externalPasswordStrategy struct {
	user       *models.User
	afterProof func(context.Context, int64) error
}

func (externalPasswordStrategy) ID() string { return "external-password-v1" }
func (externalPasswordStrategy) RequiredMethods() []utils.AMR {
	return []utils.AMR{utils.AMR_PASSWORD}
}
func (s externalPasswordStrategy) Authenticate(ctx context.Context, conn bun.IDB, _ string, password string) (*helpers.LoginIdentity, error) {
	credential, err := models.GetPasswordCredential(ctx, conn, s.user.ID)
	if err != nil {
		return nil, err
	}
	matched, err := utils.VerifyPasswordContext(ctx, credential.PasswordHash, password)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, helpers.ErrLoginRejected
	}
	if s.afterProof != nil {
		if err := s.afterProof(ctx, credential.Version); err != nil {
			return nil, err
		}
	}
	return &helpers.LoginIdentity{
		User: s.user, Methods: []utils.AMR{utils.AMR_PASSWORD}, CredentialVersion: credential.Version,
	}, nil
}

func TestExternalPasswordStrategyRejectsRemoveReenrollRace(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	t.Setenv("DEBUG", "0")

	for _, sameHash := range []bool{true, false} {
		for _, requireEmail := range []bool{false, true} {
			t.Run(fmt.Sprintf("same_hash=%t/email=%t", sameHash, requireEmail), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				var user models.User
				require.NoError(t, test.LoadFixture("user.json", &user))
				email := utils.EncryptedString(fmt.Sprintf("race-%t-%t@example.com", sameHash, requireEmail))
				user.Email = &email
				require.NoError(t, user.Save(ctx, conn))
				const password = "verified before removal"
				require.NoError(t, helpers.SetPassword(ctx, conn, user.ID, password))
				initial, err := models.GetPasswordCredential(ctx, conn, user.ID)
				require.NoError(t, err)
				require.Positive(t, initial.Version)

				verified := make(chan int64, 1)
				resume := make(chan struct{})
				strategy := externalPasswordStrategy{user: &user, afterProof: func(ctx context.Context, version int64) error {
					verified <- version
					select {
					case <-resume:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}}
				deliveries := 0
				config := helpers.LoginConfig{
					DB: conn, Strategy: strategy, RequireEmail: requireEmail,
					Limiter: helpers.LoginLimiterFunc(func(context.Context, string) error { return nil }),
					Sender: helpers.EmailCodeSenderFunc(func(context.Context, string, string) error {
						deliveries++
						return nil
					}),
					ChallengeKey: []byte(strings.Repeat("k", 32)),
				}
				service, err := helpers.NewLoginService(config)
				require.NoError(t, err)
				input := helpers.LoginInput{Email: string(email), Password: password, Binding: strings.Repeat("b", 32)}
				type outcome struct {
					result *helpers.LoginResult
					err    error
				}
				finished := make(chan outcome, 1)
				go func() {
					result, err := service.Start(ctx, input)
					finished <- outcome{result, err}
				}()
				select {
				case version := <-verified:
					require.Equal(t, initial.Version, version)
				case <-ctx.Done():
					t.Fatal("custom strategy did not reach the verification barrier")
				}
				// No attempt exists for RemovePassword to invalidate yet. The
				// first case starts with the fresh schema's initial generation;
				// even reusing its exact hash must not resurrect that evidence.
				count, err := conn.NewSelect().TableExpr("oidc_login_attempts").Where("user_id = ?", user.ID).Count(ctx)
				require.NoError(t, err)
				require.Zero(t, count)
				require.NoError(t, helpers.RemovePassword(ctx, conn, user.ID))
				if sameHash {
					require.NoError(t, conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
						return helpers.SetEncodedPasswordInTx(ctx, tx, user.ID, initial.PasswordHash)
					}))
				} else {
					require.NoError(t, helpers.SetPassword(ctx, conn, user.ID, "replacement password"))
				}
				current, err := models.GetPasswordCredential(ctx, conn, user.ID)
				require.NoError(t, err)
				require.Greater(t, current.Version, initial.Version)
				close(resume)
				select {
				case completed := <-finished:
					require.ErrorIs(t, completed.err, helpers.ErrLoginRejected)
					require.Nil(t, completed.result)
				case <-ctx.Done():
					t.Fatal("custom strategy login did not finish")
				}
				require.Zero(t, deliveries)
				for _, table := range []string{"oidc_login_attempts", "oidc_sessions"} {
					count, err := conn.NewSelect().TableExpr(table).Where("user_id = ?", user.ID).Count(ctx)
					require.NoError(t, err)
					require.Zero(t, count, table)
				}

				// A fresh custom proof succeeds without access to the private hash
				// field, ruling out rejection of all external password strategies.
				config.Strategy = externalPasswordStrategy{user: &user}
				service, err = helpers.NewLoginService(config)
				require.NoError(t, err)
				if !sameHash {
					input.Password = "replacement password"
				}
				result, err := service.Start(ctx, input)
				require.NoError(t, err)
				require.NotNil(t, result)
				if requireEmail {
					require.Nil(t, result.Session)
					require.Equal(t, 1, deliveries)
				} else {
					require.NotNil(t, result.Session)
				}
			})
		}
	}
}
