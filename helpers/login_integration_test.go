package helpers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

type loginTestDelivery struct{ email, code string }
type loginTestSender struct {
	mu         sync.Mutex
	deliveries []loginTestDelivery
	fail       bool
}

func (s *loginTestSender) SendLoginCode(_ context.Context, email, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, loginTestDelivery{email, code})
	if s.fail {
		return errors.New("delivery failed")
	}
	return nil
}

func (s *loginTestSender) last(t *testing.T) loginTestDelivery {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.deliveries)
	return s.deliveries[len(s.deliveries)-1]
}

// TestLoginPostgres uses a test-local copy of the agreed schema contract so it
// can run while the parent agent adds the production schema independently.
func TestLoginPostgres(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	t.Setenv("DEBUG", "0")
	_, err = conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS oidc_login_attempts (
		attempt_id UUID PRIMARY KEY, user_id UUID REFERENCES oidc_users(user_id) ON DELETE CASCADE,
		flow TEXT NOT NULL, binding_hash BYTEA NOT NULL, methods oidc_amr_type[],
		credential_version BIGINT NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL,
		completed_at TIMESTAMPTZ, challenge_id UUID, code_digest BYTEA,
		code_expires_at TIMESTAMPTZ, failed_attempts INT NOT NULL DEFAULT 0,
		last_sent_at TIMESTAMPTZ, continuation TEXT NOT NULL DEFAULT '/', created_at TIMESTAMPTZ DEFAULT now())`)
	require.NoError(t, err)
	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	require.NoError(t, SetPassword(ctx, conn, user.ID, " byte exact password "))
	email := string(*user.Email)
	binding := strings.Repeat("b", 32)
	now := time.Now().UTC()
	sender := &loginTestSender{}
	newService := func(strategy LoginStrategy, requireEmail bool) *LoginService {
		s, err := NewLoginService(LoginConfig{
			DB: conn, Strategy: strategy, RequireEmail: requireEmail,
			Limiter: LoginLimiterFunc(allowLoginTest), Sender: sender,
			ChallengeKey: []byte(strings.Repeat("k", 32)), Clock: func() time.Time { return now },
		})
		require.NoError(t, err)
		return s
	}
	input := LoginInput{Email: "  " + strings.ToUpper(email) + "  ", Password: " byte exact password ", Binding: binding, Continuation: "/authorize?state=safe"}
	codeInput := func(pending *LoginResult, code string) CodeInput {
		return CodeInput{AttemptID: pending.AttemptID, Binding: binding, Code: code}
	}
	assertSession := func(result *LoginResult, methods []utils.AMR) {
		require.NotNil(t, result.Session)
		require.Equal(t, user.ID, result.Session.UserID)
		require.ElementsMatch(t, methods, *result.Session.AMR)
		require.WithinDuration(t, now, result.Session.AuthTime, time.Microsecond)
		var attempt loginAttempt
		require.NoError(t, conn.NewSelect().Model(&attempt).Where("attempt_id = ?", result.AttemptID).Scan(ctx))
		require.NotNil(t, attempt.CompletedAt)
		require.Empty(t, attempt.CodeDigest)
		require.ElementsMatch(t, methods, attempt.Methods)
		var lastLogin time.Time
		require.NoError(t, conn.NewSelect().TableExpr("oidc_users").Column("last_login_at").Where("user_id = ?", user.ID).Scan(ctx, &lastLogin))
		require.WithinDuration(t, now, lastLogin, time.Microsecond)
	}
	t.Run("password only", func(t *testing.T) {
		s := newService(PasswordStrategy(), false)
		result, err := s.Start(ctx, input)
		require.NoError(t, err)
		assertSession(result, []utils.AMR{utils.AMR_PASSWORD})
		_, err = s.VerifyCode(ctx, codeInput(result, "000000"))
		require.ErrorIs(t, err, ErrLoginRejected)
		for _, in := range []LoginInput{
			{Email: email, Password: "byte exact password", Binding: binding},
			{Email: "unknown@example.com", Password: input.Password, Binding: binding},
		} {
			_, err := s.Start(ctx, in)
			require.ErrorIs(t, err, ErrLoginRejected)
		}
	})
	for _, flow := range []struct {
		name     string
		strategy LoginStrategy
		email    bool
		methods  []utils.AMR
	}{
		{"email only", EmailCodeStrategy(), false, []utils.AMR{utils.AMR_EMAIL}},
		{"password then email", PasswordStrategy(), true, []utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}},
	} {
		t.Run(flow.name, func(t *testing.T) {
			s := newService(flow.strategy, flow.email)
			pending, err := s.Start(ctx, input)
			require.NoError(t, err)
			require.Nil(t, pending.Session)
			delivery := sender.last(t)
			require.Equal(t, email, delivery.email)
			require.Len(t, delivery.code, 6)
			var stored loginAttempt
			require.NoError(t, conn.NewSelect().Model(&stored).Where("attempt_id = ?", pending.AttemptID).Scan(ctx))
			require.NotEqual(t, []byte(delivery.code), stored.CodeDigest)
			wrongBinding := codeInput(pending, delivery.code)
			wrongBinding.Binding = strings.Repeat("x", 32)
			_, err = s.VerifyCode(ctx, wrongBinding)
			require.ErrorIs(t, err, ErrLoginRejected)
			// Simultaneous valid completions must mint exactly one session.
			var wg sync.WaitGroup
			results := make(chan *LoginResult, 2)
			failures := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					result, err := s.VerifyCode(ctx, codeInput(pending, delivery.code))
					results <- result
					failures <- err
				}()
			}
			wg.Wait()
			close(results)
			close(failures)
			successes := 0
			for result := range results {
				if result != nil {
					successes++
					assertSession(result, flow.methods)
				}
			}
			require.Equal(t, 1, successes)
			for err := range failures {
				if err != nil {
					require.ErrorIs(t, err, ErrLoginRejected)
				}
			}
		})
	}
	t.Run("fake unknown email", func(t *testing.T) {
		s := newService(EmailCodeStrategy(), false)
		before := len(sender.deliveries)
		in := input
		in.Email = "unknown@example.com"
		pending, err := s.Start(ctx, in)
		require.NoError(t, err)
		require.Nil(t, pending.Session)
		require.Len(t, sender.deliveries, before)
		_, err = s.VerifyCode(ctx, codeInput(pending, "000000"))
		require.ErrorIs(t, err, ErrLoginRejected)
	})
	t.Run("whitelist enrollment is email-only and still requires proof", func(t *testing.T) {
		enrolledEmail := utils.EncryptedString("enrolled-login@example.com")
		whitelist := &models.MagicLinkWhitelist{Email: &enrolledEmail}
		require.NoError(t, whitelist.Save(ctx, conn))
		in := input
		in.Email = string(enrolledEmail)
		password := newService(PasswordStrategy(), true)
		_, err := password.Start(ctx, in)
		require.ErrorIs(t, err, ErrLoginRejected)
		_, err = lookupLoginUser(ctx, conn, in.Email)
		require.Error(t, err)
		s := newService(EmailCodeStrategy(), false)
		pending, err := s.Start(ctx, in)
		require.NoError(t, err)
		require.Nil(t, pending.Session)
		created, err := lookupLoginUser(ctx, conn, in.Email)
		require.NoError(t, err)
		count, err := conn.NewSelect().Model((*models.Session)(nil)).Where("user_id = ?", created.ID).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
		delivery := sender.last(t)
		require.Equal(t, in.Email, delivery.email)
		result, err := s.VerifyCode(ctx, codeInput(pending, delivery.code))
		require.NoError(t, err)
		require.Equal(t, created.ID, result.Session.UserID)
	})
	t.Run("parallel resends serialize and fixed flow rejects substitution", func(t *testing.T) {
		s := newService(PasswordStrategy(), true)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		weaker := newService(EmailCodeStrategy(), false)
		_, err = weaker.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		now = now.Add(31 * time.Second)
		before := len(sender.deliveries)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.Resend(ctx, codeInput(pending, ""))
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		successes := 0
		for err := range errs {
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, ErrLoginRejected)
			}
		}
		require.Equal(t, 1, successes)
		require.Len(t, sender.deliveries, before+1)
	})
	t.Run("resend rotates challenge and preserves failure budget", func(t *testing.T) {
		s := newService(PasswordStrategy(), true)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		var old loginAttempt
		require.NoError(t, conn.NewSelect().Model(&old).Where("attempt_id = ?", pending.AttemptID).Scan(ctx))
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.ErrorIs(t, err, ErrLoginRejected)
		_, err = s.VerifyCode(ctx, codeInput(pending, "bad"))
		require.ErrorIs(t, err, ErrLoginRejected)
		now = now.Add(31 * time.Second)
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.NoError(t, err)
		var current loginAttempt
		require.NoError(t, conn.NewSelect().Model(&current).Where("attempt_id = ?", pending.AttemptID).Scan(ctx))
		require.NotEqual(t, old.ChallengeID, current.ChallengeID)
		require.NotEqual(t, old.CodeDigest, current.CodeDigest)
		require.Equal(t, 1, current.FailedAttempts)
		// Concurrent failures serialize increments rather than losing updates.
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.VerifyCode(ctx, codeInput(pending, "bad"))
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.ErrorIs(t, err, ErrLoginRejected)
		}
		require.NoError(t, conn.NewSelect().Model(&current).Where("attempt_id = ?", pending.AttemptID).Scan(ctx))
		require.Equal(t, 5, current.FailedAttempts)
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		now = now.Add(31 * time.Second)
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.ErrorIs(t, err, ErrLoginRejected)
	})
	t.Run("delivery failure invalidates and permits later resend", func(t *testing.T) {
		s := newService(EmailCodeStrategy(), false)
		sender.fail = true
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		sender.fail = false
		now = now.Add(31 * time.Second)
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.NoError(t, err)
		result, err := s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.NoError(t, err)
		assertSession(result, []utils.AMR{utils.AMR_EMAIL})
	})
	t.Run("credential removal invalidates pending attempts", func(t *testing.T) {
		s := newService(PasswordStrategy(), true)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		code := sender.last(t).code
		require.NoError(t, RemovePassword(ctx, conn, user.ID))
		require.NoError(t, SetPassword(ctx, conn, user.ID, input.Password))
		_, err = s.VerifyCode(ctx, codeInput(pending, code))
		require.ErrorIs(t, err, ErrLoginRejected)
	})
	t.Run("credential version rechecked even without deletion", func(t *testing.T) {
		s := newService(PasswordStrategy(), true)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		credential, err := models.GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.NoError(t, models.SetPasswordCredential(ctx, conn, user.ID, credential.PasswordHash))
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
	})
	t.Run("remove and re-enroll during primary verification closes version ABA", func(t *testing.T) {
		require.NoError(t, RemovePassword(ctx, conn, user.ID))
		require.NoError(t, SetPassword(ctx, conn, user.ID, input.Password))
		strategy := PasswordStrategyWithVerifier(func(ctx context.Context, encoded, password string) (bool, error) {
			matched, err := utils.VerifyPasswordContext(ctx, encoded, password)
			if err != nil {
				return false, err
			}
			if err := RemovePassword(ctx, conn, user.ID); err != nil {
				return false, err
			}
			if err := SetPassword(ctx, conn, user.ID, "different password"); err != nil {
				return false, err
			}
			return matched, nil
		})
		s := newService(strategy, false)
		_, err := s.Start(ctx, input)
		require.ErrorIs(t, err, ErrLoginRejected)
		require.NoError(t, SetPassword(ctx, conn, user.ID, input.Password))
	})
	t.Run("session insert failure rolls back completion", func(t *testing.T) {
		s := newService(EmailCodeStrategy(), false)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		code := sender.last(t).code
		_, err = conn.ExecContext(ctx, `CREATE FUNCTION reject_login_session_fixture() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'injected session insert failure'; END; $$ LANGUAGE plpgsql`)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `CREATE TRIGGER reject_login_session_fixture BEFORE INSERT ON oidc_sessions
			FOR EACH ROW EXECUTE FUNCTION reject_login_session_fixture()`)
		require.NoError(t, err)
		_, err = s.VerifyCode(ctx, codeInput(pending, code))
		require.Error(t, err)
		var attempt loginAttempt
		require.NoError(t, conn.NewSelect().Model(&attempt).Where("attempt_id = ?", pending.AttemptID).Scan(ctx))
		require.Nil(t, attempt.CompletedAt)
		require.NotEmpty(t, attempt.CodeDigest)
		_, err = conn.ExecContext(ctx, `DROP TRIGGER reject_login_session_fixture ON oidc_sessions`)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `DROP FUNCTION reject_login_session_fixture()`)
		require.NoError(t, err)
		result, err := s.VerifyCode(ctx, codeInput(pending, code))
		require.NoError(t, err)
		assertSession(result, []utils.AMR{utils.AMR_EMAIL})
	})
	t.Run("account lock rechecked", func(t *testing.T) {
		s := newService(EmailCodeStrategy(), false)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		_, err = conn.NewUpdate().TableExpr("oidc_users").Set("is_locked = TRUE").Where("user_id = ?", user.ID).Exec(ctx)
		require.NoError(t, err)
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		_, err = conn.NewUpdate().TableExpr("oidc_users").Set("is_locked = FALSE").Where("user_id = ?", user.ID).Exec(ctx)
		require.NoError(t, err)
	})
	t.Run("challenge expiry and attempt expiry", func(t *testing.T) {
		s := newService(EmailCodeStrategy(), false)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		now = now.Add(5 * time.Minute)
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.NoError(t, err)
		now = now.Add(5 * time.Minute)
		_, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.ErrorIs(t, err, ErrLoginRejected)
		_, err = s.Resend(ctx, codeInput(pending, ""))
		require.ErrorIs(t, err, ErrLoginRejected)
	})
	t.Run("custom primary strategy and invalid evidence", func(t *testing.T) {
		strategy := loginTestStrategy{id: "custom-fido-v1", methods: []utils.AMR{utils.AMR_FIDO},
			authenticate: func(context.Context, bun.IDB, string, string) (*LoginIdentity, error) {
				return &LoginIdentity{User: &user, Methods: []utils.AMR{utils.AMR_FIDO}}, nil
			}}
		s := newService(strategy, false)
		result, err := s.Start(ctx, input)
		require.NoError(t, err)
		assertSession(result, []utils.AMR{utils.AMR_FIDO})
		s = newService(strategy, true)
		pending, err := s.Start(ctx, input)
		require.NoError(t, err)
		require.Nil(t, pending.Session)
		result, err = s.VerifyCode(ctx, codeInput(pending, sender.last(t).code))
		require.NoError(t, err)
		assertSession(result, []utils.AMR{utils.AMR_FIDO, utils.AMR_EMAIL})
		strategy.authenticate = func(context.Context, bun.IDB, string, string) (*LoginIdentity, error) {
			return &LoginIdentity{User: &user}, nil
		}
		s = newService(strategy, false)
		_, err = s.Start(ctx, input)
		require.ErrorIs(t, err, ErrLoginRejected)
	})
}
