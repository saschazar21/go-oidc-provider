package helpers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

type loginTestStrategy struct {
	id           string
	methods      []utils.AMR
	authenticate func(context.Context, bun.IDB, string, string) (*LoginIdentity, error)
}

func (s loginTestStrategy) ID() string                   { return s.id }
func (s loginTestStrategy) RequiredMethods() []utils.AMR { return s.methods }
func (s loginTestStrategy) Authenticate(ctx context.Context, db bun.IDB, email, password string) (*LoginIdentity, error) {
	return s.authenticate(ctx, db, email, password)
}

func allowLoginTest(context.Context, string) error { return nil }

func TestLoginConfiguration(t *testing.T) {
	// Constructor validation never queries this placeholder database.
	placeholder := new(bun.DB)
	base := LoginConfig{
		DB: placeholder, Limiter: LoginLimiterFunc(allowLoginTest),
		Sender:       EmailCodeSenderFunc(func(context.Context, string, string) error { return nil }),
		ChallengeKey: []byte(strings.Repeat("k", 32)),
	}
	for _, mutate := range []func(*LoginConfig){
		func(c *LoginConfig) { c.DB = nil },
		func(c *LoginConfig) { c.Limiter = nil },
		func(c *LoginConfig) { c.Limiter = LoginLimiterFunc(nil) },
		func(c *LoginConfig) { c.Sender = nil },
		func(c *LoginConfig) { c.Sender = EmailCodeSenderFunc(nil) },
		func(c *LoginConfig) { c.ChallengeKey = c.ChallengeKey[:31] },
		func(c *LoginConfig) { c.Strategy = loginTestStrategy{id: "bad"} },
		func(c *LoginConfig) { c.Strategy = loginTestStrategy{methods: []utils.AMR{utils.AMR_FIDO}} },
		func(c *LoginConfig) { c.Strategy = loginTestStrategy{id: "bad", methods: []utils.AMR{"invented"}} },
		func(c *LoginConfig) {
			c.Strategy = loginTestStrategy{id: "bad", methods: []utils.AMR{utils.AMR_FIDO, utils.AMR_FIDO}}
		},
	} {
		config := base
		mutate(&config)
		_, err := NewLoginService(config)
		require.Error(t, err)
	}
	service, err := NewLoginService(base)
	require.NoError(t, err)
	require.Equal(t, []utils.AMR{utils.AMR_EMAIL}, service.RequiredMethods())
	require.False(t, service.UsesPassword())
	service.RequiredMethods()[0] = utils.AMR_PASSWORD
	require.Equal(t, []utils.AMR{utils.AMR_EMAIL}, service.RequiredMethods())
	base.ChallengeKey[0] = 'x'
	require.NotEqual(t, base.ChallengeKey, service.key)
	password, err := NewLoginService(LoginConfig{DB: placeholder, Limiter: LoginLimiterFunc(allowLoginTest), Strategy: PasswordStrategy()})
	require.NoError(t, err)
	require.True(t, password.UsesPassword())
	require.Equal(t, []utils.AMR{utils.AMR_PASSWORD}, password.RequiredMethods())
}

func TestLoginContinuationAndDigest(t *testing.T) {
	for _, path := range []string{"", "/", "/authorize", "/authorize?state=hello%20world", "/profile#settings"} {
		_, safe := safeLoginContinuation(path)
		require.True(t, safe, path)
	}
	for _, path := range []string{"https://evil.example", "//evil.example", "/\\evil", "/%2fevil", "/%252fevil", "/%5cevil", "/%0aevil", "/\x00", "relative", "/%zz"} {
		_, safe := safeLoginContinuation(path)
		require.False(t, safe, path)
	}
	require.False(t, validLoginBinding(""))
	require.True(t, validLoginBinding(strings.Repeat("b", 32)))
	s := &LoginService{key: []byte(strings.Repeat("k", 32))}
	id := uuid.New()
	a := &loginAttempt{ID: uuid.New(), ChallengeID: &id, Flow: "flow"}
	digest := s.codeDigest(a, "012345")
	require.Len(t, digest, 32)
	require.NotEqual(t, digest, s.codeDigest(a, "012346"))
	b := *a
	b.ID = uuid.New()
	require.NotEqual(t, digest, s.codeDigest(&b, "012345"))
	b = *a
	other := uuid.New()
	b.ChallengeID = &other
	require.NotEqual(t, digest, s.codeDigest(&b, "012345"))
	b = *a
	b.Flow = "other"
	require.NotEqual(t, digest, s.codeDigest(&b, "012345"))
}

func TestLoginLimiterBeforeDatabase(t *testing.T) {
	var calls []string
	s, err := NewLoginService(LoginConfig{
		DB: new(bun.DB), Strategy: loginTestStrategy{id: "fido", methods: []utils.AMR{utils.AMR_FIDO}},
		Limiter: LoginLimiterFunc(func(_ context.Context, key string) error {
			calls = append(calls, key)
			return errors.New("limited")
		}),
	})
	require.NoError(t, err)
	_, err = s.Start(context.Background(), LoginInput{Email: "secret@example.com", RemoteIP: "127.0.0.1"})
	require.ErrorIs(t, err, ErrLoginRejected)
	_, err = s.VerifyCode(context.Background(), CodeInput{})
	require.ErrorIs(t, err, ErrLoginRejected)
	_, err = s.Resend(context.Background(), CodeInput{})
	require.ErrorIs(t, err, ErrLoginRejected)
	require.Len(t, calls, 3)
	for _, key := range calls {
		require.NotContains(t, key, "secret")
		require.NotContains(t, key, "127.0.0.1")
	}
}
