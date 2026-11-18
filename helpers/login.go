package helpers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type EmailCodeSender interface {
	SendLoginCode(context.Context, string, string) error
}
type EmailCodeSenderFunc func(context.Context, string, string) error

func (f EmailCodeSenderFunc) SendLoginCode(ctx context.Context, email, code string) error {
	return f(ctx, email, code)
}

// LoginLimiter must enforce deployment-wide IP/account/attempt budgets. Keys are
// namespaced, SHA-256 hashed identifiers, not plaintext emails or bindings. An
// error fails closed. All operations call it, including malformed requests.
type LoginLimiter interface {
	Allow(context.Context, string) error
}
type LoginLimiterFunc func(context.Context, string) error

func (f LoginLimiterFunc) Allow(ctx context.Context, key string) error { return f(ctx, key) }

type LoginConfig struct {
	DB           *bun.DB
	Strategy     LoginStrategy
	RequireEmail bool
	Sender       EmailCodeSender
	ChallengeKey []byte
	Limiter      LoginLimiter
	// Clock defaults to time.Now. Overrides must be concurrency-safe.
	Clock func() time.Time
}

type LoginInput struct{ Email, Password, Binding, Continuation, RemoteIP string }
type CodeInput struct {
	AttemptID               uuid.UUID
	Code, Binding, RemoteIP string
}
type LoginResult struct {
	AttemptID    uuid.UUID
	Session      *models.Session
	Continuation string
}

// LoginService has immutable per-provider policy. It never writes cookies;
// handlers must emit a session cookie only after a successful return.
type LoginService struct {
	db                                    *bun.DB
	strategy                              LoginStrategy
	sender                                EmailCodeSender
	limiter                               LoginLimiter
	key                                   []byte
	clock                                 func() time.Time
	methods, primaryMethods               []utils.AMR
	flow                                  string
	emailOnly, requireEmail, usesPassword bool
}

// loginAttempt deliberately has no Bun hooks. Only HMAC digests, never codes,
// enter SQL. Failure counters are a lifetime budget and NEVER reset on resend.
type loginAttempt struct {
	bun.BaseModel     `bun:"table:oidc_login_attempts,alias:login_attempt"`
	ID                uuid.UUID   `bun:"attempt_id,type:uuid,pk"`
	UserID            *uuid.UUID  `bun:"user_id,type:uuid"`
	Flow              string      `bun:"flow"`
	BindingHash       []byte      `bun:"binding_hash"`
	Methods           []utils.AMR `bun:"methods,array"`
	CredentialVersion int64       `bun:"credential_version"`
	ExpiresAt         time.Time   `bun:"expires_at"`
	CompletedAt       *time.Time  `bun:"completed_at"`
	ChallengeID       *uuid.UUID  `bun:"challenge_id,type:uuid"`
	CodeDigest        []byte      `bun:"code_digest"`
	CodeExpiresAt     *time.Time  `bun:"code_expires_at"`
	FailedAttempts    int         `bun:"failed_attempts"`
	LastSentAt        *time.Time  `bun:"last_sent_at"`
	Continuation      string      `bun:"continuation"`
	CreatedAt         time.Time   `bun:"created_at"`
}

func nilLoginDependency(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

func NewLoginService(config LoginConfig) (*LoginService, error) {
	if config.DB == nil || nilLoginDependency(config.Limiter) {
		return nil, errors.New("login requires a database and limiter")
	}
	strategy := config.Strategy
	if strategy == nil {
		strategy = EmailCodeStrategy()
	}
	if nilLoginDependency(strategy) {
		return nil, errors.New("nil login strategy")
	}
	_, emailOnly := strategy.(emailCodeLoginStrategy)
	methods := slices.Clone(strategy.RequiredMethods())
	if strings.TrimSpace(strategy.ID()) == "" || len(strategy.ID()) > 128 || !validLoginMethods(methods) {
		return nil, errors.New("login strategy requires a stable ID and nonempty valid methods")
	}
	requireEmail := config.RequireEmail || emailOnly
	primary := slices.Clone(methods)
	if emailOnly {
		primary = []utils.AMR{}
	}
	if requireEmail && !slices.Contains(methods, utils.AMR_EMAIL) {
		methods = append(methods, utils.AMR_EMAIL)
	}
	if requireEmail && (nilLoginDependency(config.Sender) || len(config.ChallengeKey) < 32) {
		return nil, errors.New("email login requires a sender and at least 32 challenge-key bytes")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	usesPassword := slices.Contains(methods, utils.AMR_PASSWORD)
	if usesPassword {
		if _, err := utils.DummyPasswordHash(); err != nil {
			return nil, err
		}
	}
	// Bind persisted attempts to the fixed provider policy, including all methods.
	fingerprint := sha256.Sum256(fmt.Appendf(nil, "%s|%t|%v", strategy.ID(), requireEmail, methods))
	return &LoginService{db: config.DB, strategy: strategy, sender: config.Sender,
		limiter: config.Limiter, key: slices.Clone(config.ChallengeKey), clock: config.Clock,
		methods: methods, primaryMethods: primary, flow: hex.EncodeToString(fingerprint[:]),
		emailOnly: emailOnly, requireEmail: requireEmail, usesPassword: usesPassword}, nil
}

func validLoginMethods(methods []utils.AMR) bool {
	if len(methods) == 0 {
		return false
	}
	seen := make(map[utils.AMR]bool)
	for _, method := range methods {
		switch method {
		case utils.AMR_PASSWORD, utils.AMR_OTP, utils.AMR_MULTIFACTOR, utils.AMR_SMS,
			utils.AMR_EMAIL, utils.AMR_PUSH, utils.AMR_FIDO, utils.AMR_BIOMETRIC:
		default:
			return false
		}
		if seen[method] {
			return false
		}
		seen[method] = true
	}
	return true
}

func (s *LoginService) RequiredMethods() []utils.AMR { return slices.Clone(s.methods) }
func (s *LoginService) UsesPassword() bool           { return s.usesPassword }

func (s *LoginService) limit(ctx context.Context, operation, ip, subject string) error {
	for _, item := range []struct{ kind, value string }{{"ip", ip}, {"subject", subject}} {
		digest := sha256.Sum256([]byte(item.value))
		if err := s.limiter.Allow(ctx, "login:"+operation+":"+item.kind+":"+hex.EncodeToString(digest[:])); err != nil {
			return ErrLoginRejected
		}
	}
	return ctx.Err()
}

func safeLoginContinuation(value string) (string, bool) {
	if value == "" {
		return "/", true
	}
	// Decode repeatedly so an intermediate redirect cannot expose an encoded
	// network-path reference, backslash, or control character.
	decoded := value
	for i := 0; i < 8; i++ {
		if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") ||
			strings.Contains(decoded, "\\") || strings.ContainsFunc(decoded, unicode.IsControl) {
			return "", false
		}
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "", false
		}
		if next == decoded {
			u, err := url.Parse(value)
			return value, err == nil && !u.IsAbs() && u.Host == "" && u.Opaque == ""
		}
		decoded = next
	}
	return "", false
}

func validLoginBinding(binding string) bool { return len(binding) >= 32 && len(binding) <= 1024 }

func (s *LoginService) Start(ctx context.Context, input LoginInput) (*LoginResult, error) {
	email := normalizeLoginEmail(input.Email)
	if err := s.limit(ctx, "start", input.RemoteIP, email); err != nil {
		return nil, err
	}
	continuation, safe := safeLoginContinuation(input.Continuation)
	if !safe || !validLoginBinding(input.Binding) || len(email) > 320 {
		return nil, ErrLoginRejected
	}
	identity, err := s.strategy.Authenticate(ctx, s.db, email, input.Password)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Methods == nil || !sameLoginMethods(identity.Methods, s.primaryMethods) ||
		(!s.emailOnly && identity.User == nil) || (s.usesPassword && identity.CredentialVersion <= 0) {
		return nil, ErrLoginRejected
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	binding := sha256.Sum256([]byte(input.Binding))
	attempt := &loginAttempt{ID: id, Flow: s.flow, BindingHash: binding[:], Methods: slices.Clone(identity.Methods),
		CredentialVersion: identity.CredentialVersion, ExpiresAt: now.Add(10 * time.Minute), Continuation: continuation, CreatedAt: now}
	if identity.User != nil {
		if identity.User.ID == uuid.Nil {
			return nil, ErrLoginRejected
		}
		uid := identity.User.ID
		attempt.UserID = &uid
	}
	var code, destination string
	result := &LoginResult{AttemptID: id, Continuation: continuation}
	err = s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		user, err := s.lockUser(ctx, tx, attempt)
		if err != nil {
			return err
		}
		if attempt.UserID != nil && !eligibleLoginUser(user) {
			return ErrLoginRejected
		}
		// Check the non-reusable generation before inserting an attempt: removal
		// cannot delete evidence still held by an in-flight custom strategy.
		if err := s.checkCredential(ctx, tx, attempt); err != nil {
			return err
		}
		if identity.credentialHash != "" {
			credential, err := models.GetPasswordCredential(ctx, tx, *attempt.UserID)
			if err != nil {
				return err
			}
			if !hmac.Equal([]byte(identity.credentialHash), []byte(credential.PasswordHash)) {
				return ErrLoginRejected
			}
		}
		if s.requireEmail {
			code, err = s.issueCode(attempt, now)
			if err != nil {
				return err
			}
			if user != nil && user.Email != nil {
				destination = string(*user.Email)
			}
		}
		if _, err := tx.NewInsert().Model(attempt).Exec(ctx); err != nil {
			return err
		}
		if !s.requireEmail {
			result.Session, err = s.finalize(ctx, tx, attempt, user, now)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.requireEmail {
		if err := s.deliver(ctx, attempt, destination, code); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func sameLoginMethods(a, b []utils.AMR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, method := range b {
		if !slices.Contains(a, method) {
			return false
		}
	}
	return len(a) == 0 || validLoginMethods(a)
}

func (s *LoginService) lockUser(ctx context.Context, tx bun.Tx, attempt *loginAttempt) (*models.User, error) {
	if attempt.UserID == nil {
		return nil, nil
	}
	var user models.User
	// Match password mutation's lock order: user FIRST, then attempt.
	err := tx.NewSelect().Model(&user).Where("user_id = ?", *attempt.UserID).For("UPDATE").Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLoginRejected
	}
	if err != nil {
		return nil, err
	}
	user.Hydrate()
	return &user, nil
}

func (s *LoginService) checkCredential(ctx context.Context, tx bun.Tx, attempt *loginAttempt) error {
	if !s.usesPassword && attempt.CredentialVersion == 0 {
		return nil
	}
	if attempt.UserID == nil {
		return ErrLoginRejected
	}
	credential, err := models.GetPasswordCredential(ctx, tx, *attempt.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLoginRejected
	}
	if err != nil {
		return err
	}
	if credential.Version != attempt.CredentialVersion {
		return ErrLoginRejected
	}
	return nil
}

func (s *LoginService) issueCode(attempt *loginAttempt, now time.Time) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	challenge, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	attempt.ChallengeID = &challenge
	expires := now.Add(5 * time.Minute)
	if expires.After(attempt.ExpiresAt) {
		expires = attempt.ExpiresAt
	}
	attempt.CodeExpiresAt, attempt.LastSentAt = &expires, &now
	attempt.CodeDigest = s.codeDigest(attempt, code)
	return code, nil
}

func (s *LoginService) codeDigest(attempt *loginAttempt, code string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("oidc-login-code-v1\x00"))
	mac.Write(attempt.ID[:])
	if attempt.ChallengeID != nil {
		mac.Write(attempt.ChallengeID[:])
	}
	mac.Write([]byte(attempt.Flow))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

func (s *LoginService) deliver(ctx context.Context, attempt *loginAttempt, email, code string) error {
	// Fake attempts have identical outward progress.
	if email == "" {
		return nil
	}
	if err := s.sender.SendLoginCode(ctx, email, code); err != nil {
		// Conditional invalidation cannot destroy a newer concurrently resent code.
		// Cleanup is independent of request cancellation, but bounded.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, invalidateErr := s.db.NewUpdate().Model((*loginAttempt)(nil)).
			Set("code_digest = NULL").Where("attempt_id = ? AND challenge_id = ? AND completed_at IS NULL", attempt.ID, attempt.ChallengeID).Exec(cleanup)
		if invalidateErr != nil {
			return errors.New("login code delivery and invalidation failed")
		}
		// Return pending even on failure: no account/delivery oracle, and the
		// caller retains its attempt ID for a rate-limited resend.
	}
	return nil
}

func (s *LoginService) VerifyCode(ctx context.Context, input CodeInput) (*LoginResult, error) {
	return s.codeOperation(ctx, input, false)
}

func (s *LoginService) Resend(ctx context.Context, input CodeInput) (*LoginResult, error) {
	return s.codeOperation(ctx, input, true)
}

func (s *LoginService) codeOperation(ctx context.Context, input CodeInput, resend bool) (*LoginResult, error) {
	operation := "verify"
	if resend {
		operation = "resend"
	}
	if err := s.limit(ctx, operation, input.RemoteIP, input.AttemptID.String()); err != nil {
		return nil, err
	}
	if !s.requireEmail || input.AttemptID == uuid.Nil || !validLoginBinding(input.Binding) {
		return nil, ErrLoginRejected
	}
	// Read identity without a lock, then acquire user before locking/reloading
	// attempt. Password changes may delete it while we wait: reload fails closed.
	var initial loginAttempt
	err := s.db.NewSelect().Model(&initial).Column("attempt_id", "user_id").Where("attempt_id = ?", input.AttemptID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLoginRejected
	}
	if err != nil {
		return nil, err
	}
	var attempt loginAttempt
	var result *LoginResult
	var code, destination string
	rejected := false
	err = s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		user, err := s.lockUser(ctx, tx, &initial)
		if err != nil {
			return err
		}
		err = tx.NewSelect().Model(&attempt).Where("attempt_id = ?", input.AttemptID).For("UPDATE").Scan(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			rejected = true
			return nil
		}
		if err != nil {
			return err
		}
		now := s.clock().UTC()
		binding := sha256.Sum256([]byte(input.Binding))
		if !sameLoginUserID(initial.UserID, attempt.UserID) || attempt.Flow != s.flow || attempt.CompletedAt != nil ||
			!now.Before(attempt.ExpiresAt) || attempt.FailedAttempts >= 5 ||
			subtle.ConstantTimeCompare(binding[:], attempt.BindingHash) != 1 ||
			!sameLoginMethods(attempt.Methods, s.primaryMethods) {
			rejected = true
			return nil
		}
		if attempt.UserID != nil && !eligibleLoginUser(user) {
			rejected = true
			return nil
		}
		if err := s.checkCredential(ctx, tx, &attempt); err != nil {
			if errors.Is(err, ErrLoginRejected) {
				rejected = true
				return nil
			}
			return err
		}
		result = &LoginResult{AttemptID: attempt.ID, Continuation: attempt.Continuation}
		if resend {
			if attempt.LastSentAt == nil || now.Before(attempt.LastSentAt.Add(30*time.Second)) {
				rejected = true
				return nil
			}
			code, err = s.issueCode(&attempt, now)
			if err != nil {
				return err
			}
			if user != nil && user.Email != nil {
				destination = string(*user.Email)
			}
			_, err = tx.NewUpdate().Model(&attempt).Column("challenge_id", "code_digest", "code_expires_at", "last_sent_at").WherePK().Exec(ctx)
			return err
		}
		validCode := len(input.Code) == 6
		candidate := ""
		if validCode {
			for _, c := range input.Code {
				validCode = validCode && c >= '0' && c <= '9'
			}
			if validCode {
				candidate = input.Code
			}
		}
		matched := hmac.Equal(attempt.CodeDigest, s.codeDigest(&attempt, candidate))
		if !validCode || !matched || attempt.ChallengeID == nil || attempt.CodeExpiresAt == nil ||
			!now.Before(*attempt.CodeExpiresAt) || user == nil {
			rejected = true
			// Expected rejection is NOT returned from the transaction callback:
			// otherwise PostgreSQL would roll back the attempt counter.
			_, err = tx.NewUpdate().Model(&attempt).Set("failed_attempts = failed_attempts + 1").WherePK().Exec(ctx)
			return err
		}
		attempt.Methods = append(slices.Clone(attempt.Methods), utils.AMR_EMAIL)
		if slices.Contains(s.primaryMethods, utils.AMR_EMAIL) {
			attempt.Methods = slices.Clone(s.methods)
		}
		result.Session, err = s.finalize(ctx, tx, &attempt, user, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	if rejected {
		return nil, ErrLoginRejected
	}
	if resend {
		if err := s.deliver(ctx, &attempt, destination, code); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func sameLoginUserID(a, b *uuid.UUID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (s *LoginService) finalize(ctx context.Context, tx bun.Tx, attempt *loginAttempt, user *models.User, now time.Time) (*models.Session, error) {
	if !eligibleLoginUser(user) || !sameLoginMethods(attempt.Methods, s.methods) {
		return nil, ErrLoginRejected
	}
	if err := s.checkCredential(ctx, tx, attempt); err != nil {
		return nil, err
	}
	methods := slices.Clone(attempt.Methods)
	active := true
	session := &models.Session{UserID: user.ID, User: user, AMR: &methods, AuthTime: now, IsActive: &active}
	// No cookie side effects; insertion and completion commit together.
	if _, err := tx.NewInsert().Model(session).Returning("*").Exec(ctx); err != nil {
		return nil, err
	}
	if _, err := tx.NewUpdate().TableExpr("oidc_users").Set("last_login_at = ?", now).Where("user_id = ?", user.ID).Exec(ctx); err != nil {
		return nil, err
	}
	attempt.CompletedAt, attempt.CodeDigest = &now, nil
	if _, err := tx.NewUpdate().Model(attempt).Column("completed_at", "code_digest", "methods").WherePK().Exec(ctx); err != nil {
		return nil, err
	}
	user.LastLoginAt = &now
	return session, nil
}
