package helpers

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

// ErrLoginRejected deliberately does not distinguish absent users, bad passwords,
// expired challenges, locked accounts, invalid bindings, or exhausted attempts.
var ErrLoginRejected = errors.New("login could not be completed")

// LoginIdentity is trusted primary-authentication evidence, never a session.
// Password evidence MUST include the version read alongside the verified hash.
// This database-issued generation is non-reusable across replacement/removal;
// custom strategies must return it unchanged, never infer or increment it.
type LoginIdentity struct {
	User              *models.User
	Methods           []utils.AMR
	CredentialVersion int64
	// Built-in password proof is additionally bound to the exact hash until the
	// user lock is acquired. Custom strategies need only CredentialVersion.
	credentialHash string
}

// LoginStrategy implementations are trusted server-side plugins. ID must be
// stable and unique (change it when semantics change); RequiredMethods must be
// nonempty and immutable. Authenticate must not issue sessions or deliver codes.
// The coordinator reloads/locks the user and checks the declared evidence before
// finalizing. Plugins must support concurrent calls and honor cancellation.
type LoginStrategy interface {
	ID() string
	RequiredMethods() []utils.AMR
	Authenticate(context.Context, bun.IDB, string, string) (*LoginIdentity, error)
}

type emailCodeLoginStrategy struct{}

// EmailCodeStrategy preserves whitelist enrollment, but requires the coordinator
// to verify email possession before creating any authenticated session.
func EmailCodeStrategy() LoginStrategy { return emailCodeLoginStrategy{} }

func (emailCodeLoginStrategy) ID() string                   { return "email-code-v1" }
func (emailCodeLoginStrategy) RequiredMethods() []utils.AMR { return []utils.AMR{utils.AMR_EMAIL} }
func (emailCodeLoginStrategy) Authenticate(ctx context.Context, db bun.IDB, email, _ string) (*LoginIdentity, error) {
	email = normalizeLoginEmail(email)
	if !validateEmail(ctx, db, email) {
		// A nil user is allowed ONLY for this built-in, creating a fake attempt.
		return &LoginIdentity{Methods: []utils.AMR{}}, nil
	}
	user, err := lookupLoginUser(ctx, db, email)
	if err != nil {
		return nil, err
	}
	return &LoginIdentity{User: user, Methods: []utils.AMR{}}, nil
}

// PasswordVerifier receives (ctx, encodedHash, byte-exactPassword). Overrides
// must preserve the default verifier's bounded-cost and constant-time behavior.
type PasswordVerifier func(context.Context, string, string) (bool, error)

type passwordLoginStrategy struct{ verify PasswordVerifier }

func PasswordStrategy() LoginStrategy { return PasswordStrategyWithVerifier(nil) }

// PasswordStrategyWithVerifier supports controlled verifier injection. A nil
// verifier uses utils.VerifyPasswordContext, including its bounded KDF pool.
func PasswordStrategyWithVerifier(verify PasswordVerifier) LoginStrategy {
	if verify == nil {
		verify = utils.VerifyPasswordContext
	}
	return passwordLoginStrategy{verify: verify}
}

func (passwordLoginStrategy) ID() string                   { return "password-v1" }
func (passwordLoginStrategy) RequiredMethods() []utils.AMR { return []utils.AMR{utils.AMR_PASSWORD} }
func (p passwordLoginStrategy) Authenticate(ctx context.Context, db bun.IDB, email, password string) (*LoginIdentity, error) {
	dummy, err := utils.DummyPasswordHash()
	if err != nil {
		return nil, err
	}
	user, lookupErr := lookupLoginUser(ctx, db, normalizeLoginEmail(email))
	var credential *models.PasswordCredential
	if lookupErr == nil {
		credential, err = models.GetPasswordCredential(ctx, db, user.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	} else if !errors.Is(lookupErr, sql.ErrNoRows) {
		return nil, lookupErr
	}
	encoded := dummy
	if credential != nil {
		encoded = credential.PasswordHash
	}
	matched, verifyErr := p.verify(ctx, encoded, password)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if verifyErr != nil || !matched || credential == nil || !eligibleLoginUser(user) {
		return nil, ErrLoginRejected
	}
	return &LoginIdentity{User: user, Methods: []utils.AMR{utils.AMR_PASSWORD}, CredentialVersion: credential.Version, credentialHash: credential.PasswordHash}, nil
}

func normalizeLoginEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func lookupLoginUser(ctx context.Context, db bun.IDB, email string) (*models.User, error) {
	var user models.User
	err := db.NewSelect().Model(&user).Where("\"user\".email_hash = ?", utils.Hash([]byte(email))).Scan(ctx)
	if err != nil {
		return nil, err
	}
	user.Hydrate()
	return &user, nil
}

func eligibleLoginUser(user *models.User) bool {
	return user != nil && user.IsActive != nil && *user.IsActive && user.IsLocked != nil && !*user.IsLocked
}
