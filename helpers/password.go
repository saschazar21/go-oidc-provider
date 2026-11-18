package helpers

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

// SetPassword hashes before opening the transaction. No password is ever
// supplied as SQL input; encoded hashes use native driver bindings in models.
func SetPassword(ctx context.Context, db *bun.DB, userID uuid.UUID, password string) error {
	encoded, err := utils.HashPasswordContext(ctx, password)
	if err != nil {
		return err
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return SetEncodedPasswordInTx(ctx, tx, userID, encoded)
	})
}

// SetPasswordInTx supports atomic creation plus initial provisioning. Prefer
// prehashing with utils.HashPasswordContext and SetEncodedPasswordInTx when the
// transaction can be opened afterwards; this convenience method must hash in
// the caller's already-open transaction, but does so before locking the user.
func SetPasswordInTx(ctx context.Context, tx bun.Tx, userID uuid.UUID, password string) error {
	encoded, err := utils.HashPasswordContext(ctx, password)
	if err != nil {
		return err
	}
	return SetEncodedPasswordInTx(ctx, tx, userID, encoded)
}

// SetEncodedPasswordInTx requires a PHC hash, not plaintext. The caller must
// roll back the transaction on ANY error from this function.
func SetEncodedPasswordInTx(ctx context.Context, tx bun.Tx, userID uuid.UUID, encoded string) error {
	if err := utils.ValidatePasswordHash(encoded); err != nil {
		return err
	}
	if err := lockPasswordUser(ctx, tx, userID); err != nil {
		return err
	}
	if err := models.SetPasswordCredential(ctx, tx, userID, encoded); err != nil {
		return err
	}
	return invalidatePasswordEvidence(ctx, tx, userID)
}

// RemovePassword is idempotent for a passwordless existing user. The user lock
// and deletion of ALL attempts invalidate persisted authentication evidence.
// Non-reusable credential generations also reject verification that started
// before removal but has not yet inserted an attempt when re-enrollment occurs.
// Login completion must take the same user-row lock before checking its attempt
// still exists and comparing the current credential version.
func RemovePassword(ctx context.Context, db *bun.DB, userID uuid.UUID) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := lockPasswordUser(ctx, tx, userID); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*models.PasswordCredential)(nil)).Where("user_id = ?", userID).Exec(ctx); err != nil {
			return errors.New("failed to remove password credential")
		}
		return invalidatePasswordEvidence(ctx, tx, userID)
	})
}

func lockPasswordUser(ctx context.Context, tx bun.Tx, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return errors.New("password operation requires a user ID")
	}
	var id uuid.UUID
	return tx.NewSelect().TableExpr("oidc_users").Column("user_id").
		Where("user_id = ?", userID).For("UPDATE").Scan(ctx, &id)
}

func invalidatePasswordEvidence(ctx context.Context, tx bun.Tx, userID uuid.UUID) error {
	// Delete completed attempts too. In-flight primary verification is separately
	// protected by the non-reusable generation checked under the user-row lock.
	statements := []string{
		`DELETE FROM oidc_login_attempts WHERE user_id = ?`,
		`UPDATE oidc_tokens SET is_active = FALSE, revoked_at = clock_timestamp(),
			revocation_reason = 'password credential changed'
			WHERE is_active = TRUE AND (user_id = ? OR authorization_id IN
				(SELECT authorization_id FROM oidc_authorizations WHERE user_id = ?))`,
		`UPDATE oidc_authorizations SET is_active = FALSE, status = 'revoked', revoked_at = clock_timestamp()
			WHERE user_id = ? AND (is_active = TRUE OR status = 'approved')`,
	}
	for i, statement := range statements {
		args := []interface{}{userID}
		if i == 1 {
			args = append(args, userID)
		}
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return errors.New("failed to invalidate password authentication evidence")
		}
	}
	if err := models.LogoutSessionsByUserID(ctx, tx, userID.String(), "password credential changed"); err != nil {
		return err
	}
	return nil
}
