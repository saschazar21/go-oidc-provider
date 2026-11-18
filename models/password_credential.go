package models

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

// PasswordCredential is separate from User so profile/claim serialization and
// profile updates can neither disclose nor overwrite credentials.
type PasswordCredential struct {
	bun.BaseModel `bun:"table:oidc_password_credentials"`
	UserID        uuid.UUID `json:"-" bun:"user_id,type:uuid,pk"`
	PasswordHash  string    `json:"-" bun:"password_hash,notnull"`
	Version       int64     `json:"-" bun:"version,notnull"`
	ChangedAt     time.Time `json:"-" bun:"changed_at,notnull"`
}

// String and GoString also keep accidental formatted logging secret-free.
func (p PasswordCredential) String() string   { return "PasswordCredential{redacted}" }
func (p PasswordCredential) GoString() string { return p.String() }

// Native database/sql handles are essential here: Bun's QueryContext and
// ExecContext interpolate arguments before invoking query/debug hooks. Native
// $n bindings keep hashes out of Bun formatted SQL entirely. Applications must
// likewise not enable parameter-value logging in their driver/database server.
type passwordSQL interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}

func passwordConnection(db bun.IDB) (passwordSQL, error) {
	switch conn := db.(type) {
	case *bun.DB:
		return conn.DB, nil
	case bun.Tx:
		return conn.Tx, nil
	case *bun.Tx:
		return conn.Tx, nil
	case bun.Conn:
		return conn.Conn, nil
	case *bun.Conn:
		return conn.Conn, nil
	default:
		return nil, errors.New("unsupported password database connection")
	}
}

// GetPasswordCredential returns sql.ErrNoRows for a passwordless user.
func GetPasswordCredential(ctx context.Context, db bun.IDB, userID uuid.UUID) (*PasswordCredential, error) {
	conn, err := passwordConnection(db)
	if err != nil {
		return nil, err
	}
	credential := &PasswordCredential{}
	err = conn.QueryRowContext(ctx, `SELECT user_id, password_hash, version, changed_at
		FROM oidc_password_credentials WHERE user_id = $1`, userID).
		Scan(&credential.UserID, &credential.PasswordHash, &credential.Version, &credential.ChangedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, errors.New("failed to read password credential")
	}
	return credential, nil
}

// SetPasswordCredential is a persistence primitive, NOT a provisioning API.
// Call helpers.SetPassword (or helpers.SetEncodedPasswordInTx) to also lock the
// user and atomically invalidate attempts/revoke sessions and grants. Replacing
// or re-enrolling a credential allocates a fresh database sequence generation,
// including after deletion or rollback. Versions are not adjacent per user.
func SetPasswordCredential(ctx context.Context, db bun.IDB, userID uuid.UUID, encoded string) error {
	if userID == uuid.Nil {
		return errors.New("password credential requires a user ID")
	}
	if err := utils.ValidatePasswordHash(encoded); err != nil {
		return err
	}
	conn, err := passwordConnection(db)
	if err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO oidc_password_credentials (user_id, password_hash, version, changed_at)
		VALUES ($1, $2, nextval('oidc_password_credential_version_seq'), clock_timestamp())
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash,
		version = nextval('oidc_password_credential_version_seq'), changed_at = clock_timestamp()`, userID, encoded)
	if err != nil {
		// Driver errors can include rejected row data; never wrap or log them.
		return errors.New("failed to store password credential")
	}
	return nil
}
