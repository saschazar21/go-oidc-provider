package helpers

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func TestPasswordProvisioning(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	// One connection keeps the test-only attempts fixture in this session. Its
	// deliberately minimal contract avoids coupling credential tests to the
	// coordinator's other attempt fields and constraints.
	conn.DB.SetMaxOpenConns(1)
	_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE oidc_login_attempts (
		user_id UUID, credential_version BIGINT, completed_at TIMESTAMPTZ)`)
	require.NoError(t, err)

	var user models.User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	var other models.User
	require.NoError(t, test.LoadFixture("user.json", &other))
	otherEmail := utils.EncryptedString("unaffected@example.com")
	other.Email = &otherEmail
	require.NoError(t, other.Save(ctx, conn))
	var client models.Client
	require.NoError(t, test.LoadFixture("client_minimal.json", &client))
	client.OwnerID = user.ID
	require.NoError(t, client.Save(ctx, conn))

	seedEvidence := func(t *testing.T, id uuid.UUID) uuid.UUID {
		t.Helper()
		authID := uuid.New()
		// Seed only grant fields needed by revocation, independent of concurrent
		// parent changes to OIDC model hooks and authentication evidence fields.
		_, err := conn.ExecContext(ctx, `INSERT INTO oidc_authorizations
			(authorization_id, client_id, user_id, redirect_uri, response_type, scope, is_active, status, expires_at)
			VALUES (?, ?, ?, 'https://minimal-client.example.com/callback', 'code', '{openid}', TRUE, 'approved', now() + interval '1 day')`, authID, client.ID, id)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `INSERT INTO oidc_sessions (user_id) VALUES (?)`, id)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `INSERT INTO oidc_login_attempts (user_id, credential_version) VALUES (?, 1)`, id)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `INSERT INTO oidc_login_attempts (user_id, credential_version, completed_at)
			VALUES (?, 1, now())`, id)
		require.NoError(t, err)
		for _, tokenType := range []string{"authorization_code", "access_token", "refresh_token"} {
			_, err = conn.ExecContext(ctx, `INSERT INTO oidc_tokens
				(authorization_id, token_value, token_type, expires_at, scope)
				VALUES (?, ?, ?, now() + interval '1 day', '{}')`, authID, []byte(uuid.NewString()), tokenType)
			require.NoError(t, err)
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO oidc_tokens
			(user_id, token_value, token_type, is_custom, scope, expires_at)
			VALUES (?, ?, 'access_token', TRUE, '{openid}', now() + interval '1 day')`, id, []byte(uuid.NewString()))
		require.NoError(t, err)
		return authID
	}
	assertEvidence := func(t *testing.T, id uuid.UUID, active bool) {
		t.Helper()
		for _, table := range []string{"oidc_sessions", "oidc_authorizations"} {
			var count int
			require.NoError(t, conn.NewSelect().TableExpr(table).ColumnExpr("count(*)").
				Where("user_id = ? AND is_active = TRUE", id).Scan(ctx, &count))
			require.Equal(t, active, count > 0, table)
		}
		var count int
		require.NoError(t, conn.NewSelect().TableExpr("oidc_tokens").ColumnExpr("count(*)").
			Where(`is_active = TRUE AND (user_id = ? OR authorization_id IN
				(SELECT authorization_id FROM oidc_authorizations WHERE user_id = ?))`, id, id).Scan(ctx, &count))
		require.Equal(t, active, count > 0, "tokens")
		require.NoError(t, conn.NewSelect().TableExpr("oidc_login_attempts").ColumnExpr("count(*)").
			Where("user_id = ?", id).Scan(ctx, &count))
		require.Equal(t, active, count > 0, "attempts, including completed attempts")
	}

	seedEvidence(t, user.ID)
	seedEvidence(t, other.ID)
	require.NoError(t, SetPassword(ctx, conn, user.ID, " original password "))
	first, err := models.GetPasswordCredential(ctx, conn, user.ID)
	require.NoError(t, err)
	require.Positive(t, first.Version)
	assertEvidence(t, user.ID, false)
	assertEvidence(t, other.ID, true)

	seedEvidence(t, user.ID)
	require.NoError(t, SetPassword(ctx, conn, user.ID, "replacement"))
	second, err := models.GetPasswordCredential(ctx, conn, user.ID)
	require.NoError(t, err)
	require.Greater(t, second.Version, first.Version)
	matched, err := utils.VerifyPassword(second.PasswordHash, "replacement")
	require.NoError(t, err)
	require.True(t, matched)
	assertEvidence(t, user.ID, false)

	t.Run("failure rolls back credential and revocation", func(t *testing.T) {
		seedEvidence(t, user.ID)
		// Force invalidation to fail after the credential write; the outer
		// transaction must roll back the credential and its version too.
		_, err := conn.ExecContext(ctx, `CREATE FUNCTION pg_temp.reject_attempt_delete_fixture() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'injected invalidation failure'; END;
			$$ LANGUAGE plpgsql`)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `CREATE TRIGGER reject_attempt_delete_fixture BEFORE DELETE
			ON oidc_login_attempts FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_attempt_delete_fixture()`)
		require.NoError(t, err)
		err = SetPassword(ctx, conn, user.ID, "must not survive")
		require.Error(t, err)
		_, restoreErr := conn.ExecContext(ctx, `DROP TRIGGER reject_attempt_delete_fixture ON oidc_login_attempts`)
		require.NoError(t, restoreErr)
		current, err := models.GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.Equal(t, second.PasswordHash, current.PasswordHash)
		require.Equal(t, second.Version, current.Version)
		assertEvidence(t, user.ID, true)
	})

	require.NoError(t, RemovePassword(ctx, conn, user.ID))
	_, err = models.GetPasswordCredential(ctx, conn, user.ID)
	require.ErrorIs(t, err, sql.ErrNoRows)
	assertEvidence(t, user.ID, false)
	assertEvidence(t, other.ID, true)
	require.NoError(t, RemovePassword(ctx, conn, user.ID))
	// Re-enrollment must not reuse evidence still held by primary verifiers
	// that have not yet inserted an attempt.
	require.NoError(t, SetPassword(ctx, conn, user.ID, "re-enrolled"))
	reenrolled, err := models.GetPasswordCredential(ctx, conn, user.ID)
	require.NoError(t, err)
	require.Greater(t, reenrolled.Version, second.Version)
	require.ErrorIs(t, RemovePassword(ctx, conn, uuid.New()), sql.ErrNoRows)
	require.Error(t, SetPassword(ctx, conn, uuid.Nil, "secret"))
	require.Error(t, RemovePassword(ctx, conn, uuid.Nil))

	t.Run("atomic create with password rolls back", func(t *testing.T) {
		var created models.User
		email := utils.EncryptedString("rollback-password@example.com")
		created.Email = &email
		rollback := errors.New("intentional rollback")
		err := conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			require.NoError(t, created.Save(ctx, tx))
			require.NoError(t, SetPasswordInTx(ctx, tx, created.ID, "initial password"))
			credential, err := models.GetPasswordCredential(ctx, tx, created.ID)
			require.NoError(t, err)
			require.Greater(t, credential.Version, reenrolled.Version)
			return rollback
		})
		require.ErrorIs(t, err, rollback)
		_, err = models.GetPasswordCredential(ctx, conn, created.ID)
		require.ErrorIs(t, err, sql.ErrNoRows)
		exists, err := conn.NewSelect().Model((*models.User)(nil)).Where("user_id = ?", created.ID).Exists(ctx)
		require.NoError(t, err)
		require.False(t, exists)
	})
}
