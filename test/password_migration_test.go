package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestPasswordMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := CreateContainer(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() { TerminateContainer(t, context.Background(), container) })
	conn, err := pgx.Connect(ctx, os.Getenv(DB_URL_ENV))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close(context.Background())) })

	root := os.Getenv(ROOT_DIR_ENV)
	if root == "" {
		root = ".."
	}
	migration, err := os.ReadFile(filepath.Join(root, ".migrations", "0.2.0.sql"))
	require.NoError(t, err)

	exec := func(statement string) {
		t.Helper()
		_, err := conn.Exec(ctx, statement)
		require.NoError(t, err, "SQL: %s", statement)
	}
	text := func(query string) string {
		t.Helper()
		var value string
		require.NoError(t, conn.QueryRow(ctx, query).Scan(&value))
		return value
	}

	// Column order intentionally does not participate: ALTER TABLE appends AMR,
	// whereas the fresh schema declares it beside the other authentication data.
	schema := func() map[string]string {
		t.Helper()
		return map[string]string{
			"columns": text(`
				SELECT jsonb_agg(to_jsonb(c) ORDER BY table_name, column_name)::text
				FROM (
					SELECT table_name, column_name, data_type, udt_schema, udt_name,
					       is_nullable, column_default, character_maximum_length,
					       numeric_precision, numeric_scale, datetime_precision
					FROM information_schema.columns
					WHERE table_schema = 'public' AND table_name IN (
						'oidc_password_credentials', 'oidc_login_attempts', 'oidc_authorizations')
				) c`),
			"constraints": text(`
				SELECT jsonb_agg(to_jsonb(c) ORDER BY table_name, constraint_name)::text
				FROM (
					SELECT r.relname AS table_name, c.conname AS constraint_name,
					       c.contype, c.convalidated, c.condeferrable, c.condeferred,
					       pg_get_constraintdef(c.oid) AS definition
					FROM pg_constraint c
					JOIN pg_class r ON r.oid = c.conrelid
					JOIN pg_namespace n ON n.oid = r.relnamespace
					WHERE n.nspname = 'public' AND r.relname IN (
						'oidc_password_credentials', 'oidc_login_attempts', 'oidc_authorizations')
				) c`),
			"indexes": text(`
				SELECT jsonb_agg(to_jsonb(i) ORDER BY tablename, indexname)::text
				FROM (
					SELECT tablename, indexname, indexdef
					FROM pg_indexes
					WHERE schemaname = 'public' AND tablename IN (
						'oidc_password_credentials', 'oidc_login_attempts', 'oidc_authorizations')
				) i`),
		}
	}
	fresh := schema()
	require.Contains(t, fresh["columns"], "amr")
	require.Contains(t, fresh["indexes"], "idx_oidc_login_attempts_user")
	require.Contains(t, fresh["indexes"], "idx_oidc_login_attempts_expires")

	// Reconstruct the deployed pre-feature schema without brittle textual SQL
	// rewriting. Populate it only after removing every password-login addition.
	exec(`DROP TABLE oidc_login_attempts;
	      DROP TABLE oidc_password_credentials;
	      DROP SEQUENCE oidc_password_credential_version_seq;
	      ALTER TABLE oidc_authorizations DROP COLUMN amr;`)
	require.Equal(t, "true", text(`SELECT (
		to_regclass('public.oidc_password_credentials') IS NULL AND
		to_regclass('public.oidc_login_attempts') IS NULL AND NOT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'oidc_authorizations'
			AND column_name = 'amr'))::text`))

	// BYTEA values are opaque ciphertext stand-ins: SQL must preserve them byte
	// for byte; no model hooks, encryption keys, or import cycles are involved.
	exec(`
		INSERT INTO oidc_users (user_id, email, email_hash, given_name, email_verified)
		VALUES ('00000000-0000-0000-0000-000000000001',
		        decode('00ff1020', 'hex'), decode('aabbccdd', 'hex'), decode('ff00', 'hex'), true);
		INSERT INTO oidc_clients (client_id, client_name, owner_id, redirect_uris)
		VALUES ('migration-client', 'Legacy client', '00000000-0000-0000-0000-000000000001',
		        ARRAY['https://example.com/callback']);
		INSERT INTO oidc_authorizations (
			authorization_id, client_id, user_id, redirect_uri, response_type,
			scope, status, is_active, auth_time, expires_at)
		VALUES ('00000000-0000-0000-0000-000000000002', 'migration-client',
		        '00000000-0000-0000-0000-000000000001', 'https://example.com/callback',
		        'code', ARRAY['openid', 'offline_access']::oidc_standard_scope[],
		        'approved', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour');
		INSERT INTO oidc_tokens (token_id, authorization_id, token_value, token_type, scope, expires_at)
		VALUES ('00000000-0000-0000-0000-000000000003',
		        '00000000-0000-0000-0000-000000000002', decode('deadbeef00', 'hex'),
		        'refresh_token', ARRAY[]::oidc_standard_scope[], CURRENT_TIMESTAMP + INTERVAL '1 day');`)
	legacyRows := func() string {
		t.Helper()
		return text(`SELECT jsonb_build_object(
			'users', (SELECT jsonb_agg(to_jsonb(u) ORDER BY user_id) FROM oidc_users u),
			'clients', (SELECT jsonb_agg(to_jsonb(c) ORDER BY client_id) FROM oidc_clients c),
			'authorizations', (SELECT jsonb_agg(to_jsonb(a) - 'amr' ORDER BY authorization_id)
			                   FROM oidc_authorizations a),
			'tokens', (SELECT jsonb_agg(to_jsonb(k) ORDER BY token_id) FROM oidc_tokens k))::text`)
	}
	before := legacyRows()

	for pass := 1; pass <= 2; pass++ {
		exec(string(migration))
		require.Equal(t, fresh, schema(), "migration pass %d differs from fresh schema", pass)
		require.Equal(t, before, legacyRows(), "migration pass %d changed legacy data", pass)
		require.Equal(t, "true", text(`SELECT (amr IS NULL)::text FROM oidc_authorizations
			WHERE authorization_id = '00000000-0000-0000-0000-000000000002'`))
		require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_password_credentials`))
		require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_login_attempts`))
	}

	// Upgraded users remain passwordless until explicitly provisioned. Verify
	// actual defaults and constraints, not only their catalog representations.
	exec(`INSERT INTO oidc_password_credentials (user_id, password_hash)
		VALUES ('00000000-0000-0000-0000-000000000001', 'opaque-password-verifier');
		INSERT INTO oidc_login_attempts (attempt_id, user_id, flow, binding_hash, expires_at)
		VALUES ('00000000-0000-0000-0000-000000000004',
		        '00000000-0000-0000-0000-000000000001', 'password', decode('010203', 'hex'),
		        CURRENT_TIMESTAMP + INTERVAL '10 minutes');`)
	require.Equal(t, "true", text(`SELECT (version > 0 AND changed_at IS NOT NULL)::text
		FROM oidc_password_credentials`))
	require.Equal(t, "true", text(`SELECT (credential_version = 0 AND failed_attempts = 0
		AND continuation = '/' AND methods IS NULL AND completed_at IS NULL
		AND challenge_id IS NULL AND code_digest IS NULL AND code_expires_at IS NULL
		AND last_sent_at IS NULL AND created_at IS NOT NULL)::text FROM oidc_login_attempts`))

	for _, tc := range []struct {
		name, statement, code string
	}{
		{"credential primary key", `INSERT INTO oidc_password_credentials (user_id, password_hash)
		 VALUES ('00000000-0000-0000-0000-000000000001', 'duplicate')`, "23505"},
		{"credential user foreign key", `INSERT INTO oidc_password_credentials (user_id, password_hash)
		 VALUES ('00000000-0000-0000-0000-000000000099', 'orphan')`, "23503"},
		{"credential hash required", `UPDATE oidc_password_credentials SET password_hash = NULL`, "23502"},
		{"positive credential version", `UPDATE oidc_password_credentials SET version = 0`, "23514"},
		{"attempt primary key", `INSERT INTO oidc_login_attempts SELECT * FROM oidc_login_attempts`, "23505"},
		{"attempt user foreign key", `UPDATE oidc_login_attempts
		 SET user_id = '00000000-0000-0000-0000-000000000099'`, "23503"},
		{"attempt binding required", `UPDATE oidc_login_attempts SET binding_hash = NULL`, "23502"},
		{"attempt flow required", `UPDATE oidc_login_attempts SET flow = NULL`, "23502"},
		{"attempt expiry required", `UPDATE oidc_login_attempts SET expires_at = NULL`, "23502"},
		{"nonnegative failed attempts", `UPDATE oidc_login_attempts SET failed_attempts = -1`, "23514"},
		{"attempt method enum", `UPDATE oidc_login_attempts SET methods = ARRAY['unverified']::oidc_amr_type[]`, "22P02"},
		{"authorization AMR enum", `UPDATE oidc_authorizations SET amr = ARRAY['unverified']::oidc_amr_type[]`, "22P02"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, tc.statement)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, tc.code, pgErr.Code)
		})
	}

	// Idempotence must also hold with populated new tables, without resetting
	// credentials, attempt progress, or trusted authorization evidence.
	exec(`UPDATE oidc_authorizations SET amr = ARRAY['pwd', 'email']::oidc_amr_type[];
	      UPDATE oidc_password_credentials SET version = 7;
	      UPDATE oidc_login_attempts SET failed_attempts = 2, credential_version = 7,
	             methods = ARRAY['pwd']::oidc_amr_type[];`)
	newRows := func() string {
		t.Helper()
		return text(`SELECT jsonb_build_object(
			'credentials', (SELECT jsonb_agg(to_jsonb(c)) FROM oidc_password_credentials c),
			'attempts', (SELECT jsonb_agg(to_jsonb(a)) FROM oidc_login_attempts a),
			'amr', (SELECT to_jsonb(amr) FROM oidc_authorizations))::text`)
	}
	provisioned := newRows()
	exec(string(migration))
	require.Equal(t, provisioned, newRows())
	require.Equal(t, fresh, schema())
	require.Equal(t, "{pwd,email}", text(`SELECT amr::text FROM oidc_authorizations`))

	// Attempts may also precede user identification; deleting an identified
	// user cascades only that user's credential/attempt (and legacy grants).
	exec(`INSERT INTO oidc_login_attempts (attempt_id, flow, binding_hash, expires_at)
		VALUES ('00000000-0000-0000-0000-000000000005', 'email', decode('040506', 'hex'),
		        CURRENT_TIMESTAMP + INTERVAL '10 minutes');
		DELETE FROM oidc_users WHERE user_id = '00000000-0000-0000-0000-000000000001';`)
	require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_password_credentials`))
	require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_login_attempts WHERE user_id IS NOT NULL`))
	require.Equal(t, "1", text(`SELECT count(*)::text FROM oidc_login_attempts
		WHERE attempt_id = '00000000-0000-0000-0000-000000000005' AND user_id IS NULL`))
	require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_authorizations`))
	require.Equal(t, "0", text(`SELECT count(*)::text FROM oidc_tokens`))
}
