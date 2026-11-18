package models

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

type passwordQueryRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *passwordQueryRecorder) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, event.Query, fmt.Sprint(event.QueryArgs))
	return ctx
}

func (*passwordQueryRecorder) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestPasswordCredentialSerialization(t *testing.T) {
	credential := PasswordCredential{PasswordHash: "sensitive-verifier"}
	encoded, err := json.Marshal(credential)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), credential.PasswordHash)
	for _, output := range []string{fmt.Sprint(credential), fmt.Sprintf("%+v", credential), fmt.Sprintf("%#v", credential)} {
		require.NotContains(t, output, credential.PasswordHash)
	}
}

func TestPasswordCredential(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	var user User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	_, err = GetPasswordCredential(ctx, conn, user.ID)
	require.ErrorIs(t, err, sql.ErrNoRows)

	encoded, err := utils.HashPassword("  credential secret  ")
	require.NoError(t, err)
	recorder := &passwordQueryRecorder{}
	conn.AddQueryHook(recorder)
	require.NoError(t, SetPasswordCredential(ctx, conn, user.ID, encoded))
	credential, err := GetPasswordCredential(ctx, conn, user.ID)
	require.NoError(t, err)
	require.Equal(t, encoded, credential.PasswordHash)
	require.Positive(t, credential.Version)
	require.False(t, credential.ChangedAt.IsZero())

	var rolledBackVersion int64
	t.Run("transaction rollback", func(t *testing.T) {
		rollback := errors.New("rollback fixture")
		err := conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			require.NoError(t, SetPasswordCredential(ctx, tx, user.ID, encoded))
			current, err := GetPasswordCredential(ctx, tx, user.ID)
			require.NoError(t, err)
			require.Greater(t, current.Version, credential.Version)
			rolledBackVersion = current.Version
			return rollback
		})
		require.ErrorIs(t, err, rollback)
		current, err := GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.Equal(t, credential.Version, current.Version)
	})

	t.Run("concurrent replacements allocate distinct generations", func(t *testing.T) {
		const replacements = 6
		results := make(chan error, replacements)
		versions := make(chan int64, replacements)
		for i := 0; i < replacements; i++ {
			go func() {
				results <- conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
					if err := SetPasswordCredential(ctx, tx, user.ID, encoded); err != nil {
						return err
					}
					current, err := GetPasswordCredential(ctx, tx, user.ID)
					if err == nil {
						versions <- current.Version
					}
					return err
				})
			}()
		}
		for i := 0; i < replacements; i++ {
			require.NoError(t, <-results)
		}
		close(versions)
		seen := make(map[int64]bool)
		for version := range versions {
			require.Greater(t, version, rolledBackVersion, "rolled-back generations must not be reused")
			require.False(t, seen[version], "concurrent replacements must not reuse a generation")
			seen[version] = true
		}
		require.Len(t, seen, replacements)
		current, err := GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.Greater(t, current.Version, credential.Version)
		require.False(t, current.ChangedAt.Before(credential.ChangedAt))
	})

	t.Run("removal and identical hash re-enrollment never reuse a generation", func(t *testing.T) {
		previous, err := GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		_, err = conn.NewDelete().Model((*PasswordCredential)(nil)).Where("user_id = ?", user.ID).Exec(ctx)
		require.NoError(t, err)
		require.NoError(t, SetPasswordCredential(ctx, conn, user.ID, encoded))
		current, err := GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.Greater(t, current.Version, previous.Version)
		require.Equal(t, previous.PasswordHash, current.PasswordHash)
	})

	t.Run("profile update preserves credential", func(t *testing.T) {
		nickname := "passwordtest"
		user.Nickname = &nickname
		require.NoError(t, user.Save(ctx, conn))
		current, err := GetPasswordCredential(ctx, conn, user.ID)
		require.NoError(t, err)
		require.Equal(t, encoded, current.PasswordHash)
		profile, err := json.Marshal(user)
		require.NoError(t, err)
		require.NotContains(t, string(profile), encoded)
	})

	t.Run("native connection bindings", func(t *testing.T) {
		nativeConn, err := conn.Conn(ctx)
		require.NoError(t, err)
		defer nativeConn.Close()
		require.NoError(t, SetPasswordCredential(ctx, nativeConn, user.ID, encoded))
		current, err := GetPasswordCredential(ctx, &nativeConn, user.ID)
		require.NoError(t, err)
		require.Equal(t, encoded, current.PasswordHash)
	})

	t.Run("driver errors are sanitized", func(t *testing.T) {
		require.Error(t, conn.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
			_, err := tx.ExecContext(ctx, `CREATE FUNCTION pg_temp.reject_password_fixture() RETURNS trigger AS $$
				BEGIN RAISE EXCEPTION '%', NEW.password_hash; END;
				$$ LANGUAGE plpgsql`)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `CREATE TRIGGER reject_password_fixture BEFORE INSERT OR UPDATE
				ON oidc_password_credentials FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_password_fixture()`)
			require.NoError(t, err)
			err = SetPasswordCredential(ctx, tx, user.ID, encoded)
			require.Error(t, err)
			require.NotContains(t, err.Error(), encoded)
			return err
		}))
	})

	require.Error(t, SetPasswordCredential(ctx, conn, uuid.Nil, encoded))
	require.Error(t, SetPasswordCredential(ctx, conn, user.ID, "plaintext"))
	require.Error(t, SetPasswordCredential(ctx, conn, uuid.New(), encoded))
	_, err = conn.NewDelete().Model(&user).WherePK().Exec(ctx)
	require.NoError(t, err)
	_, err = GetPasswordCredential(ctx, conn, user.ID)
	require.ErrorIs(t, err, sql.ErrNoRows)
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for _, query := range recorder.queries {
		require.False(t, strings.Contains(query, encoded), "Bun debug hooks received a password verifier")
		require.NotContains(t, query, "credential secret")
	}
}
