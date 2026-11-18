package models

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func TestMagicLinkTokenAtomicConsumption(t *testing.T) {
	ctx := context.Background()
	container, err := test.CreateContainer(t, ctx)
	require.NoError(t, err)
	defer test.TerminateContainer(t, ctx, container)
	conn := db.Connect(ctx)
	defer conn.Close()
	t.Setenv("DEBUG", "0")
	var user User
	require.NoError(t, test.LoadFixture("user.json", &user))
	require.NoError(t, user.Save(ctx, conn))
	create := func(t *testing.T) (*MagicLinkToken, string) {
		t.Helper()
		token, err := CreateMagicLinkToken(ctx, conn, string(*user.Email))
		require.NoError(t, err)
		return token, string(*token.Token)
	}

	for _, useConn := range []bool{false, true} {
		name := "DB"
		if useConn {
			name = "Conn"
		}
		t.Run(name+" exactly one success", func(t *testing.T) {
			token, code := create(t)
			const contenders = 8
			start := make(chan struct{})
			outcomes := make(chan bool, contenders)
			var wg sync.WaitGroup
			for i := 0; i < contenders; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var handle bun.IDB = conn
					if useConn {
						c, err := conn.Conn(ctx)
						if err != nil {
							outcomes <- false
							return
						}
						defer c.Close()
						handle = c
					}
					<-start
					consumed, err := ConsumeMagicLinkToken(ctx, handle, token.ID.String(), code)
					outcomes <- err == nil && consumed != nil && consumed.Result != nil && *consumed.Result == utils.SUCCESS && consumed.User != nil
				}()
			}
			close(start)
			wg.Wait()
			close(outcomes)
			successes := 0
			for success := range outcomes {
				if success {
					successes++
				}
			}
			require.Equal(t, 1, successes)
		})
	}

	for _, pointer := range []bool{false, true} {
		name := "Tx"
		if pointer {
			name = "Tx pointer"
		}
		t.Run(name+" holds lock and rolls back session", func(t *testing.T) {
			token, code := create(t)
			tx, err := conn.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			var handle bun.IDB = tx
			if pointer {
				handle = &tx
			}
			consumed, err := ConsumeMagicLinkToken(ctx, handle, token.ID.String(), code)
			require.NoError(t, err)
			require.Equal(t, utils.SUCCESS, *consumed.Result)
			session := &Session{UserID: user.ID, AuthTime: time.Now().UTC()}
			require.NoError(t, session.Save(ctx, tx))

			started := make(chan struct{})
			done := make(chan bool, 1)
			go func() {
				close(started)
				result, err := ConsumeMagicLinkToken(ctx, conn, token.ID.String(), code)
				done <- err == nil && result != nil && result.Result != nil && *result.Result == utils.SUCCESS
			}()
			<-started
			select {
			case <-done:
				t.Fatal("competing consumer completed before outer transaction ended")
			case <-time.After(100 * time.Millisecond):
			}
			require.NoError(t, tx.Rollback())
			select {
			case success := <-done:
				require.True(t, success, "rolled-back consumption must be retryable")
			case <-time.After(5 * time.Second):
				t.Fatal("consumer did not finish after rollback")
			}
			count, err := conn.NewSelect().TableExpr("oidc_sessions").Where("session_id = ?", session.ID).Count(ctx)
			require.NoError(t, err)
			require.Zero(t, count)
		})
	}

	t.Run("inactive token without result", func(t *testing.T) {
		token, code := create(t)
		_, err := conn.NewUpdate().Model((*MagicLinkToken)(nil)).Set("is_active = false").Where("token_id = ?", token.ID).Exec(ctx)
		require.NoError(t, err)
		consumed, err := ConsumeMagicLinkToken(ctx, conn, token.ID.String(), code)
		require.Error(t, err)
		require.Nil(t, consumed)
	})
}
