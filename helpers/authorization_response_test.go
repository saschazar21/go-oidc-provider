package helpers

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	AUTHORIZATION_RESPONSE_INIT = "authorization_response_init"
)

func TestAuthorizationResponse(t *testing.T) {
	t.Setenv("ISSUER_URL", "http://localhost:8080")
	t.Setenv("KEY_HS256", "dGVzdAo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	conn := db.Connect(ctx)

	user := loadUserFixture(t)
	client := loadClientFixture(t)
	auth := loadAuthFixture(t)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user fixture: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client fixture: %v", err)
	}

	auth.UserID = user.ID
	auth.User = user
	auth.ClientID = client.ID
	auth.Client = client

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(AUTHORIZATION_RESPONSE_INIT))

	type testStruct struct {
		name    string
		preHook func(ctx context.Context, db bun.IDB) *models.Authorization
		wantErr bool
	}

	tests := []testStruct{
		{
			name: "Valid authorization response",
			preHook: func(ctx context.Context, db bun.IDB) *models.Authorization {
				authorization := auth
				if err := authorization.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save authorization fixture: %v", err)
				}
				return authorization
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(AUTHORIZATION_RESPONSE_INIT))
			})

			auth := tt.preHook(ctx, conn)

			ar, err := NewAuthorizationResponse(ctx, conn, auth)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthorizationResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if auth.State != nil && *auth.State != "" {
					assert.NotEmpty(t, ar.State, "Expected state to be set")
					assert.Equal(t, *auth.State, *ar.State, "Expected state to match")
				}

				switch auth.ResponseType {
				case utils.CODE:
					assert.NotEmpty(t, ar.Code, "Expected authorization code to be set")
					assert.Empty(t, ar.IDToken, "Expected ID token to be empty")
					assert.Empty(t, ar.AccessToken, "Expected access token to be empty")
				case utils.ID_TOKEN:
					assert.NotEmpty(t, ar.IDToken, "Expected ID token to be set")
					assert.Empty(t, ar.Code, "Expected authorization code to be empty")
					assert.Empty(t, ar.AccessToken, "Expected access token to be empty")
				case utils.TOKEN:
					assert.NotEmpty(t, ar.AccessToken, "Expected access token to be set")
					assert.Equal(t, ar.TokenType, "Bearer", "Expected token type to be set")
					assert.Empty(t, ar.Code, "Expected authorization code to be empty")
					assert.Empty(t, ar.IDToken, "Expected ID token to be empty")
				case utils.CODE_ID_TOKEN:
					assert.NotEmpty(t, ar.Code, "Expected authorization code to be set")
					assert.NotEmpty(t, ar.IDToken, "Expected ID token to be set")
					assert.Empty(t, ar.AccessToken, "Expected access token to be empty")
				case utils.CODE_TOKEN:
					assert.NotEmpty(t, ar.Code, "Expected authorization code to be set")
					assert.NotEmpty(t, ar.AccessToken, "Expected access token to be set")
					assert.Equal(t, ar.TokenType, "Bearer", "Expected token type to be set")
					assert.Empty(t, ar.IDToken, "Expected ID token to be empty")
					assert.Empty(t, ar.Code, "Expected authorization code to be empty")
				case utils.CODE_ID_TOKEN_TOKEN:
					assert.NotEmpty(t, ar.Code, "Expected authorization code to be set")
					assert.NotEmpty(t, ar.AccessToken, "Expected access token to be set")
					assert.Equal(t, ar.TokenType, "Bearer", "Expected token type to be set")
					assert.NotEmpty(t, ar.IDToken, "Expected ID token to be set")
				}
			}
		})
	}
}
