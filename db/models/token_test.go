package models

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const TOKEN_TEST_INIT = "token_test_init"

func TestToken(t *testing.T) {
	t.Setenv(test.ROOT_DIR_ENV, "../../")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := loadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	var client Client
	if err := loadFixture("client_minimal.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	var authorization Authorization
	if err := loadFixture("authorization_approved.json", &authorization); err != nil {
		t.Fatalf("Failed to load fixture: %v", err)
	}

	authorization.UserID = user.ID
	authorization.User = &user
	authorization.ClientID = client.ID
	authorization.Client = &client
	if err := authorization.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))

	type testStruct struct {
		Name        string
		CreateToken func(ctx context.Context, db bun.IDB) (*Token, error)
		WantErr     bool
	}

	tests := []testStruct{
		{
			Name: "Create Standard Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateToken(ctx, db, utils.ACCESS_TOKEN_TYPE, &authorization)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token with User",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token for testing"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					User:        &user,
					Description: &msg,
					Scope:       &scope,
				}
				return CreateCustomToken(ctx, db, customToken)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token with UserID",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token with UserID"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					UserID:      &user.ID,
					Description: &msg,
					Scope:       &scope,
				}
				return CreateCustomToken(ctx, db, customToken)
			},
			WantErr: false,
		},
		{
			Name: "Create Custom Token without User",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				msg := "Custom token without user"
				scope := []utils.Scope{"openid", "profile"}
				customToken := &Token{
					Description: &msg,
					Scope:       &scope,
				}
				return CreateCustomToken(ctx, db, customToken)
			},
			WantErr: true,
		},
		{
			Name: "Create Client Credentials Token",
			CreateToken: func(ctx context.Context, db bun.IDB) (*Token, error) {
				return CreateClientCredentialsToken(ctx, db, &client)
			},
			WantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_TEST_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			token, err := tt.CreateToken(ctx, db)
			if (err != nil) != tt.WantErr {
				t.Fatalf("CreateToken() error = %v, wantErr %v", err, tt.WantErr)
			}

			if err == nil {
				assert.NotNil(t, token, "Expected token to be non-nil")
				assert.NotEmpty(t, token.ID, "Expected token ID to be set")
				assert.NotEmpty(t, token.Value, "Expected token Value to be set")
				assert.NotEmpty(t, token.ExpiresAt.ExpiresAt, "Expected token ExpiresAt to be set")

				tokenHash, hashErr := token.GenerateTokenHash()
				if hashErr != nil {
					t.Fatalf("GenerateTokenHash() error = %v", hashErr)
				}
				assert.NotEmpty(t, tokenHash, "Expected token hash to be generated")

				var retrievedToken *Token
				retrievedToken, err = GetTokenByValue(ctx, db, string(token.Value))

				if err != nil {
					t.Fatalf("GetTokenByValue() error = %v", err)
				}

				assert.NotNil(t, retrievedToken, "Expected retrieved token to be non-nil")
				assert.Equal(t, token.ID, retrievedToken.ID, "Expected retrieved token ID to match")
				assert.Equal(t, token.Type, retrievedToken.Type, "Expected retrieved token Type to match")

			} else {
				assert.Nil(t, token, "Expected token to be nil on error")
			}
		})
	}
}
