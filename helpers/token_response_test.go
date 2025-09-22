package helpers

import (
	"context"
	"net/http/httptest"
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
	TOKEN_RESPONSE_INIT = "token_response_init"
)

func TestTokenResponse(t *testing.T) {
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
	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization fixture: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(TOKEN_RESPONSE_INIT))

	type testStruct struct {
		Name    string
		PreHook func(ctx context.Context, db bun.IDB) *[]*models.Token
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Valid token response",
			PreHook: func(ctx context.Context, db bun.IDB) *[]*models.Token {
				tokens := make([]*models.Token, 0)
				for _, tokenType := range []utils.TokenType{utils.ACCESS_TOKEN_TYPE, utils.REFRESH_TOKEN_TYPE} {
					token, err := models.CreateToken(ctx, db, string(tokenType), auth)
					if err != nil {
						t.Fatalf("Failed to create %s: %v", tokenType, err)
					}

					tokens = append(tokens, token)
				}
				return &tokens
			},
			WantErr: false,
		},
		{
			Name: "Missing access token",
			PreHook: func(ctx context.Context, db bun.IDB) *[]*models.Token {
				tokens := make([]*models.Token, 0)
				token, err := models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), auth)
				if err != nil {
					t.Fatalf("Failed to create refresh token: %v", err)
				}

				tokens = append(tokens, token)
				return &tokens
			},
			WantErr: true,
		},
		{
			Name: "Missing refresh token",
			PreHook: func(ctx context.Context, db bun.IDB) *[]*models.Token {
				tokens := make([]*models.Token, 0)
				token, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), auth)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				tokens = append(tokens, token)
				return &tokens
			},
			WantErr: false,
		},
		{
			Name: "No tokens",
			PreHook: func(ctx context.Context, db bun.IDB) *[]*models.Token {
				tokens := make([]*models.Token, 0)
				return &tokens
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(TOKEN_RESPONSE_INIT))
			})

			var tokens *[]*models.Token
			if tt.PreHook != nil {
				tokens = tt.PreHook(ctx, conn)
			}

			res := NewTokenResponse(*tokens...)

			for _, token := range *tokens {
				switch token.Type {
				case utils.ACCESS_TOKEN_TYPE:
					assert.NotEmpty(t, res.AccessToken, "Access token should be set")
					assert.Equal(t, int64(token.ExpiresAt.ExpiresAt.Sub(token.CreatedAt.CreatedAt).Seconds()), res.ExpiresIn, "ExpiresIn should match token expiry")
					assert.Equal(t, "Bearer", res.TokenType, "TokenType should be Bearer")
					assert.NotEmpty(t, res.Scope, "Scope should be set")
				case utils.REFRESH_TOKEN_TYPE:
					assert.NotEmpty(t, res.RefreshToken, "Refresh token should be set")
				}
			}

			w := httptest.NewRecorder()

			res.Write(w)

			if !tt.WantErr {
				assert.Equal(t, 200, w.Result().StatusCode, "Expected HTTP status 200 OK")
				assert.Equal(t, "application/json", w.Result().Header.Get("Content-Type"), "Expected Content-Type application/json")
				assert.Equal(t, "no-store", w.Result().Header.Get("Cache-Control"), "Expected Cache-Control no-store")
				assert.Equal(t, "no-cache", w.Result().Header.Get("Pragma"), "Expected Pragma no-cache")
			} else {
				assert.NotEqual(t, 200, w.Result().StatusCode, "Did not expect HTTP status 200 OK")
			}
		})
	}
}
