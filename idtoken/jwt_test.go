package idtoken

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	JWT_TEST_INIT = "jwt_test_init"
)

func TestJWT(t *testing.T) {
	t.Setenv("KEY_ES256", "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUgxRUgxWlVHRXB0Ui80QmhMS2YwL2RTaDhidzRkL2E1U3QxSmdxZ2w5UjlvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFMzFEbzZtOWxhOEtGeWRER0JkRzV3KzVFQVM4QlZST1FhaWpzOU5LM3JJWUN6TjRCNk9lTAo1TU1NVnFhbXh6SXZMZEE3ZlhLZExWcytkMVBoc1diMUdRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	conn := db.Connect(ctx)

	var user models.User
	if err := test.LoadFixture("user_address.json", &user); err != nil {
		t.Fatalf("Failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("Failed to load authorization fixture: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user fixture: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client fixture: %v", err)
	}

	auth.UserID = user.ID
	auth.User = &user
	auth.ClientID = client.ID
	auth.Client = &client
	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization fixture: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(JWT_TEST_INIT))

	type testStruct struct {
		Name    string
		PreHook func(ctx context.Context, db bun.IDB) *map[utils.TokenType]*models.Token
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Valid JWT",
			PreHook: func(ctx context.Context, db bun.IDB) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				// Create a valid access token
				authorization := auth                                                                 // create a copy to avoid modifying the original
				authorization.Scope = []utils.Scope{"openid", "profile", "email", "address", "phone"} // request all scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				conn.Close()
				pgContainer.Restore(ctx, postgres.WithSnapshotName(JWT_TEST_INIT))
			})

			var tokens *map[utils.TokenType]*models.Token
			if tt.PreHook != nil {
				tokens = tt.PreHook(ctx, conn)
			}

			_, err := NewSignedJWT(tokens, "ES256")
			if (err != nil) != tt.WantErr {
				t.Errorf("NewSignedJWT() error = %v, wantErr %v", err, tt.WantErr)
				return
			}
		})
	}
}
