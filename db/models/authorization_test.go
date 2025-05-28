package models

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestAuthorization(t *testing.T) {
	t.Setenv(test.ROOT_DIR_ENV, "../..")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	type testStruct struct {
		Name        string
		TestFile    string
		WantsClient bool
		WantsUser   bool
		WantErr     bool
	}

	tests := []testStruct{
		{
			Name:        "Pending Authorization",
			TestFile:    "authorization_pending.json",
			WantsClient: true,
			WantsUser:   false,
			WantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(test.SNAPSHOT_INIT))
			})

			var user User
			if err := loadFixture("user.json", &user); err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			if err := user.Save(ctx, conn); err != nil {
				t.Fatalf("Failed to save user: %v", err)
			}

			var client Client
			if err := loadFixture("client_minimal.json", &client); err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			client.OwnerID = user.ID
			if err := client.Save(ctx, conn); err != nil {
				t.Fatalf("Failed to save client: %v", err)
			}

			var authorization Authorization
			if err := loadFixture(tt.TestFile, &authorization); err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			if tt.WantsClient {
				authorization.ClientID = client.ID
				authorization.Client = &client
			}

			if tt.WantsUser {
				authorization.UserID = user.ID
				authorization.User = &user
			}

			if err := authorization.Save(ctx, conn); (err != nil) != tt.WantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, authorization.ID, "Authorization ID should not be empty after save")
				assert.Empty(t, authorization.ReplacedID, "Replaced ID should be empty for new authorizations")

				newAuthorization := authorization

				if tt.WantsUser {
					newAuthorization.UserID = user.ID
					newAuthorization.User = &user
				}

				if err := newAuthorization.Save(ctx, conn); err != nil {
					t.Errorf("Save() error = %v", err)
				}
				assert.NotEmpty(t, newAuthorization.ID, "New Authorization ID should not be empty after save")
				assert.NotEmpty(t, newAuthorization.ReplacedID, "Replaced ID should not be empty for replaced authorizations")
				assert.NotNil(t, newAuthorization.ReplacedAuthorization, "Replaced Authorization should not be nil for replaced authorizations")
				assert.Equal(t, authorization.ID, newAuthorization.ReplacedID, "Replaced ID should match the original authorization ID")
			}
		})
	}
}
