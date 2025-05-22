package models

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestUser(t *testing.T) {
	t.Setenv(test.ROOT_DIR_ENV, "../../")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)

	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name     string
		TestFile string
		WantErr  bool
	}

	tests := []testStruct{
		{
			Name:     "Simple User",
			TestFile: "user.json",
			WantErr:  false,
		},
		{
			Name:     "User with address",
			TestFile: "user_address.json",
			WantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(test.SNAPSHOT_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			file, err := os.Open(filepath.Join("testdata", tt.TestFile))

			if err != nil {
				t.Fatalf("Failed to open file: %v", err)
			}

			defer file.Close()

			var user User

			if err := json.NewDecoder(file).Decode(&user); err != nil {
				t.Fatalf("Failed to decode JSON: %v", err)
			}

			initialID := user.ID.String()

			if err := user.Save(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.WantErr)
			}

			if tt.WantErr {
				return
			}

			assert.NotNil(t, user.ID, "User ID should not be nil")
			assert.NotEqual(t, initialID, user.ID.String(), "User ID should be different from initial ID")

			retrievedUser, err := GetUserByID(ctx, db, user.ID.String())
			if err != nil {
				t.Fatalf("Failed to retrieve user: %v", err)
			}

			assert.Equal(t, user.ID, retrievedUser.ID, "User ID should match")
			assert.Equal(t, user.Email, retrievedUser.Email, "User email should match")
			assert.NotNil(t, retrievedUser.EmailHash, "User email hash should not be nil")

			retrievedUserByEmail, err := GetUserByEmail(ctx, db, string(*user.Email))
			if err != nil {
				t.Fatalf("Failed to retrieve user by email: %v", err)
			}

			assert.Equal(t, user.ID, retrievedUserByEmail.ID, "User ID should match")
			assert.Equal(t, user.Email, retrievedUserByEmail.Email, "User email should match")

			if user.Address != nil {
				assert.NotNil(t, retrievedUser.Address, "User address should not be nil")
				assert.Equal(t, user.Address.StreetAddress, retrievedUser.Address.StreetAddress, "User address street should match")
				assert.Equal(t, user.Address.Locality, retrievedUser.Address.Locality, "User address city should match")
				assert.Equal(t, user.Address.Region, retrievedUser.Address.Region, "User address state should match")
				assert.Equal(t, user.Address.PostalCode, retrievedUser.Address.PostalCode, "User address zip code should match")
			} else {
				assert.Nil(t, retrievedUser.Address, "User address should be nil")
			}
		})
	}

}
