package models

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestUser(t *testing.T) {
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

			var user User
			if err := test.LoadFixture(tt.TestFile, &user); err != nil {
				t.Fatalf("Failed to create user from file: %v", err)
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
			assert.Equal(t, *user.Email, *retrievedUser.Email, "User email should match")
			assert.NotNil(t, retrievedUser.EmailHash, "User email hash should not be nil")

			retrievedUserByEmail, err := GetUserByEmail(ctx, db, string(*user.Email))
			if err != nil {
				t.Fatalf("Failed to retrieve user by email: %v", err)
			}

			assert.Equal(t, user.ID, retrievedUserByEmail.ID, "User ID should match")
			assert.Equal(t, user.Email, retrievedUserByEmail.Email, "User email should match")

			if user.Address != nil {
				assert.NotNil(t, retrievedUser.Address, "User address should not be nil")
				assert.Equal(t, *user.Address.StreetAddress, *retrievedUser.Address.StreetAddress, "User address street should match")
				assert.Equal(t, *user.Address.Locality, *retrievedUser.Address.Locality, "User address city should match")
				assert.Equal(t, *user.Address.Region, *retrievedUser.Address.Region, "User address state should match")
				assert.Equal(t, *user.Address.PostalCode, *retrievedUser.Address.PostalCode, "User address zip code should match")
			} else {
				assert.Nil(t, retrievedUser.Address, "User address should be nil")
			}

			newEmail := utils.EncryptedString("admin@example.com")
			user.Email = &newEmail
			if err := user.Save(ctx, db); err != nil {
				t.Fatalf("Failed to update user email: %v", err)
			}

			updatedUser, err := GetUserByEmail(ctx, db, string(*user.Email))
			if err != nil {
				t.Fatalf("Failed to retrieve updated user by email: %v", err)
			}

			assert.Equal(t, user.ID, updatedUser.ID, "Updated user ID should match")
			assert.Equal(t, retrievedUser.ID, updatedUser.ID, "Retrieved user ID should match updated user ID")
			assert.Equal(t, *user.Email, *updatedUser.Email, "Updated user email should match")
			assert.NotEqual(t, retrievedUser.EmailHash, updatedUser.EmailHash, "Email hash should be updated after email change")
		})
	}
}

func TestInvalidUser(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name    string
		User    User
		WantErr bool
	}

	email := utils.EncryptedString("invalid-email")

	tests := []testStruct{
		{
			Name:    "Invalid User - Missing Email",
			User:    User{},
			WantErr: true,
		},
		{
			Name:    "Invalid User - Invalid Email",
			User:    User{Email: &email},
			WantErr: true,
		},
		{
			Name:    "Invalid User - Invalid ID",
			User:    User{ID: uuid.New()},
			WantErr: true,
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

			var user User
			if err := test.LoadFixture("user.json", &user); err != nil {
				t.Fatalf("Failed to create user from file: %v", err)
			}

			var email string
			if tt.User.Email != nil {
				email = string(*tt.User.Email)
			}
			if _, err := GetUserByEmail(ctx, db, email); err == nil {
				t.Fatalf("Expected error for invalid or empty email, but got none")
			}

			var uid string
			if tt.User.ID != uuid.Nil {
				uid = tt.User.ID.String()
			}
			if _, err := GetUserByID(ctx, db, uid); err == nil {
				t.Fatalf("Expected error for invalid user ID, but got none")
			}

			if err := tt.User.Save(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.WantErr)
			}
		})
	}
}
