package models

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestAuthorization(t *testing.T) {
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
		{
			Name:        "Approved Authorization",
			TestFile:    "authorization_approved.json",
			WantsClient: true,
			WantsUser:   true,
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
			if err := test.LoadFixture("user.json", &user); err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			if err := user.Save(ctx, conn); err != nil {
				t.Fatalf("Failed to save user: %v", err)
			}

			var client Client
			if err := test.LoadFixture("client_minimal.json", &client); err != nil {
				t.Fatalf("Failed to load fixture: %v", err)
			}

			client.OwnerID = user.ID
			if err := client.Save(ctx, conn); err != nil {
				t.Fatalf("Failed to save client: %v", err)
			}

			var authorization Authorization
			if err := test.LoadFixture(tt.TestFile, &authorization); err != nil {
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

			if !tt.WantErr && tt.WantsUser {
				assert.NotEmpty(t, authorization.ID, "Authorization ID should not be empty after save")
				assert.Empty(t, authorization.ReplacedID, "Replaced ID should be empty for new authorizations")

				newAuthorization := authorization
				newAuthorization.ID = uuid.UUID{}

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

				var fetchedById *Authorization
				var fetchedByClientAndUser *Authorization

				if fetchedById, err = GetAuthorizationByID(ctx, conn, newAuthorization.ID.String()); err != nil {
					t.Errorf("GetAuthorizationById() error = %v", err)
				}

				if fetchedByClientAndUser, err = GetAuthorizationByClientAndUser(ctx, conn, newAuthorization.ClientID, newAuthorization.UserID); err != nil {
					t.Errorf("GetAuthorizationByClientAndUser() error = %v", err)
				}

				assert.NotNil(t, fetchedById)
				assert.NotNil(t, fetchedByClientAndUser)
				assert.Equal(t, fetchedByClientAndUser.ID, fetchedById.ID)
				assert.Equal(t, fetchedByClientAndUser.ClientID, newAuthorization.ClientID)

				/* manually delete newly stored authorization to trigger error while updating */
				var result sql.Result
				if result, err = conn.NewDelete().Model((*Authorization)(nil)).Where("authorization_id = ?", newAuthorization.ID).Exec(ctx); err != nil {
					t.Errorf("Delete() error = %v", err)
				}
				if rows, err := result.RowsAffected(); rows == 0 || err != nil {
					t.Errorf("Delete() wanted 1 affected row, received %d rows, error %v", rows, err)
				}

				if err := newAuthorization.Save(ctx, conn); err == nil {
					t.Errorf("Save() wanted error after delete, received nil")
				}
			}
		})
	}
}

func TestGetAuthorizationByID(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var existingAuth Authorization
	if err := test.LoadFixture("authorization_pending.json", &existingAuth); err != nil {
		t.Errorf("test.LoadFixture() error = %v", err)
	}

	existingAuth.ID = uuid.New()
	existingAuth.ExpiresAt.ExpiresAt = time.Now().UTC().Add(time.Minute * 10)

	type testStruct struct {
		name          string
		authorization *Authorization
		clientFixture string
		id            string
		wantErr       bool
	}

	tests := []testStruct{
		{
			name:          "Empty ID",
			authorization: nil,
			clientFixture: "client_minimal.json",
			id:            "",
			wantErr:       true,
		},
		{
			name:          "Nil UUID ID",
			authorization: nil,
			clientFixture: "client_minimal.json",
			id:            uuid.Nil.String(),
			wantErr:       true,
		},
		{
			name:          "Non-existing ID",
			authorization: nil,
			clientFixture: "client_minimal.json",
			id:            "bb792595-be1f-4e1e-9856-c70c2f8e9d4c",
			wantErr:       true,
		},
		{
			name:          "Existing ID",
			authorization: &existingAuth,
			clientFixture: "client_minimal.json",
			id:            existingAuth.ID.String(),
			wantErr:       false,
		},
		{
			name:          "Existing ID",
			authorization: &existingAuth,
			clientFixture: "client.json",
			id:            existingAuth.ID.String(),
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(test.SNAPSHOT_INIT))
			})

			if tt.authorization != nil {
				var user User
				if err := test.LoadFixture("user.json", &user); err != nil {
					t.Fatalf("Failed to load fixture: %v", err)
				}

				if err := user.Save(ctx, conn); err != nil {
					t.Fatalf("Failed to save user: %v", err)
				}

				var client Client
				if err := test.LoadFixture(tt.clientFixture, &client); err != nil {
					t.Fatalf("Failed to load fixture: %v", err)
				}

				client.OwnerID = user.ID
				if err := client.Save(ctx, conn); err != nil {
					t.Fatalf("Failed to save client: %v", err)
				}

				tt.authorization.ClientID = client.ID
				if _, err := conn.NewInsert().Model(tt.authorization).Exec(ctx, tt.authorization); err != nil {
					t.Errorf("Save() error = %v", err)
				}
			}

			if _, err := GetAuthorizationByID(ctx, conn, tt.id); (err != nil) != tt.wantErr {
				t.Errorf("GetAuthorizationByID() error = %v", err)
			}
		})
	}
}

func TestGetAuthorizationByClientAndUser(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var existingAuth Authorization
	if err := test.LoadFixture("authorization_approved.json", &existingAuth); err != nil {
		t.Errorf("test.LoadFixture() error = %v", err)
	}

	existingAuth.ID = uuid.New()
	existingAuth.ExpiresAt.ExpiresAt = time.Now().UTC().Add(time.Minute * 10)

	inactiveAuth := existingAuth
	inactiveAuth.IsActive = false

	type testStruct struct {
		name          string
		authorization *Authorization
		client        string
		user          uuid.UUID
		wantErr       bool
	}

	tests := []testStruct{
		{
			name:          "Empty client and user",
			authorization: nil,
			client:        "",
			user:          uuid.Nil,
			wantErr:       true,
		},
		{
			name:          "Empty client and inexisting user",
			authorization: nil,
			client:        "",
			user:          uuid.New(),
			wantErr:       true,
		},
		{
			name:          "Inexisting client and empty user",
			authorization: nil,
			client:        "bb792595-be1f-4e1e-9856-c70c2f8e9d4c",
			user:          uuid.Nil,
			wantErr:       true,
		},
		{
			name:          "Inexisting client and inexisting user",
			authorization: nil,
			client:        "bb792595-be1f-4e1e-9856-c70c2f8e9d4c",
			user:          uuid.New(),
			wantErr:       true,
		},
		{
			name:          "Inactive authorization",
			authorization: &inactiveAuth,
			client:        "",
			user:          uuid.Nil,
			wantErr:       true,
		},
		{
			name:          "Existing authorization",
			authorization: &existingAuth,
			client:        "",       // will be set once client is saved
			user:          uuid.Nil, // will be set once user is saved
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Errorf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(test.SNAPSHOT_INIT))
			})

			if tt.authorization != nil {
				var user User
				if err := test.LoadFixture("user.json", &user); err != nil {
					t.Fatalf("Failed to load fixture: %v", err)
				}

				if err := user.Save(ctx, conn); err != nil {
					t.Fatalf("Failed to save user: %v", err)
				}

				var client Client
				if err := test.LoadFixture("client_minimal.json", &client); err != nil {
					t.Fatalf("Failed to load fixture: %v", err)
				}

				client.OwnerID = user.ID
				if err := client.Save(ctx, conn); err != nil {
					t.Fatalf("Failed to save client: %v", err)
				}

				tt.authorization.ClientID = client.ID
				tt.authorization.UserID = user.ID

				tt.client = client.ID
				tt.user = user.ID

				if _, err := conn.NewInsert().Model(tt.authorization).Exec(ctx, tt.authorization); err != nil {
					t.Errorf("Save() error = %v", err)
				}
			}

			if _, err := GetAuthorizationByClientAndUser(ctx, conn, tt.client, tt.user); (err != nil) != tt.wantErr {
				t.Errorf("GetAuthorizationByClientAndUser() error = %v", err)
			}
		})
	}
}
