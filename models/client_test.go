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

func populateClientWithMandatoryDefaults(client *Client) {
	if len(client.RedirectURIs) == 0 {
		client.RedirectURIs = []string{"https://example.com/cb"}
	}

	if client.Name == "" {
		client.Name = "Test Client"
	}
}

func TestClient(t *testing.T) {
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
			Name:     "Minimal Client",
			TestFile: "client_minimal.json",
		},
		{
			Name:     "Full Client",
			TestFile: "client.json",
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
			if err := test.LoadFixture("user.json", &user); err != nil {
				t.Fatalf("Failed to create user from file: %v", err)
			}

			var client Client
			if err := test.LoadFixture(tt.TestFile, &client); err != nil {
				t.Fatalf("Failed to create client from file: %v", err)
			}

			if err := user.Save(ctx, db); err != nil {
				t.Fatalf("Failed to save user: %v", err)
			}

			client.OwnerID = user.ID
			if err := client.Save(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				if client.ID == "" {
					t.Errorf("Expected client ID to be set, got empty string")
				}

				var retrievedClient *Client

				if client.Secret != nil && *client.Secret != "" {
					retrievedClient, err = GetClientByIDAndSecret(ctx, db, client.ID, string(*client.Secret))
					if err != nil {
						t.Errorf("GetClientByIDAndSecret() error = %v", err)
					}
				} else {
					retrievedClient, err = GetClientByID(ctx, db, client.ID)
					if err != nil {
						t.Errorf("GetClientByID() error = %v", err)
					}
				}

				assert.Equal(t, client.ID, retrievedClient.ID, "Client ID should match")
				assert.Equal(t, client.Name, retrievedClient.Name, "Client name should match")
				assert.Equal(t, client.RedirectURIs, retrievedClient.RedirectURIs, "Redirect URIs should match")

				if client.IsConfidential != nil && (*client.IsConfidential) {
					newSecret, err := retrievedClient.NewSecret(ctx, db)

					if err != nil {
						t.Errorf("NewSecret() error = %v", err)
					}

					assert.NotNil(t, retrievedClient.Secret, "Confidential client should have a secret")
					assert.NotEmpty(t, *retrievedClient.Secret, "Client secret should not be empty")
					assert.NotEmpty(t, newSecret, "Newly generated client secret should not be empty")
					assert.Equal(t, *retrievedClient.Secret, utils.HashedString(newSecret), "Hashed secret should match the new secret")
				} else {
					assert.Nil(t, retrievedClient.Secret, "Non-confidential client should not have a secret")
				}
			}
		})
	}
}

func TestInvalidClient(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name    string
		Client  Client
		WantErr bool
	}

	boolTrue := true
	boolFalse := false
	hashedString := utils.HashedString("invalid-secret")

	tests := []testStruct{
		{
			Name: "Invalid Client ID",
			Client: Client{
				ID:             "invalid-id",
				IsConfidential: &boolTrue,
			},
			WantErr: true,
		},
		{
			Name: "Invalid Client Secret",
			Client: Client{
				ID:             "test-id",
				Secret:         &hashedString,
				IsConfidential: &boolFalse,
			},
			WantErr: true,
		},
		{
			Name: "Invalid Redirect URIs",
			Client: Client{
				RedirectURIs:   []string{"invalid-uri"},
				IsConfidential: &boolFalse,
			},
			WantErr: true,
		},
		{
			Name: "Invalid Owner ID",
			Client: Client{
				OwnerID: uuid.New(),
			},
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

			if err := user.Save(ctx, db); err != nil {
				t.Fatalf("Failed to save user: %v", err)
			}

			if tt.Client.ID != "" {
				if tt.Client.Secret != nil && *tt.Client.Secret != "" {
					if _, err := GetClientByIDAndSecret(ctx, db, tt.Client.ID, string(*tt.Client.Secret)); (err != nil) != tt.WantErr {
						t.Errorf("GetClientByIDAndSecret() error = %v, wantErr %v", err, tt.WantErr)
					}
				} else {
					if _, err := GetClientByID(ctx, db, tt.Client.ID); (err != nil) != tt.WantErr {
						t.Errorf("GetClientByID() error = %v, wantErr %v", err, tt.WantErr)
					}
				}
			} else {
				if _, err := GetClientByID(ctx, db, tt.Client.ID); err == nil {
					t.Errorf("GetClientByID() should have returned an error for empty client ID")
				}
			}

			if tt.Client.OwnerID == uuid.Nil {
				tt.Client.OwnerID = user.ID
			}

			populateClientWithMandatoryDefaults(&tt.Client)

			if err := tt.Client.Save(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if _, err := tt.Client.NewSecret(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("NewSecret() error = %v, wantErr %v", err, tt.WantErr)
			}
		})
	}
}
