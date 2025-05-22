package db

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestConnect(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)

	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	type testStruct struct {
		Name      string
		Statement string
		WantErr   bool
	}

	tests := []testStruct{
		{
			Name:      "Test 1",
			Statement: "SELECT 1",
			WantErr:   false,
		},
		{
			Name:      "Insert user",
			Statement: "INSERT INTO oidc_users (email, email_hash) VALUES ('admin@localhost', 'hash') RETURNING user_id",
			WantErr:   false,
		},
		{
			Name:      "Insert client",
			Statement: "INSERT INTO oidc_clients (client_name, client_secret, redirect_uris) VALUES ('test-client', 'test-secret', ARRAY['https://example.com/cb']) RETURNING client_id",
			WantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(test.SNAPSHOT_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			_, err = db.NewRaw(tt.Statement).Exec(ctx)

			if (err != nil) != tt.WantErr {
				t.Errorf("Connect() error = %v, wantErr %v", err, tt.WantErr)
			}
		})
	}
}
