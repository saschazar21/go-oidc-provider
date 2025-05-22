package test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestCreateContainer(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer TerminateContainer(t, ctx, pgContainer)

	type test struct {
		Name      string
		Statement string
		WantErr   bool
	}

	tests := []test{
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
			conn, err := pgx.Connect(ctx, os.Getenv(DB_URL_ENV))

			if err != nil {
				t.Fatalf("Failed to connect to container: %v", err)
			}

			t.Cleanup(func() {
				if err := conn.Close(ctx); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(SNAPSHOT_INIT))
			})

			// Execute the SQL statement
			_, err = conn.Exec(ctx, tt.Statement)
			if (err != nil) != tt.WantErr {
				t.Errorf("Expected error: %v, got: %v", tt.WantErr, err)
			}
		})
	}
}
