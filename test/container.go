package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	DOCKER_IMAGE = "postgres:alpine"

	DB_NAME     = "testdb"
	DB_USER     = "testuser"
	DB_PASSWORD = "testpassword"

	DB_URL_ENV   = "DB_URL"
	ROOT_DIR_ENV = "ROOT_DIR"
	DEBUG_ENV    = "DEBUG"

	SNAPSHOT_INIT = "INIT"
)

func CreateContainer(t *testing.T, ctx context.Context) (pgContainer *postgres.PostgresContainer, err error) {
	rootDir, err := filepath.Abs("../")

	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if os.Getenv(ROOT_DIR_ENV) != "" {
		rootDir = os.Getenv(ROOT_DIR_ENV)
	}

	t.Logf("Attempting to load schema.sql from: %s", filepath.Join(rootDir, "./schema.sql"))

	// Create a new PostgreSQL container
	pgContainer, err = postgres.Run(ctx,
		DOCKER_IMAGE,
		testcontainers.WithCmd("postgres", "-c", "fsync=off"),
		postgres.WithInitScripts(filepath.Join(rootDir, "./schema.sql")),
		postgres.WithDatabase(DB_NAME),
		postgres.WithUsername(DB_USER),
		postgres.WithPassword(DB_PASSWORD),
		postgres.WithSQLDriver("pgx"),
		postgres.BasicWaitStrategies(),
	)

	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	if err := pgContainer.Snapshot(ctx, postgres.WithSnapshotName(SNAPSHOT_INIT)); err != nil {
		t.Fatalf("Failed to create snapshot: %v", err)
	}

	connString, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	t.Logf("Connection string: %s", connString)

	if err != nil {
		t.Fatalf("Failed to get connection string: %v", err)
	}

	t.Setenv(DB_URL_ENV, connString)
	t.Setenv(DEBUG_ENV, "2")
	t.Setenv("MASTER_KEY", TEST_MASTER_KEY)

	return
}

func TerminateContainer(t *testing.T, ctx context.Context, pgContainer *postgres.PostgresContainer) {
	if err := pgContainer.Terminate(ctx); err != nil {
		t.Fatalf("Failed to terminate container: %v", err)
	}
}
