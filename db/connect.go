package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/extra/bundebug"
)

func Connect(ctx context.Context) (db *bun.DB) {
	dsn := os.Getenv(DB_URL_ENV)

	if dsn == "" {
		log.Fatalf("DB_URL env is not set!")
	}

	config, err := pgx.ParseConfig(dsn)

	if err != nil {
		log.Fatalf("failed to parse DSN: %v", err)
	}

	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	sqlDb := stdlib.OpenDB(*config)
	db = bun.NewDB(sqlDb, pgdialect.New())
	db.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithEnabled(false),
		bundebug.FromEnv(test.DEBUG_ENV),
	))

	return
}
