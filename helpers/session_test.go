package helpers

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/test"
)

func TestSession(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

}
