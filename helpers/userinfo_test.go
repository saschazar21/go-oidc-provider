package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	UI_SNAPSHOT_INIT = "userinfo_init"
)

func TestHandleUserinfoRequest(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://localhost:8080")
	t.Setenv("KEY_HS256", "c2VjcmV0Cg==")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create test container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("failed to load authorization fixture: %v", err)
	}

	conn := db.Connect(ctx)

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	auth.UserID = user.ID
	auth.ClientID = client.ID
	auth.User = &user
	auth.Client = &client
	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("failed to save authorization: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(UI_SNAPSHOT_INIT))

	type testStruct struct {
		name    string
		preHook func(ctx context.Context, db bun.IDB) string
		method  string
		wantErr bool
	}

	tests := []testStruct{
		{
			name: "Valid access token",
			preHook: func(ctx context.Context, db bun.IDB) string {
				token, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &auth)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				return string(token.Value)
			},
			method:  http.MethodGet,
			wantErr: false,
		},
		{
			name: "Valid JWT access token",
			preHook: func(ctx context.Context, db bun.IDB) string {
				jwtToken, err := idtoken.NewSignedJWTFromAuthorization(&auth)
				if err != nil {
					t.Fatalf("Failed to create JWT access token: %v", err)
				}

				return jwtToken
			},
			method:  http.MethodPost,
			wantErr: false,
		},
		{
			name: "Invalid access token",
			preHook: func(ctx context.Context, db bun.IDB) string {
				return "invalidtokenvalue"
			},
			method:  http.MethodGet,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				if err := conn.Close(); err != nil {
					t.Fatalf("Failed to close database connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(UI_SNAPSHOT_INIT))
			})

			bearer := tt.preHook(ctx, conn)

			req := httptest.NewRequest(tt.method, "https://localhost:8080/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+bearer)

			u, err := HandleUserinfoRequest(ctx, conn, req)
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleUserinfoRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				mappedUser := user.GetClaimsBasedOnScopes(auth.Scope)
				assert.Equal(t, mappedUser.ID, u.ID, "Returned user ID does not match expected user ID")
				assert.Equal(t, *mappedUser.Name, *u.Name, "Returned user Name does not match expected user Name")
			}
		})
	}
}
