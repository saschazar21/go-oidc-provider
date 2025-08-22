package models

import (
	"context"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const MLT_SNAPSHOT_INIT = "magic_link_token_init"

func TestMagicLinkToken(t *testing.T) {
	t.Setenv(test.ROOT_DIR_ENV, "../../")

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := loadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(MLT_SNAPSHOT_INIT))

	type testStruct struct {
		Name            string
		PreHook         func(*User) *User
		PostHook        func(*MagicLinkToken) (*MagicLinkToken, bool)
		WantErr         bool
		WantPostErr     bool
		WantRetrieveErr bool
	}

	tests := []testStruct{
		{
			Name:    "Valid Magic Link Token",
			WantErr: false,
		},
		{
			Name: "Invalidate user before saving token",
			PreHook: func(u *User) *User {
				isActive := false
				u.IsActive = &isActive
				return u
			},
			WantErr: true,
		},
		{
			Name: "Replace token to force mismatch",
			PostHook: func(mlt *MagicLinkToken) (*MagicLinkToken, bool) {
				token := utils.HashedString("invalid")
				mlt.Token = &token
				return mlt, false
			},
			WantErr:         false,
			WantPostErr:     false,
			WantRetrieveErr: true,
		},
		{
			Name: "Pre-Expire token",
			PostHook: func(mlt *MagicLinkToken) (*MagicLinkToken, bool) {
				exp := time.Now().Add(-1 * time.Hour)
				mlt.ExpiresAt = ExpiresAt{ExpiresAt: exp}
				return mlt, false
			},
			WantErr:         false,
			WantPostErr:     false,
			WantRetrieveErr: true,
		},
		{
			Name: "Pre-Consume token",
			PostHook: func(mlt *MagicLinkToken) (*MagicLinkToken, bool) {
				result := utils.SUCCESS
				mlt.Result = &result
				isActive := false
				mlt.IsActive = &isActive
				consumedAt := time.Now()
				mlt.ConsumedAt = &consumedAt
				return mlt, true
			},
			WantErr:     false,
			WantPostErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(MLT_SNAPSHOT_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			var mlt *MagicLinkToken
			var httpErr errors.HTTPError

			if tt.PreHook != nil {
				user = *tt.PreHook(&user)
				if err := user.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save user: %v", err)
				}
			}

			mlt, httpErr = CreateMagicLinkToken(ctx, db, string(*user.Email))
			if (httpErr != nil) != tt.WantErr {
				t.Fatalf("CreateMagicLinkToken() error = %v, wantErr %v", httpErr, tt.WantErr)
			}
			if httpErr != nil {
				return
			}
			if mlt == nil {
				t.Fatalf("CreateMagicLinkToken() returned nil MagicLinkToken")
			}

			if tt.PostHook != nil {
				var isDBUpdateRequired bool
				mlt, isDBUpdateRequired = tt.PostHook(mlt)

				if isDBUpdateRequired {
					intermediateMLT := *mlt
					intermediateMLT.Token = nil
					if err := intermediateMLT.save(ctx, db); err != nil {
						t.Fatalf("Failed to save modified MagicLinkToken: %v", err)
					}
				}
			}

			mlt, httpErr = ConsumeMagicLinkToken(ctx, db, mlt.ID.String(), string(*mlt.Token))
			if (httpErr != nil) != tt.WantPostErr {
				t.Fatalf("ConsumeMagicLinkToken() error = %v, wantErr %v", httpErr, tt.WantPostErr)
			}
			if httpErr != nil {
				return
			}
			if mlt == nil {
				t.Fatalf("ConsumeMagicLinkToken() returned nil MagicLinkToken")
			}

			retrievedMLT, httpErr := GetMagicLinkTokenByID(ctx, db, mlt.ID.String())
			if httpErr != nil {
				t.Fatalf("GetMagicLinkTokenByID() returned error = %v", httpErr)
			}
			if httpErr != nil {
				return
			}
			if retrievedMLT == nil {
				t.Fatalf("GetMagicLinkTokenByID() returned nil MagicLinkToken")
			}
		})
	}
}
