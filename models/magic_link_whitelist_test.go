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

const MLW_SNAPSHOT_INIT = "magic_link_whitelist_init"

var MLW_INEXISTENT_USER = uuid.New()
var MLW_INVALID_EMAIL = utils.EncryptedString("invalid")
var MLW_VALID_EMAIL = utils.EncryptedString("test@example.com")
var MLW_REASON = "Test reason"
var MLW_NOTES = "Test notes"

func TestMagicLinkWhitelist(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create container: %v", err)
	}

	// Terminate the container after tests
	defer test.TerminateContainer(t, ctx, pgContainer)

	conn := db.Connect(ctx)

	var user User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(MLW_SNAPSHOT_INIT))

	type testStruct struct {
		Name               string
		MagicLinkWhitelist *MagicLinkWhitelist
		WantErr            bool
	}

	tests := []testStruct{
		{
			Name: "Valid Magic Link Whitelist Entry",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email: &MLW_VALID_EMAIL,
			},
			WantErr: false,
		},
		{
			Name: "Valid Magic Link Whitelist Entry with Reason and Notes",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email:  &MLW_VALID_EMAIL,
				Reason: &MLW_REASON,
				Notes:  &MLW_NOTES,
			},
			WantErr: false,
		},
		{
			Name: "Valid Magic Link Whitelist Entry with AddedBy",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email:     &MLW_VALID_EMAIL,
				AddedByID: &user.ID,
			},
			WantErr: false,
		},
		{
			Name: "Invalid Email Format",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email: &MLW_INVALID_EMAIL,
			},
			WantErr: true,
		},
		{
			Name: "Non-existent user",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email:     &MLW_VALID_EMAIL,
				AddedByID: &MLW_INEXISTENT_USER, // Non-existent user
			},
			WantErr: true,
		},
		{
			Name: "Missing Required Fields",
			MagicLinkWhitelist: &MagicLinkWhitelist{
				Email: nil, // Missing email
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

				pgContainer.Restore(ctx, postgres.WithSnapshotName(MLW_SNAPSHOT_INIT))
			})

			if db == nil {
				t.Fatal("Database connection is nil")
			}

			err := tt.MagicLinkWhitelist.Save(ctx, db)

			if (err != nil) != tt.WantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				retrievedEntry, err := GetMagicLinkWhitelistByEmail(ctx, db, string(MLW_VALID_EMAIL))

				if err != nil {
					t.Fatalf("GetMagicLinkWhitelistByEmail() error = %v", err)
				}

				assert.Equal(t, tt.MagicLinkWhitelist.Email, retrievedEntry.Email, "Email should match")
				assert.Equal(t, tt.MagicLinkWhitelist.ID, retrievedEntry.ID, "ID should match")

				if tt.MagicLinkWhitelist.AddedByID != nil {
					assert.NotNil(t, retrievedEntry.AddedBy, "AddedBy should be populated")
				} else {
					assert.Nil(t, retrievedEntry.AddedBy, "AddedBy should be nil")
				}

				if err := DeleteMagicLinkWhitelistByEmail(ctx, db, string(MLW_VALID_EMAIL)); err != nil {
					t.Fatalf("DeleteMagicLinkWhitelistByEmail() error = %v", err)
				}
			}
		})
	}
}
