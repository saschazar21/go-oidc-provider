package models

import (
	"context"
	"testing"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const SESSION_TEST_INIT = "session_test_init"

func TestSession(t *testing.T) {
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

	var client Client
	if err := loadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(SESSION_TEST_INIT))

	IPAddress := utils.EncryptedString("127.0.0.1")
	UserAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	DeviceInfo := "Windows 10, Chrome 91"
	Scope := []utils.Scope{"openid", "profile", "email"}
	ACRValues := []utils.ACR{"urn:mace:incommon:iap:silver"}
	AMR := []utils.AMR{"pwd", "otp"}

	type testStruct struct {
		Name    string
		Session Session
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Minimal Session",
			Session: Session{
				UserID: user.ID,
			},
			WantErr: false,
		},
		{
			Name: "Full Session",
			Session: Session{
				UserID:     user.ID,
				ClientID:   &client.ID,
				IPAddress:  &IPAddress,
				UserAgent:  &UserAgent,
				DeviceInfo: &DeviceInfo,
				Scope:      &Scope,
				ACRValues:  &ACRValues,
				AMR:        &AMR,
			},
			WantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			db := db.Connect(ctx)

			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Fatalf("Failed to close connection: %v", err)
				}

				pgContainer.Restore(ctx, postgres.WithSnapshotName(SESSION_TEST_INIT))
			})

			if db == nil {
				t.Fatalf("Failed to connect to database")
			}

			session := tt.Session
			if err := session.Save(ctx, db); (err != nil) != tt.WantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if !tt.WantErr {
				assert.NotEmpty(t, session.ID, "Session ID should not be empty after save")
				assert.NotEmpty(t, session.CreatedAt, "Session CreatedAt should not be empty after save")
				assert.NotEmpty(t, session.UpdatedAt, "Session UpdatedAt should not be empty after save")

				retrievedSession, err := GetSessionByID(ctx, db, session.ID.String())
				if err != nil {
					t.Fatalf("GetSessionByID() error = %v", err)
				}

				assert.Equal(t, session.ID, retrievedSession.ID, "Retrieved session ID should match saved session ID")
				assert.Equal(t, session.UserID, retrievedSession.UserID, "Retrieved session UserID should match saved session UserID")
				assert.NotNil(t, retrievedSession.User, "Retrieved session User should not be nil")

				if session.ClientID != nil {
					assert.Equal(t, *session.ClientID, *retrievedSession.ClientID, "Retrieved session ClientID should match saved session ClientID")
					assert.NotNil(t, retrievedSession.Client, "Retrieved session Client should not be nil")
				}

			} else {
				assert.Empty(t, session.ID, "Session ID should be empty if save fails")
			}
		})
	}
}
