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

var INVALID_CLIENT_ID = "invalid client ID"
var INVALID_IP_ADDRESS = utils.EncryptedString("invalid_ip")

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
		Name            string
		Session         Session
		MutateUser      func(*User)
		WantErr         bool
		WantRetrieveErr bool
	}

	tests := []testStruct{
		{
			Name: "Minimal Session",
			Session: Session{
				UserID: user.ID,
			},
			WantErr:         false,
			WantRetrieveErr: false,
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
			WantErr:         false,
			WantRetrieveErr: false,
		},
		{
			Name: "Session with Invalid User",
			Session: Session{
				UserID: user.ID,
			},
			MutateUser: func(u *User) {
				isActive := false
				u.IsActive = &isActive
			},
			WantErr:         false,
			WantRetrieveErr: true,
		},
		{
			Name: "Session with Invalid Client",
			Session: Session{
				UserID:   user.ID,
				ClientID: &INVALID_CLIENT_ID,
			},
			WantErr:         true,
			WantRetrieveErr: true,
		},
		{
			Name: "Session with Invalid IP Address",
			Session: Session{
				UserID:    user.ID,
				ClientID:  &client.ID,
				IPAddress: &INVALID_IP_ADDRESS,
			},
			WantErr:         true,
			WantRetrieveErr: true,
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
				t.Fatalf("Save() error = %v, wantErr %v", err, tt.WantErr)
			}

			if tt.MutateUser != nil {
				updatedUser := user

				tt.MutateUser(&updatedUser)
				if err := updatedUser.Save(ctx, db); err != nil {
					t.Fatalf("Failed to save user: %v", err)
				}
			}

			retrievedSession, err := GetSessionByID(ctx, db, session.ID.String())
			if (err != nil) != tt.WantRetrieveErr {
				t.Fatalf("GetSessionByID() error = %v, wantRetrieveErr %v", err, tt.WantRetrieveErr)
			}

			if retrievedSession != nil {
				assert.Equal(t, session.ID, retrievedSession.ID, "Session ID mismatch")
				assert.Equal(t, session.UserID, retrievedSession.UserID, "User ID mismatch")
				assert.Equal(t, session.ClientID, retrievedSession.ClientID, "Client ID mismatch")
				assert.Equal(t, session.IPAddress, retrievedSession.IPAddress, "IP Address mismatch")
				assert.Equal(t, session.UserAgent, retrievedSession.UserAgent, "User Agent mismatch")
				assert.Equal(t, session.DeviceInfo, retrievedSession.DeviceInfo, "Device Info mismatch")
				assert.Equal(t, session.Scope, retrievedSession.Scope, "Scope mismatch")
				assert.Equal(t, session.ACRValues, retrievedSession.ACRValues, "ACR Values mismatch")
				assert.Equal(t, session.AMR, retrievedSession.AMR, "AMR mismatch")

				updatedRetrievedSession, err := GetSessionByID(ctx, db, retrievedSession.ID.String())
				if err != nil {
					t.Fatalf("GetSessionByID() after save error = %v", err)
				}

				assert.Equal(t, retrievedSession.ID, updatedRetrievedSession.ID, "Updated Session ID mismatch")
				assert.NotEqual(t, retrievedSession.UpdatedAt, updatedRetrievedSession.UpdatedAt, "UpdatedAt should have changed after save")
				assert.NotEqual(t, retrievedSession.LastAccessedAt, updatedRetrievedSession.LastAccessedAt, "LastAccessedAt should have changed after save")

				msg := "Test Logout"
				if err := LogoutSession(ctx, db, retrievedSession.ID.String(), &msg); err != nil {
					t.Fatalf("LogoutSession() error = %v", err)
				}

				_, err = GetSessionByID(ctx, db, retrievedSession.ID.String())
				if err == nil {
					t.Fatalf("GetSessionByID() after logout should have returned an error, got nil")
				}
			}
		})
	}
}
