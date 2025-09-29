package idtoken

import (
	"context"
	"testing"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
)

const (
	JWT_TEST_INIT = "jwt_test_init"
)

func TestJWT(t *testing.T) {
	t.Setenv("ISSUER_URL", "http://localhost:8080")

	es256, err := test.LoadTextFixture("ecdsa-p256.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ecdsa-p256.pem: %v", err)
	}
	eddsa, err := test.LoadTextFixture("ed25519.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ed25519.pem: %v", err)
	}
	rs256, err := test.LoadTextFixture("rsa2048.pem", true)
	if err != nil {
		t.Fatalf("Failed to load rsa2048.pem: %v", err)
	}

	t.Setenv("KEY_ES256", es256)
	t.Setenv("KEY_HS256", "dGVzdAo=")
	t.Setenv("KEY_EdDSA", eddsa)
	t.Setenv("KEY_RS256", rs256)

	ctx := context.Background()

	pgContainer, err := test.CreateContainer(t, ctx)
	if err != nil {
		t.Fatalf("Failed to create PostgreSQL container: %v", err)
	}
	defer pgContainer.Terminate(ctx)

	conn := db.Connect(ctx)

	var user models.User
	if err := test.LoadFixture("user_address.json", &user); err != nil {
		t.Fatalf("Failed to load user fixture: %v", err)
	}

	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to load client fixture: %v", err)
	}

	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("Failed to load authorization fixture: %v", err)
	}

	if err := user.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save user fixture: %v", err)
	}

	client.OwnerID = user.ID
	if err := client.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save client fixture: %v", err)
	}

	auth.UserID = user.ID
	auth.User = &user
	auth.ClientID = client.ID
	auth.Client = &client
	if err := auth.Save(ctx, conn); err != nil {
		t.Fatalf("Failed to save authorization fixture: %v", err)
	}

	conn.Close()

	pgContainer.Snapshot(ctx, postgres.WithSnapshotName(JWT_TEST_INIT))

	type testStruct struct {
		Name       string
		PreHook    func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token
		WantScopes []utils.Scope
		WantErr    bool
	}

	tests := []testStruct{
		{
			Name: "Valid JWT and ES256",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				alg := utils.SigningAlgorithm("ES256")
				// Create a valid access token
				client := client // create a copy to avoid modifying the original
				client.IDTokenSignedResponseAlg = &alg
				authorization := auth // create a copy to avoid modifying the original
				authorization.Client = &client
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID, utils.PROFILE, utils.EMAIL, utils.ADDRESS, utils.PHONE},
			WantErr:    false,
		},
		{
			Name: "Valid JWT with minimal scopes and HS256",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				alg := utils.SigningAlgorithm("HS256")
				// Create a valid access token
				client := client // create a copy to avoid modifying the original
				client.IDTokenSignedResponseAlg = &alg
				authorization := auth // create a copy to avoid modifying the original
				authorization.Client = &client
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID},
			WantErr:    false,
		},
		{
			Name: "Valid JWT with minimal scopes and EdDSA",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				alg := utils.SigningAlgorithm("EdDSA")
				// Create a valid access token
				client := client // create a copy to avoid modifying the original
				client.IDTokenSignedResponseAlg = &alg
				authorization := auth // create a copy to avoid modifying the original
				authorization.Client = &client
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID},
			WantErr:    false,
		},
		{
			Name: "Valid JWT with alg=none",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				alg := utils.SigningAlgorithm("none")
				// Create a valid access token
				client := client // create a copy to avoid modifying the original
				client.IDTokenSignedResponseAlg = &alg
				authorization := auth // create a copy to avoid modifying the original
				authorization.Client = &client
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID},
			WantErr:    false,
		},
		{
			Name: "Valid JWT with minimal scopes and authorization_code",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				// Create a valid access token
				authorization := auth // create a copy to avoid modifying the original
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken

				// Create a valid authorization code
				authCode, err := models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create authorization code: %v", err)
				}
				tokens[utils.AUTHORIZATION_CODE_TYPE] = authCode

				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID},
			WantErr:    false,
		},
		{
			Name: "Using default signing key",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				// Create a valid access token
				authorization := auth // create a copy to avoid modifying the original
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				accessToken.CreatedAt.CreatedAt = time.Now().UTC().Add(-5 * time.Second) // backdate to avoid timing issues with iat & nbf
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID, utils.PROFILE},
			WantErr:    false,
		},
		{
			Name: "Missing access token",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				// Create a refresh token only
				authorization := auth // create a copy to avoid modifying the original
				authorization.Scope = scopes
				refreshToken, err := models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create refresh token: %v", err)
				}
				tokens[utils.REFRESH_TOKEN_TYPE] = refreshToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID, utils.PROFILE},
			WantErr:    true,
		},
		{
			Name: "Unsupported signing algorithm",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				tokens := make(map[utils.TokenType]*models.Token)
				alg := utils.SigningAlgorithm("HS512") // not configured
				// Create a valid access token
				client := client // create a copy to avoid modifying the original
				client.IDTokenSignedResponseAlg = &alg
				authorization := auth // create a copy to avoid modifying the original
				authorization.Client = &client
				authorization.Scope = scopes
				accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), &authorization)
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}
				tokens[utils.ACCESS_TOKEN_TYPE] = accessToken
				return &tokens
			},
			WantScopes: []utils.Scope{utils.OPENID, utils.PROFILE},
			WantErr:    false,
		},
		{
			Name: "No tokens provided",
			PreHook: func(ctx context.Context, db bun.IDB, scopes ...utils.Scope) *map[utils.TokenType]*models.Token {
				return &map[utils.TokenType]*models.Token{}
			},
			WantScopes: []utils.Scope{utils.OPENID, utils.PROFILE},
			WantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			conn := db.Connect(ctx)

			t.Cleanup(func() {
				conn.Close()
				pgContainer.Restore(ctx, postgres.WithSnapshotName(JWT_TEST_INIT))
			})

			var tokens *map[utils.TokenType]*models.Token
			if tt.PreHook != nil {
				tokens = tt.PreHook(ctx, conn, tt.WantScopes...)
			}

			jwt, err := NewSignedJWT(tokens)
			if (err != nil) != tt.WantErr {
				t.Errorf("NewSignedJWT() error = %v, wantErr %v", err, tt.WantErr)
				return
			}

			if !tt.WantErr {
				assert.NotEmpty(t, jwt, "Expected non-empty JWT")
				if (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.Client.IDTokenSignedResponseAlg != nil && *(*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.Client.IDTokenSignedResponseAlg == "none" {
					return // skip further checks for alg=none
				}

				claims, err := ParseJWT(jwt)
				if err != nil {
					t.Fatalf("ParseJWT() error = %v", err)
				}

				subject, err := claims.GetSubject()
				if err != nil {
					t.Fatalf("GetSubject() error = %v", err)
				}
				assert.Equal(t, (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.UserID.String(), subject, "Expected subject to match user ID")
				assert.Equal(t, client.ID, claims.Audience[0], "Expected audience to match client ID")
				assert.Equal(t, "http://localhost:8080", claims.Issuer, "Expected issuer to match")
				assert.Equal(t, (*tokens)[utils.ACCESS_TOKEN_TYPE].CreatedAt.CreatedAt.Unix(), time.Time(claims.IssuedAt).Unix(), "Expected created_at to match")
				assert.Equal(t, (*tokens)[utils.ACCESS_TOKEN_TYPE].CreatedAt.CreatedAt.Add(time.Duration(client.IDTokenLifetime)*time.Second).Unix(), time.Time(claims.ExpiresAt).Unix(), "Expected expires_at to match")
				assert.ElementsMatch(t, (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.Scope, claims.Scope, "Expected scopes to match")

				if _, ok := (*tokens)[utils.ACCESS_TOKEN_TYPE]; ok {
					assert.NotEmpty(t, claims.AccessTokenHash, "Expected at_hash to be set")
				}

				if _, ok := (*tokens)[utils.AUTHORIZATION_CODE_TYPE]; ok {
					assert.NotEmpty(t, claims.CodeHash, "Expected c_hash to be set")
				}

				for _, scope := range tt.WantScopes {
					switch scope {
					case utils.EMAIL:
						assert.Equal(t, user.Email, claims.Email, "Expected email to match")
						assert.Equal(t, user.IsEmailVerified, claims.IsEmailVerified, "Expected email_verified to match")
					case utils.PHONE:
						assert.Equal(t, user.PhoneNumber, claims.PhoneNumber, "Expected phone_number to match")
						assert.Equal(t, user.IsPhoneNumberVerified, claims.IsPhoneNumberVerified, "Expected phone_number_verified to match")
					case utils.ADDRESS:
						if user.Address != nil {
							assert.Equal(t, user.Address.Formatted, claims.Address.Formatted, "Expected address.formatted to match")
							assert.Equal(t, user.Address.StreetAddress, claims.Address.StreetAddress, "Expected address.street_address to match")
							assert.Equal(t, user.Address.Locality, claims.Address.Locality, "Expected address.locality to match")
							assert.Equal(t, user.Address.Region, claims.Address.Region, "Expected address.region to match")
						}
					case utils.PROFILE:
						assert.Equal(t, user.Name, claims.Name, "Expected name to match")
						assert.Equal(t, user.GivenName, claims.GivenName, "Expected given_name to match")
						assert.Equal(t, user.FamilyName, claims.FamilyName, "Expected family_name to match")
						assert.Equal(t, user.MiddleName, claims.MiddleName, "Expected middle_name to match")
						assert.Equal(t, user.Nickname, claims.Nickname, "Expected nickname to match")
						assert.Equal(t, user.PreferredUsername, claims.PreferredUsername, "Expected preferred_username to match")
						assert.Equal(t, user.Profile, claims.Profile, "Expected profile to match")
						assert.Equal(t, user.Picture, claims.Picture, "Expected picture to match")
						assert.Equal(t, user.Website, claims.Website, "Expected website to match")
						assert.Equal(t, user.Birthdate, claims.Birthdate, "Expected birthdate to match")
						assert.Equal(t, user.Gender, claims.Gender, "Expected gender to match")
						assert.Equal(t, user.Zoneinfo, claims.Zoneinfo, "Expected zoneinfo to match")
						assert.Equal(t, user.Locale, claims.Locale, "Expected locale to match")
						assert.Equal(t, user.UpdatedAt.UpdatedAt.UTC().Unix(), claims.UpdatedAt.Unix(), "Expected updated_at to match")
					}
				}
			}
		})
	}
}
