package endpoints

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saschazar21/go-oidc-provider/test"
)

func TestJWKS(t *testing.T) {
	eddsa, err := test.LoadTextFixture("ed25519.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ed25519.pem: %v", err)
	}
	rsa, err := test.LoadTextFixture("rsa2048.pem", true)
	if err != nil {
		t.Fatalf("Failed to load rsa2048.pem: %v", err)
	}
	ecdsa, err := test.LoadTextFixture("ecdsa-p256.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ecdsa-p256.pem: %v", err)
	}

	type testStruct struct {
		Name           string
		Method         string
		Keys           *map[string]string // alg -> base64url encoded private key
		ExpectedStatus int
	}

	tests := []testStruct{
		{
			Name:           "No keys configured",
			Method:         "GET",
			Keys:           nil,
			ExpectedStatus: http.StatusInternalServerError,
		},
		{
			Name:   "Mixed symmetric and asymmetric keys configured",
			Method: "GET",
			Keys: &map[string]string{
				"HS256": "dGVzdAo=",
				"RS256": rsa,
				"ES256": ecdsa,
				"EdDSA": eddsa,
			},
			ExpectedStatus: http.StatusOK,
		},
		{
			Name:           "Wrong method used",
			Keys:           nil,
			Method:         "POST",
			ExpectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Keys != nil {
				for alg, key := range *tc.Keys {
					envVar := "KEY_" + alg
					t.Setenv(envVar, key)
				}
			}

			req := httptest.NewRequest(tc.Method, "/.well-known/jwks.json", nil)
			w := httptest.NewRecorder()

			HandleJWKS(w, req)

			if w.Code != tc.ExpectedStatus {
				t.Fatalf("Expected status %d, got %d", tc.ExpectedStatus, w.Code)
			}

			if w.Code == http.StatusOK {
				var resp struct {
					Keys []map[string]interface{} `json:"keys"`
				}

				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				// Count expected number of keys (only asymmetric)
				expectedKeyCount := 0
				if tc.Keys != nil {
					for alg := range *tc.Keys {
						if alg != "HS256" && alg != "HS384" && alg != "HS512" {
							expectedKeyCount++
						}
					}
				}

				if len(resp.Keys) != expectedKeyCount {
					t.Fatalf("Expected %d keys, got %d", expectedKeyCount, len(resp.Keys))
				}

				// Check that each key has required fields
				for _, key := range resp.Keys {
					if _, ok := key["kty"]; !ok {
						t.Errorf("Key missing 'kty' field: %v", key)
					}
					if _, ok := key["kid"]; !ok {
						t.Errorf("Key missing 'kid' field: %v", key)
					}
					if _, ok := key["alg"]; !ok {
						t.Errorf("Key missing 'alg' field: %v", key)
					}
					if _, ok := key["use"]; !ok {
						t.Errorf("Key missing 'use' field: %v", key)
					}
				}
			}
		})
	}
}
