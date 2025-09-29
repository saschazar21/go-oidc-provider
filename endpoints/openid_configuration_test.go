package endpoints

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
)

func TestHandleOpenIDConfiguration(t *testing.T) {
	t.Setenv("ISSUER_URL", "https://example.com")

	rs256, err := test.LoadTextFixture("rsa2048.pem", true)
	if err != nil {
		t.Fatalf("Failed to load rsa2048.pem: %v", err)
	}
	es256, err := test.LoadTextFixture("ecdsa-p256.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ecdsa-p256.pem: %v", err)
	}
	eddsa, err := test.LoadTextFixture("ed25519.pem", true)
	if err != nil {
		t.Fatalf("Failed to load ed25519.pem: %v", err)
	}

	type testStruct struct {
		Name           string
		Method         string
		Keys           *map[string]string // alg -> base64url encoded private key
		ExpectedStatus int
		ExpectedAlgs   []string
	}

	tests := []testStruct{
		{
			Name:   "Mixed symmetric and asymmetric keys configured",
			Method: "GET",
			Keys: &map[string]string{
				"HS256": "dGVzdAo=",
				"RS256": rs256,
				"ES256": es256,
				"EdDSA": eddsa,
			},
			ExpectedStatus: http.StatusOK,
			ExpectedAlgs:   []string{"RS256", "ES256", "HS256", "EdDSA"},
		},
		{
			Name:           "Wrong method used",
			Keys:           nil,
			Method:         "POST",
			ExpectedStatus: http.StatusMethodNotAllowed,
			ExpectedAlgs:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Keys != nil {
				t.Setenv("KEY_HS256", (*tc.Keys)["HS256"])
				t.Setenv("KEY_RS256", (*tc.Keys)["RS256"])
				t.Setenv("KEY_ES256", (*tc.Keys)["ES256"])
				t.Setenv("KEY_EdDSA", (*tc.Keys)["EdDSA"])
			}
			req := httptest.NewRequest(tc.Method, "/.well-known/openid-configuration", nil)
			w := httptest.NewRecorder()

			HandleOpenIDConfiguration(w, req)
			res := w.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.ExpectedStatus {
				t.Errorf("Expected status %d, got %d", tc.ExpectedStatus, res.StatusCode)
			}

			if res.StatusCode == http.StatusOK {
				var config models.OpenIDConfiguration
				if err := json.NewDecoder(res.Body).Decode(&config); err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}

				if config.JWKSURI == "" {
					t.Error("Expected JWKS URI to be set")
				}

				if len(config.IDTokenSigningAlgValuesSupported) != len(tc.ExpectedAlgs) {
					t.Errorf("Expected %d signing algorithms, got %d", len(tc.ExpectedAlgs), len(config.IDTokenSigningAlgValuesSupported))
				} else {
					for _, alg := range tc.ExpectedAlgs {
						found := false
						for _, supportedAlg := range config.IDTokenSigningAlgValuesSupported {
							if alg == string(supportedAlg) {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("Expected signing algorithm %s to be supported, but it was not found", alg)
						}
					}
				}
			}
		})
	}
}
