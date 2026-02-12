package models

import (
	"testing"

	"github.com/saschazar21/go-oidc-provider/utils"
)

func TestOpenIDConfiguration(t *testing.T) {

	type testCase struct {
		name    string
		config  OpenIDConfiguration
		wantErr bool
	}

	testCases := []testCase{
		{
			name: "minimal valid configuration",
			config: OpenIDConfiguration{
				Issuer:                           "https://example.com",
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				JWKSURI:                          "https://example.com/jwks",
				SubjectTypesSupported:            []utils.SubjectType{"public"},
				IDTokenSigningAlgValuesSupported: []utils.SigningAlgorithm{"RS256"},
				ResponseTypesSupported:           []utils.ResponseType{"code"},
			},
			wantErr: false,
		},
		{
			name: "valid configuration",
			config: OpenIDConfiguration{
				Issuer:                           "https://example.com",
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				JWKSURI:                          "https://example.com/jwks",
				SubjectTypesSupported:            []utils.SubjectType{"public"},
				IDTokenSigningAlgValuesSupported: []utils.SigningAlgorithm{"RS256"},
				ResponseTypesSupported:           []utils.ResponseType{"code", "id_token", "id_token token"},
			},
			wantErr: false,
		},
		{
			name: "invalid issuer URL",
			config: OpenIDConfiguration{
				Issuer:                           "http://example.com", // should be https
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				JWKSURI:                          "https://example.com/jwks",
				SubjectTypesSupported:            []utils.SubjectType{"public"},
				IDTokenSigningAlgValuesSupported: []utils.SigningAlgorithm{"RS256"},
				ResponseTypesSupported:           []utils.ResponseType{"code", "id_token", "id_token token"},
			},
			wantErr: true,
		},
		{
			name: "missing required fields",
			config: OpenIDConfiguration{
				Issuer:                 "https://example.com",
				AuthorizationEndpoint:  "https://example.com/authorize",
				TokenEndpoint:          "https://example.com/token",
				JWKSURI:                "https://example.com/jwks",
				ResponseTypesSupported: []utils.ResponseType{"code", "id_token", "id_token token"},
			},
			wantErr: true, // missing SubjectTypesSupported and IDTokenSigningAlgValuesSupported
		},
		{
			name: "missing response_type=code",
			config: OpenIDConfiguration{
				Issuer:                           "https://example.com",
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				JWKSURI:                          "https://example.com/jwks",
				SubjectTypesSupported:            []utils.SubjectType{"public"},
				IDTokenSigningAlgValuesSupported: []utils.SigningAlgorithm{"RS256"},
				ResponseTypesSupported:           []utils.ResponseType{"id_token", "id_token token"}, // missing "code"
			},
			wantErr: true,
		},
		{
			name: "invalid response type",
			config: OpenIDConfiguration{
				Issuer:                           "https://example.com",
				AuthorizationEndpoint:            "https://example.com/authorize",
				TokenEndpoint:                    "https://example.com/token",
				JWKSURI:                          "https://example.com/jwks",
				SubjectTypesSupported:            []utils.SubjectType{"public"},
				IDTokenSigningAlgValuesSupported: []utils.SigningAlgorithm{"RS256"},
				ResponseTypesSupported:           []utils.ResponseType{"invalid_response_type"},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.config.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
