package oidc

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
)

type openidConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}

func (o *openidConfiguration) GetAuthorizationEndpoint() *url.URL {
	authorizationEndpoint, err := url.Parse(o.AuthorizationEndpoint)
	if err != nil {
		log.Printf("failed to parse authorization endpoint URL: %v", err)
		return nil
	}
	return authorizationEndpoint
}

func (o openidConfiguration) String() string {
	return "openidConfiguration{" +
		"Issuer: " + o.Issuer +
		", AuthorizationEndpoint: " + o.AuthorizationEndpoint +
		", TokenEndpoint: " + o.TokenEndpoint +
		", UserinfoEndpoint: " + o.UserinfoEndpoint +
		", JwksURI: " + o.JwksURI +
		"}"
}

func FetchOpenIDConfiguration() (*openidConfiguration, error) {
	// Implementation to fetch and parse the OpenID configuration from the issuer's well-known URL
	issuerURL := getIssuerURL()
	if issuerURL == nil {
		return nil, nil
	}
	issuerURL.Path = "/.well-known/openid-configuration"

	// Fetch the configuration using a HTTP GET request
	// Parse the JSON response into the openidConfiguration struct
	// Return the struct and any error encountered
	resp, err := http.Get(issuerURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config openidConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
