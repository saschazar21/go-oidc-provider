package models

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type OpenIDConfiguration struct {
	Issuer                                     string                   `json:"issuer" validate:"required,https_origin"`
	AuthorizationEndpoint                      string                   `json:"authorization_endpoint" validate:"required,https_url"`
	TokenEndpoint                              string                   `json:"token_endpoint" validate:"required,https_url"`
	TokenIntrospectionEndpoint                 string                   `json:"introspection_endpoint" validate:"omitempty,https_url"`
	UserInfoEndpoint                           string                   `json:"userinfo_endpoint,omitempty" validate:"omitempty,https_url"`
	JWKSURI                                    string                   `json:"jwks_uri" validate:"required,https_url"`
	RegistrationEndpoint                       string                   `json:"registration_endpoint,omitempty" validate:"omitempty,https_url"`
	EndSessionEndpoint                         string                   `json:"end_session_endpoint,omitempty" validate:"omitempty,https_url"`
	ScopesSupported                            []utils.Scope            `json:"scopes_supported" validate:"omitempty,dive,scope"`
	ResponseTypesSupported                     []utils.ResponseType     `json:"response_types_supported" validate:"contains-any=code,required,dive,response-type"`
	ResponseModesSupported                     []utils.ResponseMode     `json:"response_modes_supported" validate:"omitempty,dive,response-mode"`
	GrantTypesSupported                        []utils.GrantType        `json:"grant_types_supported" validate:"omitempty,dive,grant-type"`
	ACRValuesSupported                         []utils.ACR              `json:"acr_values_supported" validate:"omitempty,dive,acr"`
	SubjectTypesSupported                      []utils.SubjectType      `json:"subject_types_supported" validate:"required,dive,subject-type"`
	IDTokenSigningAlgValuesSupported           []utils.SigningAlgorithm `json:"id_token_signing_alg_values_supported" validate:"required,dive,jws,gt=0"`
	UserInfoSigningAlgValuesSupported          []utils.SigningAlgorithm `json:"userinfo_signing_alg_values_supported,omitempty" validate:"omitempty,dive,jws"`
	RequestObjectSigningAlgValuesSupported     []utils.SigningAlgorithm `json:"request_object_signing_alg_values_supported,omitempty" validate:"omitempty,dive,jws"`
	TokenEndpointAuthMethodsSupported          []utils.AuthMethod       `json:"token_endpoint_auth_methods_supported,omitempty" validate:"omitempty,dive,auth-method"`
	TokenEndpointAuthSigningAlgValuesSupported []utils.SigningAlgorithm `json:"token_endpoint_auth_signing_alg_values_supported,omitempty" validate:"omitempty,dive,jws"`
	DisplayValuesSupported                     []utils.Display          `json:"display_values_supported,omitempty" validate:"omitempty,dive,display"`
	ClaimTypesSupported                        []utils.ClaimType        `json:"claim_types_supported,omitempty" validate:"omitempty,dive,claim-type"`
	ClaimsSupported                            []string                 `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string                   `json:"service_documentation,omitempty" validate:"omitempty,url"`
	UILocalesSupported                         []string                 `json:"ui_locales_supported,omitempty" validate:"omitempty,dive,bcp47_language_tag"`
	ClaimsLocalesSupported                     []string                 `json:"claims_locales_supported,omitempty" validate:"omitempty,dive,bcp47_language_tag"`
	ClaimsParameterSupported                   *bool                    `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  *bool                    `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported               *bool                    `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestURIRegistration              *bool                    `json:"require_request_uri_registration,omitempty"`
	OPPolicyUri                                string                   `json:"op_policy_uri,omitempty" validate:"omitempty,url"`
	OPTosUri                                   string                   `json:"op_tos_uri,omitempty" validate:"omitempty,url"`

	// JWE is not supported yet
	IDTokenEncryptionAlgValuesSupported       []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported       []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoEncryptionAlgValuesSupported      []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoEncryptionEncValuesSupported      []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`
}

func replaceOrigin(uri string, origin *url.URL) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri // fail silently, as this will be caught in validation afterwards
	}

	u.Scheme = origin.Scheme
	u.Host = origin.Host
	return u.String()
}

func NewOpenIDConfiguration(customConfig ...*OpenIDConfiguration) (*OpenIDConfiguration, errors.HTTPError) {
	var config OpenIDConfiguration
	if len(customConfig) > 0 && customConfig[0] != nil {
		config = *customConfig[0]
	}

	// Override issuer to match settings from environment variables
	config.Issuer = os.Getenv(utils.ISSUER_URL_ENV)
	if config.Issuer == "" {
		config.Issuer = utils.GetDeploymentURL()
	}

	issuer, err := url.Parse(config.Issuer)
	if err != nil {
		msg := "Invalid issuer URL"
		log.Printf("%s: %v", msg, err)

		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	// Only change the origin of existing endpoints, let the validator to the rest.
	if config.AuthorizationEndpoint != "" {
		config.AuthorizationEndpoint = replaceOrigin(config.AuthorizationEndpoint, issuer)
	}

	if config.TokenEndpoint != "" {
		config.TokenEndpoint = replaceOrigin(config.TokenEndpoint, issuer)
	}

	if config.TokenIntrospectionEndpoint != "" {
		config.TokenIntrospectionEndpoint = replaceOrigin(config.TokenIntrospectionEndpoint, issuer)
	}

	if config.UserInfoEndpoint != "" {
		config.UserInfoEndpoint = replaceOrigin(config.UserInfoEndpoint, issuer)
	}

	if config.JWKSURI != "" {
		config.JWKSURI = replaceOrigin(config.JWKSURI, issuer)
	}

	if config.EndSessionEndpoint != "" {
		config.EndSessionEndpoint = replaceOrigin(config.EndSessionEndpoint, issuer)
	}

	// Set default values for required fields if they are not provided in the custom configuration
	if len(config.ScopesSupported) == 0 {
		config.ScopesSupported = []utils.Scope{utils.OPENID}
	}

	if len(config.ResponseModesSupported) == 0 {
		config.ResponseModesSupported = []utils.ResponseMode{utils.QUERY, utils.FRAGMENT}
	}

	if len(config.GrantTypesSupported) == 0 {
		config.GrantTypesSupported = []utils.GrantType{utils.AUTHORIZATION_CODE, utils.IMPLICIT}
	}

	if len(config.SubjectTypesSupported) == 0 {
		config.SubjectTypesSupported = []utils.SubjectType{utils.PUBLIC}
	}

	if len(config.ClaimTypesSupported) == 0 {
		config.ClaimTypesSupported = []utils.ClaimType{utils.CLAIM_TYPE_NORMAL}
	}

	if config.ClaimsParameterSupported == nil {
		b := false
		config.ClaimsParameterSupported = &b
	}

	if config.RequestParameterSupported == nil {
		b := false
		config.RequestParameterSupported = &b
	}

	if config.RequestURIParameterSupported == nil {
		b := true
		config.RequestURIParameterSupported = &b
	}

	if config.RequireRequestURIRegistration == nil {
		b := false
		config.RequireRequestURIRegistration = &b
	}

	// Validate the custom configuration
	if err := config.Validate(); err != nil {
		msg := "Invalid OpenID Configuration"

		log.Printf("%s: %v", msg, err)

		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	return &config, nil
}
