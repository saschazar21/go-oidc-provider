package models

import "github.com/saschazar21/go-oidc-provider/utils"

type TokenRequest struct {
	GrantType    utils.GrantType `json:"grant_type" schema:"grant_type" validate:"required,grant-type"`
	Code         *string         `json:"code" schema:"code" validate:"required_if=GrantType authorization_code"`
	RedirectURI  *string         `json:"redirect_uri" schema:"redirect_uri" validate:"required_if=GrantType authorization_code"`
	ClientID     string          `json:"client_id" schema:"client_id" validate:"required"`
	ClientSecret *string         `json:"client_secret" schema:"client_secret" validate:"required_without=CodeVerifier"`
	CodeVerifier *string         `json:"code_verifier" schema:"code_verifier" validate:"required_without=ClientSecret"`
	RefreshToken *string         `json:"refresh_token" schema:"refresh_token" validate:"required_if=GrantType refresh_token"`
	Scope        *[]utils.Scope  `json:"scope" schema:"scope" validate:"omitempty,dive,scope"`
}
