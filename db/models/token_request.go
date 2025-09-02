package models

import (
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type tokenRequest struct {
	GrantType    utils.GrantType `json:"grant_type" schema:"grant_type" validate:"required,grant-type"`
	Code         *string         `json:"code" schema:"code" validate:"required_if=GrantType authorization_code"`
	RedirectURI  *string         `json:"redirect_uri" schema:"redirect_uri" validate:"required_if=GrantType authorization_code"`
	ClientID     string          `json:"client_id" schema:"client_id" validate:"required"`
	ClientSecret *string         `json:"client_secret" schema:"client_secret" validate:"required_without=CodeVerifier"`
	CodeVerifier *string         `json:"code_verifier" schema:"code_verifier" validate:"required_without=ClientSecret"`
	RefreshToken *string         `json:"refresh_token" schema:"refresh_token" validate:"required_if=GrantType refresh_token"`
	Scope        *[]utils.Scope  `json:"scope" schema:"scope" validate:"omitempty,dive,scope"`
}

func ParseTokenRequest(r *http.Request) (*tokenRequest, errors.HTTPError) {
	if r.Method != http.MethodPost {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     errors.METHOD_NOT_ALLOWED,
			Description: "Unsupported request method. Only POST is allowed.",
			Headers: map[string]string{
				"Allow": "POST",
			},
		}
	}

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "Content-Type must be application/x-www-form-urlencoded.",
		}
	}

	var tr tokenRequest
	decoder := utils.NewCustomDecoder()

	httpErr := errors.HTTPErrorResponse{
		StatusCode:  http.StatusBadRequest,
		Message:     errors.BAD_REQUEST,
		Description: "Invalid token request parameters.",
	}

	if err := decoder.Decode(&tr, r.PostForm); err != nil {
		log.Printf("Failed to decode token request parameters: %v", err)
		return nil, httpErr
	}

	clientId, clientSecret, ok := r.BasicAuth()

	if ok && clientId != "" {
		tr.ClientID = clientId
		tr.ClientSecret = &clientSecret
	}

	if err := tr.Validate(); err != nil {
		log.Printf("Token request validation error: %v", err)
		return nil, httpErr
	}

	return &tr, nil
}
