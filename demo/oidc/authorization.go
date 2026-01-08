package oidc

import (
	"log"
	"os"

	"github.com/gorilla/schema"
)

type oidcAuthorizationRequest struct {
	ClientID     string `json:"client_id" schema:"client_id"`
	RedirectURI  string `json:"redirect_uri" schema:"redirect_uri"`
	ResponseType string `json:"response_type" schema:"response_type"`
	Scope        string `json:"scope" schema:"scope"`
	State        string `json:"state" schema:"state"`
	Nonce        string `json:"nonce" schema:"nonce"`
}

func (r *oidcAuthorizationRequest) WithClientID(clientID string) *oidcAuthorizationRequest {
	r.ClientID = clientID
	return r
}

func (r *oidcAuthorizationRequest) WithResponseType(responseType string) *oidcAuthorizationRequest {
	r.ResponseType = responseType
	return r
}

func (r *oidcAuthorizationRequest) WithScope(scope string) *oidcAuthorizationRequest {
	r.Scope = scope
	return r
}

func (r *oidcAuthorizationRequest) BuildURL() string {
	configuration, err := FetchOpenIDConfiguration()
	if err != nil || configuration == nil {
		log.Printf("failed to fetch OpenID configuration: %v", err)
		return ""
	}
	authorizationEndpoint := configuration.GetAuthorizationEndpoint()
	if authorizationEndpoint == nil {
		log.Println("authorization endpoint is nil")
		return ""
	}
	q := authorizationEndpoint.Query()

	encoder := schema.NewEncoder()
	err = encoder.Encode(r, q)
	if err != nil {
		log.Printf("failed to encode OIDC request parameters: %v", err)
		return ""
	}
	authorizationEndpoint.RawQuery = q.Encode()
	return authorizationEndpoint.String()
}

func (r oidcAuthorizationRequest) String() string {
	return "oidcAuthorizationRequest{" +
		"ClientID: " + r.ClientID +
		", RedirectURI: " + r.RedirectURI +
		", ResponseType: " + r.ResponseType +
		", Scope: " + r.Scope +
		", State: " + r.State +
		", Nonce: " + r.Nonce +
		"}"
}

func NewOIDCAuthorizationRequest() *oidcAuthorizationRequest {
	return &oidcAuthorizationRequest{
		ClientID:     os.Getenv(OIDC_CLIENT_ID_ENV),
		RedirectURI:  GetCallbackURL(),
		ResponseType: "code",
		Scope:        "openid",
		State:        RandomString(DEFAULT_RANDOM_STRING_LENGTH),
		Nonce:        RandomString(DEFAULT_RANDOM_STRING_LENGTH),
	}
}

type OIDCAuthorizationResponse struct {
	Code  string `schema:"code"`
	State string `schema:"state"`
}

func (r OIDCAuthorizationResponse) String() string {
	return "oidcAuthorizationResponse{" +
		"Code: " + r.Code +
		", State: " + r.State +
		"}"
}
