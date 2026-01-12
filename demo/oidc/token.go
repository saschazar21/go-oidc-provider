package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/schema"
)

type HasOIDCClientCredentials interface {
	GetClientID() string
	GetClientSecret() string
}

// oidcTokenRequest represents the request to the token endpoint
type oidcTokenRequest struct {
	GrantType    string `schema:"grant_type"`
	Code         string `schema:"code"`
	RedirectURI  string `schema:"redirect_uri"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
}

func (r oidcTokenRequest) GetClientID() string {
	return r.ClientID
}

func (r oidcTokenRequest) GetClientSecret() string {
	return r.ClientSecret
}

func (r *oidcTokenRequest) WithClientID(clientID string) *oidcTokenRequest {
	r.ClientID = clientID
	return r
}

func (r *oidcTokenRequest) WithClientSecret(clientSecret string) *oidcTokenRequest {
	r.ClientSecret = clientSecret
	return r
}

func (r *oidcTokenRequest) ExchangeCode() (*oidcTokenResponse, error) {
	configuration, err := FetchOpenIDConfiguration()
	if err != nil || configuration == nil {
		return nil, err
	}

	encoder := schema.NewEncoder()
	data := make(map[string][]string)
	err = encoder.Encode(r, data)
	if err != nil {
		return nil, err
	}

	resp, err := http.PostForm(configuration.TokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		var oidcErr OIDCErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&oidcErr); err != nil {
			return nil, err
		}
		return nil, &oidcErr
	}

	var tokenResponse oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	tokenResponse.ClientID = r.ClientID
	tokenResponse.ClientSecret = r.ClientSecret

	return &tokenResponse, nil
}

func (r oidcTokenRequest) String() string {
	return "oidcTokenRequest{" +
		"GrantType: " + r.GrantType +
		", Code: " + r.Code +
		", RedirectURI: " + r.RedirectURI +
		", ClientID: " + r.ClientID +
		", ClientSecret: " + r.ClientSecret +
		"}"
}

// NewOIDCTokenRequest creates a new OIDC token request with the given authorization code
// and fills in the client ID, client secret, and redirect URI from environment variables
// and utility functions.
func NewOIDCTokenRequest(code string) *oidcTokenRequest {
	return &oidcTokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  GetCallbackURL(),
		ClientID:     os.Getenv(OIDC_CLIENT_ID_ENV),
		ClientSecret: os.Getenv(OIDC_CLIENT_SECRET_ENV),
	}
}

// oidcTokenResponse represents the response from the token endpoint
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token" schema:"access_token"`
	IDToken      string `json:"id_token" schema:"id_token"`
	TokenType    string `json:"token_type" schema:"token_type"`
	ExpiresIn    int    `json:"expires_in" schema:"expires_in"`
	RefreshToken string `json:"refresh_token" schema:"refresh_token"`
	ClientID     string `json:"-" schema:"-"`
	ClientSecret string `json:"-" schema:"-"`
}

func (r oidcTokenResponse) GetClientID() string {
	return r.ClientID
}

func (r oidcTokenResponse) GetClientSecret() string {
	return r.ClientSecret
}

func (r oidcTokenResponse) String() string {
	return "oidcTokenResponse{" +
		"AccessToken: " + r.AccessToken +
		", IDToken: " + r.IDToken +
		", TokenType: " + r.TokenType +
		", ExpiresIn: " + fmt.Sprintf("%d", r.ExpiresIn) +
		", RefreshToken: " + r.RefreshToken +
		"}"
}
