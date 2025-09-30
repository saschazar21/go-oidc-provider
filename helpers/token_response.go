package helpers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type tokenResponse struct {
	AccessToken  string           `json:"access_token" schema:"access_token" validate:"required"`
	TokenType    string           `json:"token_type" schema:"token_type" validate:"required,eq=Bearer"`
	ExpiresIn    int64            `json:"expires_in" schema:"expires_in" validate:"required,gte=0"`
	RefreshToken string           `json:"refresh_token,omitempty" schema:"refresh_token"`
	IDToken      string           `json:"id_token,omitempty" schema:"id_token"`
	Scope        utils.ScopeSlice `json:"scope,omitempty" schema:"scope"`
}

func (tr *tokenResponse) Write(w http.ResponseWriter) {
	if err := tr.Validate(); err != nil {
		msg := "Insufficient data to return token response"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(tr); err != nil {
		msg := "Failed to encode token response to JSON"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}
}

func NewTokenResponse(tokens ...*models.Token) *tokenResponse {
	var resp tokenResponse

	tokenMap := make(map[utils.TokenType]*models.Token)

	for _, token := range tokens {
		if token == nil {
			continue
		}

		switch token.Type {
		case utils.ACCESS_TOKEN_TYPE, utils.CLIENT_CREDENTIALS_TYPE:
			var scope utils.ScopeSlice
			if token.Scope != nil && len(*token.Scope) > 0 {
				scope = *token.Scope
			} else if token.Authorization != nil && len(token.Authorization.Scope) > 0 {
				scope = token.Authorization.Scope
			}

			resp.AccessToken = token.Value.String()
			resp.ExpiresIn = int64(token.ExpiresAt.ExpiresAt.Sub(token.CreatedAt.CreatedAt).Seconds())
			resp.Scope = scope
			resp.TokenType = "Bearer"

			if token.Type == utils.ACCESS_TOKEN_TYPE {
				tokenMap[utils.ACCESS_TOKEN_TYPE] = token
			}
		case utils.REFRESH_TOKEN_TYPE:
			resp.RefreshToken = token.Value.String()

			tokenMap[utils.REFRESH_TOKEN_TYPE] = token
		}
	}

	jwt, err := idtoken.NewSignedJWTFromTokens(&tokenMap)
	if err != nil {
		log.Printf("Failed to create ID token: %v", err)
		return &resp
	}

	resp.IDToken = jwt

	return &resp
}
