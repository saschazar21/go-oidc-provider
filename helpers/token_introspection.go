package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type tokenIntrospectionRequest struct {
	Token         string           `json:"-" schema:"token" validate:"required"`
	TokenTypeHint *utils.TokenType `json:"-" schema:"token_type_hint" validate:"omitempty,token-type"`
}

func (tir *tokenIntrospectionRequest) fetchToken(ctx context.Context, db bun.IDB) (*tokenIntrospectionResponse, error) {
	var token *models.Token
	var err error

	if token, err = models.GetTokenByValue(ctx, db, tir.Token); err != nil || token == nil {
		log.Printf("Failed to fetch token for introspection: %v", err)
		return nil, fmt.Errorf("failed to fetch token from database")
	}

	var clientId string
	if token.Client != nil {
		clientId = token.Client.ID
	} else if token.Authorization != nil && token.Authorization.Client != nil {
		clientId = token.Authorization.Client.ID
	}

	var subject string
	if token.User != nil {
		subject = token.User.ID.String()
	} else if token.Authorization != nil && token.Authorization.User != nil {
		subject = token.Authorization.User.ID.String()
	}

	var scope utils.ScopeSlice
	if token.Scope != nil {
		scope = *token.Scope
	} else if token.Authorization != nil {
		scope = token.Authorization.Scope
	}

	issuer := os.Getenv(utils.ISSUER_URL_ENV)
	if issuer == "" {
		issuer = utils.GetDeploymentURL()
	}

	res := tokenIntrospectionResponse{
		Active:    true,
		Scope:     scope,
		Issuer:    issuer,
		Client:    clientId,
		Sub:       subject,
		TokenType: token.Type,
		IssuedAt:  utils.Epoch(token.CreatedAt.CreatedAt),
		ExpiresAt: utils.Epoch(token.ExpiresAt.ExpiresAt),
	}

	return &res, nil
}

func (tir *tokenIntrospectionRequest) parseJWT() (*tokenIntrospectionResponse, error) {
	jwt, err := idtoken.ParseJWT(tir.Token)
	if err != nil {
		log.Printf("Failed to parse JWT for token introspection: %v", err)
		return nil, nil
	}

	sub, err := jwt.GetSubject()
	if err != nil {
		log.Printf("Failed to get subject from JWT for token introspection: %v", err)
		return nil, fmt.Errorf("failed to get subject from JWT")
	}

	res := tokenIntrospectionResponse{
		Active:    true,
		Scope:     jwt.Scope,
		Issuer:    jwt.Issuer,
		Client:    jwt.Audience[0],
		Sub:       sub,
		TokenType: utils.ACCESS_TOKEN_TYPE,
		IssuedAt:  jwt.IssuedAt,
		ExpiresAt: jwt.ExpiresAt,
	}

	return &res, nil
}

func (tir *tokenIntrospectionRequest) CreateResponse(ctx context.Context, db bun.IDB) *tokenIntrospectionResponse {
	var res *tokenIntrospectionResponse
	var err error

	if res, err = tir.parseJWT(); err != nil {
		log.Printf("Parsing of JWT failed: %v", err)
		return &tokenIntrospectionResponse{Active: false}
	}

	if res != nil {
		return res
	}

	if res, err = tir.fetchToken(ctx, db); err != nil {
		log.Printf("Fetching of token failed: %v", err)
		return &tokenIntrospectionResponse{Active: false}
	}

	if res != nil {
		return res
	}

	return &tokenIntrospectionResponse{Active: false}
}

type tokenIntrospectionResponse struct {
	Active    bool             `json:"active" validate:"required,oneof=true false"`
	Scope     utils.ScopeSlice `json:"scope,omitempty" validate:"omitempty,dive,scope"`
	Issuer    string           `json:"iss,omitempty"`
	Client    string           `json:"client_id,omitempty"`
	Sub       string           `json:"sub,omitempty"`
	TokenType utils.TokenType  `json:"token_type,omitempty" validate:"omitempty,token_type"`
	IssuedAt  utils.Epoch      `json:"iat,omitempty"`
	ExpiresAt utils.Epoch      `json:"exp,omitempty"`
}

func (tir *tokenIntrospectionResponse) Write(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")

	return json.NewEncoder(w).Encode(tir)
}

func ParseTokenIntrospectionRequest(ctx context.Context, db bun.IDB, r *http.Request) (*tokenIntrospectionRequest, errors.HTTPError) {
	if r.Method != http.MethodPost {
		msg := "Unsupported request method. Only POST is allowed."
		return nil, errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "POST",
			},
		}
	}

	if err := validateTokenIntrospectionAuthorization(ctx, db, r); err != nil {
		return nil, err
	}

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Invalid content type. Expected application/x-www-form-urlencoded."
		return nil, errors.JSONError{
			StatusCode:  http.StatusUnsupportedMediaType,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if err := r.ParseForm(); err != nil {
		msg := "Failed to parse POST form body."
		log.Printf("%s %v", msg, err)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	var tir tokenIntrospectionRequest
	decoder := utils.NewCustomDecoder()

	msg := "Failed to decode token introspection request."
	responseErr := errors.JSONError{
		StatusCode:  http.StatusBadRequest,
		ErrorCode:   errors.INVALID_REQUEST,
		Description: &msg,
	}

	if err := decoder.Decode(&tir, r.PostForm); err != nil {
		log.Printf("%s %v", msg, err)
		return nil, responseErr
	}

	if err := tir.Validate(); err != nil {
		log.Printf("%s %v", msg, err)
		return nil, responseErr
	}

	return &tir, nil
}

func validateTokenIntrospectionAuthorization(ctx context.Context, db bun.IDB, r *http.Request) errors.HTTPError {
	if r.Header.Get("Authorization") == "" {
		msg := "Missing Authorization header"
		return errors.JSONError{
			StatusCode:  http.StatusUnauthorized,
			ErrorCode:   errors.UNAUTHORIZED,
			Description: &msg,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="token_introspection", charset="UTF-8"`,
			},
		}
	}

	if token, err := validateBearerToken(ctx, db, r); err == nil && token != nil {
		return nil
	} else if err != nil {
		log.Printf("Bearer token validation failed: %v", err)
	}

	if _, err := validateClientCredentials(ctx, db, r); err == nil {
		return nil
	} else if err != nil {
		log.Printf("Client credentials validation failed: %v", err)
	}

	msg := "Invalid authorization for token introspection"
	return errors.JSONError{
		StatusCode:  http.StatusUnauthorized,
		ErrorCode:   errors.UNAUTHORIZED,
		Description: &msg,
		Headers: map[string]string{
			"WWW-Authenticate": `Basic realm="token_introspection", charset="UTF-8"`,
		},
	}
}
