package helpers

import (
	"context"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func HandleUserinfoRequest(ctx context.Context, db bun.IDB, r *http.Request) (*models.User, errors.HTTPError) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
		// Valid methods
	default:
		msg := "Invalid HTTP method for userinfo endpoint"
		log.Printf("%s: %s", msg, r.Method)
		return nil, errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "GET, POST, OPTIONS",
			},
		}
	}

	var bearer string
	var err error

	if bearer, err = parseBearerTokenFromRequest(r); err != nil {
		msg := "Invalid or missing bearer token"
		log.Printf("%s: %v", msg, err)

		return nil, errors.JSONError{
			StatusCode:  http.StatusUnauthorized,
			ErrorCode:   errors.UNAUTHORIZED,
			Description: &msg,
			Headers: map[string]string{
				"WWW-Authenticate": `Bearer realm="userinfo", charset="UTF-8"`,
			},
		}
	}

	var claims *idtoken.Claims
	if claims, err = idtoken.ParseJWT(bearer); err == nil && claims != nil {
		log.Printf("Bearer token is a valid JWT, using claims from token...")
		return claims.User, nil
	}

	var token *models.Token
	if token, err = models.GetTokenByValue(ctx, db, bearer); err != nil {
		msg := "Error retrieving token from database"
		log.Printf("%s: %v", msg, err)

		return nil, errors.JSONError{
			StatusCode:  http.StatusUnauthorized,
			ErrorCode:   errors.UNAUTHORIZED,
			Description: &msg,
			Headers: map[string]string{
				"WWW-Authenticate": `Bearer realm="userinfo", charset="UTF-8"`,
			},
		}
	}

	if token.Type != utils.ACCESS_TOKEN_TYPE || (token.User == nil && token.Authorization == nil) {
		msg := "Token is not an access token or contains no user information"
		log.Printf("%s", msg)

		return nil, errors.JSONError{
			StatusCode:  http.StatusForbidden,
			ErrorCode:   errors.FORBIDDEN,
			Description: &msg,
		}
	}

	scopes := token.Scope
	if scopes == nil {
		scopes = &token.Authorization.Scope
	}

	user := token.User
	if user == nil {
		user = token.Authorization.User
	}

	return user.GetClaimsBasedOnScopes(*scopes), nil
}
