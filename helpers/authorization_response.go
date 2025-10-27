package helpers

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type authorizationResponse struct {
	// Authorization code flow parameters
	Code  string  `json:"code,omitempty" schema:"code,omitempty"`
	State *string `json:"state,omitempty" schema:"state,omitempty"`

	// Implicit flow parameters (not used in authorization code flow)
	IDToken     string `json:"id_token,omitempty" schema:"id_token,omitempty"`
	AccessToken string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty" schema:"token_type,omitempty" validate:"omitempty,eq=Bearer"`
	ExpiresIn   int64  `json:"expires_in,omitempty" schema:"expires_in,omitempty" validate:"omitempty,gt=0"`

	IsFragment bool `json:"-" schema:"-"`
	StatusCode int  `json:"-" schema:"-"`

	authorization *models.Authorization `json:"-" schema:"-"`
}

func (ar *authorizationResponse) createJWT(tokens *map[utils.TokenType]*models.Token) (string, errors.OIDCError) {
	var jwt string
	var err error

	if tokens == nil || len(*tokens) == 0 {
		jwt, err = idtoken.NewSignedJWTFromAuthorization(ar.authorization)
	} else {
		jwt, err = idtoken.NewSignedJWTFromTokens(tokens)
	}

	if err != nil {
		msg := "Failed to create ID token"
		log.Printf("%s: %v", msg, err)
		return "", errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			StatusCode:       http.StatusInternalServerError,
		}
	}

	return jwt, nil
}

func (ar *authorizationResponse) createTokens(ctx context.Context, db bun.IDB, types *[]utils.TokenType) (*map[utils.TokenType]*models.Token, errors.OIDCError) {
	tokens := make(map[utils.TokenType]*models.Token)

	for _, t := range *types {
		switch t {
		case utils.AUTHORIZATION_CODE_TYPE:
			code, err := models.CreateToken(ctx, db, string(utils.AUTHORIZATION_CODE), ar.authorization)
			if err != nil {
				msg := "Failed to create authorization code token"
				log.Printf("%s - %s: %v", t, msg, err)
				return nil, errors.OIDCErrorResponse{
					ErrorCode:        errors.SERVER_ERROR,
					ErrorDescription: &msg,
					StatusCode:       http.StatusInternalServerError,
				}
			}
			ar.Code = string(code.Value)
			tokens[t] = code
		case utils.ACCESS_TOKEN_TYPE:
			accessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), ar.authorization)
			if err != nil {
				msg := "Failed to create access token"
				log.Printf("%s - %s: %v", t, msg, err)
				return nil, errors.OIDCErrorResponse{
					ErrorCode:        errors.SERVER_ERROR,
					ErrorDescription: &msg,
					StatusCode:       http.StatusInternalServerError,
				}
			}
			ar.AccessToken = string(accessToken.Value)
			ar.TokenType = "Bearer"
			ar.ExpiresIn = int64(accessToken.ExpiresAt.ExpiresAt.Sub(accessToken.CreatedAt.CreatedAt).Seconds())
			tokens[t] = accessToken
		default:
			msg := "Unsupported token type requested"
			log.Printf("%s: %s", t, msg)
			return nil, errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &msg,
				StatusCode:       http.StatusBadRequest,
			}
		}
	}

	return &tokens, nil
}

func (ar *authorizationResponse) populateResponse(ctx context.Context, db bun.IDB) errors.OIDCError {
	switch ar.authorization.ResponseType {
	case utils.CODE:
		if _, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.AUTHORIZATION_CODE_TYPE}); err != nil {
			return err
		}
	case utils.ID_TOKEN:
		jwt, err := ar.createJWT(nil) // fallback to ar.authorization since no tokens are created
		if err != nil {
			return err
		}

		ar.IDToken = jwt
		ar.IsFragment = true
	case utils.TOKEN:
		if _, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.ACCESS_TOKEN_TYPE}); err != nil {
			return err
		}
		ar.IsFragment = true
	case utils.ID_TOKEN_TOKEN:
		tokens, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.ACCESS_TOKEN_TYPE})
		if err != nil {
			return err
		}

		jwt, err := ar.createJWT(tokens)
		if err != nil {
			return err
		}

		ar.IDToken = jwt
		ar.IsFragment = true
	case utils.CODE_ID_TOKEN:
		tokens, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.AUTHORIZATION_CODE_TYPE})
		if err != nil {
			return err
		}

		jwt, err := ar.createJWT(tokens)
		if err != nil {
			return err
		}

		ar.IDToken = jwt
		ar.Code = string((*tokens)[utils.AUTHORIZATION_CODE_TYPE].Value)
		ar.IsFragment = true
	case utils.CODE_TOKEN:
		tokens, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.AUTHORIZATION_CODE_TYPE, utils.ACCESS_TOKEN_TYPE})
		if err != nil {
			return err
		}

		ar.Code = string((*tokens)[utils.AUTHORIZATION_CODE_TYPE].Value)
		ar.AccessToken = string((*tokens)[utils.ACCESS_TOKEN_TYPE].Value)
		ar.TokenType = "Bearer"
		ar.ExpiresIn = int64((*tokens)[utils.ACCESS_TOKEN_TYPE].ExpiresAt.ExpiresAt.Sub((*tokens)[utils.ACCESS_TOKEN_TYPE].CreatedAt.CreatedAt).Seconds())
		ar.IsFragment = true
	case utils.CODE_ID_TOKEN_TOKEN:
		tokens, err := ar.createTokens(ctx, db, &[]utils.TokenType{utils.AUTHORIZATION_CODE_TYPE, utils.ACCESS_TOKEN_TYPE})
		if err != nil {
			return err
		}

		jwt, err := ar.createJWT(tokens)
		if err != nil {
			return err
		}

		ar.IDToken = jwt
		ar.Code = string((*tokens)[utils.AUTHORIZATION_CODE_TYPE].Value)
		ar.AccessToken = string((*tokens)[utils.ACCESS_TOKEN_TYPE].Value)
		ar.TokenType = "Bearer"
		ar.ExpiresIn = int64((*tokens)[utils.ACCESS_TOKEN_TYPE].ExpiresAt.ExpiresAt.Sub((*tokens)[utils.ACCESS_TOKEN_TYPE].CreatedAt.CreatedAt).Seconds())
		ar.IsFragment = true
	default:
		msg := "Unsupported response type"
		log.Printf("%s: %s", ar.authorization.ResponseType, msg)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			StatusCode:       http.StatusBadRequest,
		}
	}

	return nil
}

func (ar *authorizationResponse) Write(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     AUTHORIZATION_COOKIE_NAME,
		Value:    "",
		MaxAge:   -1, // Delete cookie
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)

	if err := ar.Validate(); err != nil {
		msg := "Invalid authorization response"
		log.Printf("%s: %v", msg, err)
		err := errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
			State:            ar.State,
			IsFragment:       ar.IsFragment,
			StatusCode:       http.StatusInternalServerError,
		}
		err.Write(w)

		return
	}

	u, err := url.Parse(ar.authorization.RedirectURI)
	if err != nil {
		msg := "Invalid redirect URI"
		log.Printf("%s: %v", msg, err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: msg,
			RedirectURI: ar.authorization.RedirectURI,
		}

		err.Write(w)
		return
	}

	encoder := utils.NewCustomEncoder()

	var query url.Values = make(map[string][]string)
	if err := encoder.Encode(ar, query); err != nil {
		msg := "Failed to encode authorization response parameters"
		log.Printf("%s: %v", msg, err)
		err := errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
			State:            ar.State,
			IsFragment:       ar.IsFragment,
		}
		err.Write(w)
		return
	}

	if ar.IsFragment {
		u.Fragment = query.Encode()
	} else {
		u.RawQuery = query.Encode()
	}

	statusCode := http.StatusFound
	if ar.StatusCode >= 100 && ar.StatusCode <= 599 {
		statusCode = ar.StatusCode
	}

	w.Header().Set("Location", u.String())
	w.WriteHeader(statusCode)
}

func NewAuthorizationResponse(ctx context.Context, db bun.IDB, auth *models.Authorization) (*authorizationResponse, errors.OIDCError) {
	if auth == nil {
		msg := "No authorization data provided"

		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			StatusCode:       http.StatusInternalServerError,
		}
	}

	if !auth.IsApproved() {
		msg := "Authorization request was not approved"

		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.ACCESS_DENIED,
			ErrorDescription: &msg,
			RedirectURI:      auth.RedirectURI,
			State:            auth.State,
			IsFragment:       auth.ResponseType != "" && auth.ResponseType != utils.CODE,
			StatusCode:       http.StatusFound,
		}
	}

	resp := &authorizationResponse{
		State:         auth.State,
		IsFragment:    auth.ResponseType != "" && auth.ResponseType != utils.CODE,
		authorization: auth,
	}

	if err := resp.populateResponse(ctx, db); err != nil {
		return nil, err
	}

	return resp, nil
}
