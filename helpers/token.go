package helpers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
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

func ExchangeToken(ctx context.Context, db bun.IDB, tr *tokenRequest) (map[utils.TokenType]*models.Token, errors.OIDCError) {
	if err := tr.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		msg := "Request contained invalid parameters."

		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if tr.GrantType != utils.AUTHORIZATION_CODE || tr.Code == nil {
		msg := fmt.Sprintf("Unsupported grant_type for token exchange: %s", tr.GrantType)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_GRANT_TYPE,
			Description: &msg,
		}
	}

	var authorizationCode models.Token
	var err error

	query := models.NewTokenQuery(db, *tr.Code, string(utils.AUTHORIZATION_CODE_TYPE)).
		PopulateAuthorization(true, true, "Authorization", "authorization", "token").
		GetQuery()

	if tr.ClientSecret != nil && *tr.ClientSecret != "" {
		query = query.
			Where("\"authorization__client\".\"client_secret\" = ?", utils.HashedString(*tr.ClientSecret))
	}

	if tr.CodeVerifier != nil && *tr.CodeVerifier != "" {
		query = query.
			Where("\"authorization\".\"code_challenge\" = ?", utils.GeneratePKCEChallenge(*tr.CodeVerifier))
	}

	err = query.
		Where("\"token\".\"consumed_at\" IS NULL").
		Where("\"authorization\".\"redirect_uri\" = ?", tr.RedirectURI).
		Scan(ctx, &authorizationCode)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusNotFound,
				Title:      errors.NOT_FOUND,
				Detail:     "Authorization Code not found or inactive.",
			}
		}

		log.Printf("Error retrieving authorization code token by value: %v", err)
		msg := "Failed to retrieve authorization code from database."
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     msg,
		}
	}

	auth := authorizationCode.Authorization
	if auth == nil {
		msg := "Authorization associated with the authorization code not found."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	consumedAt := time.Now().UTC()
	authorizationCode = models.Token{
		ID: authorizationCode.ID,
	}

	var result sql.Result
	result, err = db.NewUpdate().
		Model(&authorizationCode).
		WherePK().
		Set("consumed_at = ?", consumedAt).
		Set("revoked_at = ?", consumedAt).
		Set("revocation_reason = ?", "consumed during token exchange").
		Set("is_active = ?", false).
		OmitZero().
		Exec(ctx)

	if err != nil {
		log.Printf("Database operation error marking authorization code as consumed: %v", err)
		msg := "Failed to mark authorization code as consumed."
		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      auth.RedirectURI,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected when marking authorization code as consumed: %v", err)
		msg := "Failed to mark authorization code as consumed."
		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      auth.RedirectURI,
		}
	}

	if rowsAffected == 0 {
		log.Println("No rows affected when marking authorization code as consumed.")
		msg := "Failed to mark authorization code as consumed."
		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      auth.RedirectURI,
		}
	}

	auth.ReplacedID = auth.ID
	auth.ID = uuid.Nil // create new authorization entry for tokens

	if err := auth.Save(ctx, db); err != nil {
		log.Printf("Error creating authorization during token exchange: %v", err)
		msg := "Failed to create authorization during token exchange."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	var tokens = make(map[utils.TokenType]*models.Token)

	accessToken, tokenErr := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), auth)
	if tokenErr != nil {
		return nil, tokenErr
	}
	tokens[utils.ACCESS_TOKEN_TYPE] = accessToken

	if auth.Scope != nil && utils.ContainsValue(auth.Scope, utils.OFFLINE_ACCESS) {
		refreshToken, tokenErr := models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), auth)
		if tokenErr != nil {
			return nil, tokenErr
		}
		tokens[utils.REFRESH_TOKEN_TYPE] = refreshToken
	}

	return tokens, nil
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

func RotateToken(ctx context.Context, db bun.IDB, tr *tokenRequest) (map[utils.TokenType]*models.Token, errors.OIDCError) {
	if err := tr.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		msg := "Request contained invalid parameters."

		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if tr.GrantType != utils.REFRESH_TOKEN || tr.RefreshToken == nil {
		msg := fmt.Sprintf("Unsupported grant_type for token rotation: %s", tr.GrantType)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_GRANT_TYPE,
			Description: &msg,
		}
	}

	var currentToken models.Token
	var query *bun.SelectQuery
	query = models.NewTokenQuery(db, *tr.RefreshToken, string(utils.REFRESH_TOKEN_TYPE)).
		PopulateAuthorization(true, true, "Authorization", "authorization", "token").GetQuery()

	if tr.ClientSecret != nil && *tr.ClientSecret != "" {
		query = query.
			Where("\"authorization__client\".\"client_secret\" = ?", utils.HashedString(*tr.ClientSecret))
	}

	if tr.CodeVerifier != nil && *tr.CodeVerifier != "" {
		query = query.
			Where("\"authorization\".\"code_challenge\" = ?", utils.GeneratePKCEChallenge(*tr.CodeVerifier))
	}

	err := query.
		Scan(ctx, &currentToken)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusNotFound,
				Title:      errors.NOT_FOUND,
				Detail:     "Token not found or inactive.",
			}
		}

		log.Printf("Error retrieving token by value for rotation: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     "Failed to retrieve token from database.",
		}
	}

	auth := currentToken.Authorization
	if auth == nil {
		msg := "Authorization associated with the token not found."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	auth.ReplacedID = auth.ID
	auth.ID = uuid.Nil // prevent accidental updates

	if err := auth.Save(ctx, db); err != nil {
		log.Printf("Error creating authorization during token rotation: %v", err)
		msg := "Failed to update authorization during token rotation."

		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	tokens := make(map[utils.TokenType]*models.Token)

	// Create new refresh token
	newRefreshToken, err := models.CreateToken(ctx, db, string(utils.REFRESH_TOKEN_TYPE), auth)
	if err != nil {
		log.Printf("Error creating new refresh token during rotation: %v", err)
		msg := "Failed to create new refresh token during rotation."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}
	tokens[utils.REFRESH_TOKEN_TYPE] = newRefreshToken

	// Create new access token
	newAccessToken, err := models.CreateToken(ctx, db, string(utils.ACCESS_TOKEN_TYPE), auth)
	if err != nil {
		log.Printf("Error creating new access token during rotation: %v", err)
		msg := "Failed to create new access token during rotation."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}
	tokens[utils.ACCESS_TOKEN_TYPE] = newAccessToken

	return tokens, nil
}
