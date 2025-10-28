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
	GrantType    utils.GrantType   `json:"grant_type" schema:"grant_type" validate:"required,grant-type"`
	Code         *string           `json:"code" schema:"code" validate:"required_if=GrantType authorization_code"`
	RedirectURI  *string           `json:"redirect_uri" schema:"redirect_uri" validate:"required_if=GrantType authorization_code"`
	ClientID     string            `json:"client_id" schema:"client_id" validate:"required"`
	ClientSecret *string           `json:"client_secret" schema:"client_secret" validate:"required_without=CodeVerifier"`
	CodeVerifier *string           `json:"code_verifier" schema:"code_verifier" validate:"required_without=ClientSecret"`
	RefreshToken *string           `json:"refresh_token" schema:"refresh_token" validate:"required_if=GrantType refresh_token"`
	Scope        *utils.ScopeSlice `json:"scope" schema:"scope" validate:"omitempty,dive,scope"`
}

func (tr *tokenRequest) clientCredentials(ctx context.Context, db bun.IDB) (map[utils.TokenType]*models.Token, errors.OIDCError) {
	if err := tr.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		msg := "Request contained invalid parameters."

		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if tr.GrantType != utils.CLIENT_CREDENTIALS {
		msg := fmt.Sprintf("Unsupported grant_type for client credentials: %s", tr.GrantType)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_GRANT_TYPE,
			Description: &msg,
		}
	}

	msg := "Client authentication failed."
	clientErr := errors.JSONError{
		StatusCode:  http.StatusUnauthorized,
		ErrorCode:   errors.INVALID_CLIENT,
		Description: &msg,
		Headers: map[string]string{
			"WWW-Authenticate": `Basic realm="token", charset="UTF-8"`,
		},
	}

	if tr.ClientSecret == nil {
		return nil, clientErr
	}

	client, err := models.GetClientByIDAndSecret(ctx, db, tr.ClientID, *tr.ClientSecret)
	if err != nil {
		log.Printf("Error retrieving client by ID and secret: %v", err)
		return nil, clientErr
	}

	if !utils.ContainsValue(*client.GrantTypes, utils.CLIENT_CREDENTIALS) {
		msg := fmt.Sprintf("Client is missing the client_credentials grant type: %s", tr.ClientID)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_GRANT_TYPE,
			Description: &msg,
		}
	}

	token, tokenErr := models.CreateToken(ctx, db, string(utils.CLIENT_CREDENTIALS_TYPE), client)
	if tokenErr != nil {
		log.Printf("Error creating client credentials token: %v", tokenErr)
		msg := "Failed to create client credentials token."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	tokens := make(map[utils.TokenType]*models.Token)
	tokens[utils.CLIENT_CREDENTIALS_TYPE] = token

	return tokens, nil
}

func (tr *tokenRequest) exchangeToken(ctx context.Context, db bun.IDB) (map[utils.TokenType]*models.Token, errors.OIDCError) {
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
			msg := "Authorization code not found or inactive."
			log.Printf("%s", msg)
			return nil, errors.JSONError{
				StatusCode:  http.StatusBadRequest,
				ErrorCode:   errors.INVALID_REQUEST,
				Description: &msg,
			}
		}

		log.Printf("Error retrieving authorization code token by value: %v", err)
		msg := "Failed to retrieve authorization code from database."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
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
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected when marking authorization code as consumed: %v", err)
		msg := "Failed to mark authorization code as consumed."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}
	}

	if rowsAffected == 0 {
		log.Println("No rows affected when marking authorization code as consumed.")
		msg := "Failed to mark authorization code as consumed."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
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

func (tr *tokenRequest) rotateToken(ctx context.Context, db bun.IDB) (map[utils.TokenType]*models.Token, errors.OIDCError) {
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
			msg := "Refresh Token not found or inactive."
			log.Printf("%s", msg)
			return nil, errors.JSONError{
				StatusCode:  http.StatusNotFound,
				ErrorCode:   errors.NOT_FOUND,
				Description: &msg,
			}
		}

		log.Printf("Error retrieving token by value for rotation: %v", err)
		msg := "Failed to retrieve token from database."
		return nil, errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.INTERNAL_SERVER_ERROR,
			Description: &msg,
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

func (tr *tokenRequest) HandleRequest(ctx context.Context, db bun.IDB) (map[utils.TokenType]*models.Token, errors.OIDCError) {
	switch tr.GrantType {
	case utils.AUTHORIZATION_CODE:
		return tr.exchangeToken(ctx, db)
	case utils.REFRESH_TOKEN:
		return tr.rotateToken(ctx, db)
	case utils.CLIENT_CREDENTIALS:
		return tr.clientCredentials(ctx, db)
	default:
		msg := fmt.Sprintf("Unsupported grant_type: %s", tr.GrantType)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_GRANT_TYPE,
			Description: &msg,
		}
	}
}

func ParseTokenRequest(r *http.Request) (*tokenRequest, errors.OIDCError) {
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

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Unsupported Content-Type. Only application/x-www-form-urlencoded is allowed."
		return nil, errors.JSONError{
			StatusCode:  http.StatusUnsupportedMediaType,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Failed to parse form data: %v", err)
		msg := "Failed to parse form data."
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	var tr tokenRequest
	decoder := utils.NewCustomDecoder()

	msg := "Invalid token request parameters."
	httpErr := errors.JSONError{
		StatusCode:  http.StatusBadRequest,
		ErrorCode:   errors.INVALID_REQUEST,
		Description: &msg,
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

	if tr.ClientID == "" || (tr.ClientSecret == nil && tr.CodeVerifier == nil) {
		msg := "Missing required client authentication parameters."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusUnauthorized,
			ErrorCode:   errors.INVALID_CLIENT,
			Description: &msg,
			Headers: map[string]string{
				"WWW-Authenticate": `Basic realm="token", charset="UTF-8"`,
			},
		}
	}

	if err := tr.Validate(); err != nil {
		log.Printf("Token request validation error: %v", err)
		return nil, httpErr
	}

	return &tr, nil
}
