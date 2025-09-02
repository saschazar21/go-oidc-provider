package models

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

const (
	TOKEN_DEFAULT_RANDOM_LENGTH = 24

	AUTHORIZATION_CODE_TOKEN_LIFETIME = 5 * time.Minute
	ACCESS_TOKEN_LIFETIME             = 10 * time.Minute
	REFRESH_TOKEN_LIFETIME            = 30 * 24 * time.Hour // 30 days
	CLIENT_CREDENTIALS_TOKEN_LIFETIME = 5 * time.Minute
	CUSTOM_TOKEN_LIFETIME             = 24 * time.Hour // 24 hours
)

type Token struct {
	bun.BaseModel `bun:"oidc_tokens"`

	ID          uuid.UUID          `json:"-" schema:"-" bun:"token_id,pk,type:uuid,default:gen_random_uuid()"`                                        // Unique identifier for the token
	Type        utils.TokenType    `json:"type" schema:"type,required" validate:"required,token-type" bun:"token_type,notnull"`                       // Type of the token (e.g., access token, refresh token)
	Value       utils.HashedString `json:"token,omitempty" schema:"token,omitempty" bun:"token_value,notnull"`                                        // Hashed value of the token for security
	RedirectURI *string            `json:"redirect_uri,omitempty" schema:"redirect_uri,omitempty" validate:"omitempty,uri,lt=512" bun:"redirect_uri"` // Optional redirect URI associated with the token

	IsActive         *bool   `json:"is_active" schema:"-" bun:"is_active,default:true"`                                          // Indicates if the token is active
	RevocationReason *string `json:"revocation_reason,omitempty" schema:"-" validate:"omitempty,lt=255" bun:"revocation_reason"` // Optional reason for token revocation
	RotationCount    *int    `json:"-" schema:"-" validate:"omitempty,gte=0" bun:"rotation_count"`                               // Count of how many times the token has been rotated (if applicable)

	// Custom token section below
	IsCustom    bool           `json:"isCustom,omitempty" schema:"is_custom,omitempty" bun:"is_custom"`                                                 // Indicates if the token is a custom token
	Description *string        `json:"description,omitempty" schema:"description,omitempty" validate:"omitempty,lt=512" bun:"description"`              // Optional description of the token
	Scope       *[]utils.Scope `json:"scope,omitempty" schema:"scope,omitempty" validate:"omitempty,dive,scope" bun:"scope,type:oidc_standard_scope[]"` // Optional scopes associated with the token

	// Relations
	AuthorizationID *uuid.UUID     `json:"-" schema:"-" bun:"authorization_id,type:uuid"`                            // ID of the associated authorization
	Authorization   *Authorization `json:"-" schema:"-" bun:"rel:belongs-to,join:authorization_id=authorization_id"` // Associated authorization

	ClientID *string `json:"-" schema:"-" bun:"client_id"`                               // Optional client ID associated with the token (for client_credentials)
	Client   *Client `json:"-" schema:"-" bun:"rel:belongs-to,join:client_id=client_id"` // Associated client (for client_credentials)

	UserID *uuid.UUID `json:"-" schema:"-" bun:"user_id,type:uuid"`                                // ID of the associated user (for custom tokens)
	User   *User      `json:"user,omitempty" schema:"-" bun:"rel:belongs-to,join:user_id=user_id"` // Associated user (for custom tokens)

	PreviousTokenID *uuid.UUID `json:"-" schema:"-" bun:"previous_token_id,type:uuid"`                    // ID of the previous token in a chain (if applicable)
	PreviousToken   *Token     `json:"-" schema:"-" bun:"rel:belongs-to,join:previous_token_id=token_id"` // Previous token in a chain (if applicable)

	ConsumedAt *time.Time `json:"-" schema:"-" validate:"omitempty,time-lte-now" bun:"consumed_at"`  // Timestamp when the token was consumed, if applicable (e.g. authorization_code)
	LastUsedAt *time.Time `json:"-" schema:"-" validate:"omitempty,time-lte-now" bun:"last_used_at"` // Timestamp when the token was last used, if applicable (e.g. access_token)
	RevokedAt  *time.Time `json:"-" schema:"-" validate:"omitempty,time-lte-now" bun:"revoked_at"`   // Timestamp when the token was revoked, if applicable
	CreatedAt
	ExpiresAt
}

var _ bun.BeforeAppendModelHook = (*Token)(nil)

func (m *Token) save(ctx context.Context, db bun.IDB, excludeColumns ...string) errors.OIDCError {
	var hashedValue *utils.HashedString
	redirectUri := ""

	if m.RedirectURI != nil {
		redirectUri = *m.RedirectURI
	}

	if err := m.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		description := "Token validation failed."

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
			RedirectURI:      redirectUri,
		}
	}

	var err error
	var result sql.Result

	excludeColumns = append(excludeColumns, "created_at")

	if m.ID != uuid.Nil {
		excludeColumns = append(excludeColumns, "expires_at")

		result, err = db.NewUpdate().
			Model(m).
			WherePK().
			OmitZero().
			ExcludeColumn(excludeColumns...).
			Returning("*").
			Exec(ctx)
	} else {
		hashedValue, err = generateTokenValue()
		if err != nil {
			description := "Failed to generate token value."

			return errors.HTTPErrorResponse{
				StatusCode:  http.StatusInternalServerError,
				Message:     errors.INTERNAL_SERVER_ERROR,
				Description: description,
			}
		}

		m.Value = *hashedValue // Set the unhashed token value only on creation

		result, err = db.NewInsert().
			Model(m).
			ExcludeColumn(excludeColumns...).
			Returning("*").
			Exec(ctx)

		m.Value = *hashedValue // Return the unhashed token value only on creation
	}

	defaultMsg := "Failed to store token in database"

	if err != nil {
		log.Printf("Database operation error: %v", err)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectUri,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectUri,
		}
	}

	if rowsAffected == 0 {
		log.Println("No rows affected during token save operation.")
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectUri,
		}
	}

	return nil
}

func (m *Token) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		m.CreatedAt.CreatedAt = time.Now().UTC()

		if m.ExpiresAt.ExpiresAt.IsZero() {
			m.ExpiresAt.ExpiresAt = time.Now().UTC().Add(CLIENT_CREDENTIALS_TOKEN_LIFETIME)
		}
	case *bun.UpdateQuery:
		m.Type = ""
		m.Value = ""
		m.CreatedAt.CreatedAt = time.Time{}
	}

	return nil
}

// generates the hash value for use in a JWT
// e.g. as at_hash or c_hash claim
//
// this function assumes that t.Value is the unhashed token value
func (t *Token) GenerateTokenHash() (string, error) {
	if t.Value == "" {
		return "", fmt.Errorf("token value is empty")
	}

	hash := utils.HashS256([]byte(t.Value))

	enc := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

	return enc, nil
}

func createClientCredentialsToken(ctx context.Context, db bun.IDB, rawClient interface{}) (*Token, errors.OIDCError) {
	var client *Client
	switch v := rawClient.(type) {
	case *Client:
		client = v
	case Client:
		client = &v
	default:
		msg := "Invalid client type provided."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	token := Token{
		Type:     utils.CLIENT_CREDENTIALS_TYPE,
		ClientID: &client.ID,
		ExpiresAt: ExpiresAt{
			ExpiresAt: time.Now().UTC().Add(CLIENT_CREDENTIALS_TOKEN_LIFETIME), // Default expiration to 5 minutes
		},
	}

	if err := token.save(ctx, db); err != nil {
		return nil, err
	}

	return &token, nil
}

func createCustomToken(ctx context.Context, db bun.IDB, rawCustomToken interface{}) (*Token, errors.OIDCError) {
	var token *Token
	var user *User
	switch v := rawCustomToken.(type) {
	case *Token:
		token = v
	case Token:
		token = &v
	case *User:
		user = v
	case User:
		user = &v
	default:
		msg := "Invalid custom token or user type provided."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if token == nil && user == nil {
		msg := "Either a custom token or user must be provided."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	if token == nil {
		token = &Token{
			UserID: &user.ID,
			Scope:  &[]utils.Scope{utils.OPENID},
		}
	}

	if token.UserID == nil || *token.UserID == uuid.Nil {
		if token.User == nil {
			msg := "User is required to create a custom token."
			log.Printf("%s", msg)

			return nil, errors.JSONError{
				StatusCode:  http.StatusBadRequest,
				ErrorCode:   errors.INVALID_REQUEST,
				Description: &msg,
			}
		}
		token.UserID = &token.User.ID
	}

	if token.ExpiresAt.ExpiresAt.IsZero() {
		token.ExpiresAt.ExpiresAt = time.Now().UTC().Add(CUSTOM_TOKEN_LIFETIME)
	}

	t := &Token{
		Type:        utils.ACCESS_TOKEN_TYPE,
		IsCustom:    true,
		UserID:      token.UserID,
		Description: token.Description,
		Scope:       token.Scope,
		ExpiresAt:   token.ExpiresAt,
	}

	if err := t.save(ctx, db); err != nil {
		return nil, err
	}
	return t, nil
}

func createToken(ctx context.Context, db bun.IDB, tokenType utils.TokenType, rawAuth interface{}) (*Token, errors.OIDCError) {
	var authorization *Authorization
	switch v := rawAuth.(type) {
	case *Authorization:
		authorization = v
	case Authorization:
		authorization = &v
	default:
		msg := "Invalid authorization type provided."
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	var client *Client
	if authorization.Client != nil {
		client = authorization.Client
	}

	token := Token{
		Type:            tokenType,
		AuthorizationID: &authorization.ID,
	}

	switch tokenType {
	case utils.AUTHORIZATION_CODE_TYPE:
		token.RedirectURI = &authorization.RedirectURI
		token.ExpiresAt = ExpiresAt{
			ExpiresAt: time.Now().UTC().Add(AUTHORIZATION_CODE_TOKEN_LIFETIME), // Default expiration to 5 minutes
		}
	case utils.ACCESS_TOKEN_TYPE:
		lifetime := ACCESS_TOKEN_LIFETIME // Default expiration to 5 minutes
		if client != nil && client.AccessTokenLifetime > 0 {
			lifetime = time.Duration(client.AccessTokenLifetime) * time.Second
		}
		token.ExpiresAt = ExpiresAt{
			ExpiresAt: time.Now().UTC().Add(lifetime),
		}
	case utils.REFRESH_TOKEN_TYPE:
		lifetime := REFRESH_TOKEN_LIFETIME // Default expiration to 30 days
		if client != nil && client.AccessTokenLifetime > 0 {
			lifetime = time.Duration(client.RefreshTokenLifetime) * time.Second
		}
		token.ExpiresAt = ExpiresAt{
			ExpiresAt: time.Now().UTC().Add(lifetime),
		}
	}

	if err := token.save(ctx, db); err != nil {
		return nil, err
	}

	expiresAt := time.Now().UTC().Add(AUTHORIZATION_GRANT_LIFETIME)
	if token.ExpiresAt.ExpiresAt.Before(expiresAt) {
		expiresAt = token.ExpiresAt.ExpiresAt
	}

	authorization = &Authorization{
		ID: authorization.ID,
	}

	var err error
	_, err = db.NewUpdate().
		Model(authorization).
		WherePK().
		Where("expires_at < ?", expiresAt).
		Set("expires_at = ?", expiresAt).
		OmitZero().
		Exec(ctx)

	if err != nil {
		log.Printf("Database operation error updating authorization expiration: %v", err)
		msg := "Failed to update authorization expiration."
		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      authorization.RedirectURI,
		}
	}

	return &token, nil
}

func generateTokenValue() (*utils.HashedString, error) {
	tokenValue, err := utils.RandomBase58String(TOKEN_DEFAULT_RANDOM_LENGTH)
	if err != nil {
		log.Printf("Error generating token value: %v", err)
		return nil, fmt.Errorf("failed to generate token value")
	}

	hashedToken := utils.HashedString(tokenValue)

	return &hashedToken, nil
}

func revokeTokensByAuthorizationID(ctx context.Context, db bun.IDB, authorizationID uuid.UUID, reason *string) errors.OIDCError {
	var result sql.Result
	var err error

	isActive := false
	revokedAt := time.Now().UTC()

	token := Token{
		RevocationReason: reason,
		IsActive:         &isActive,
		RevokedAt:        &revokedAt,
	}

	result, err = db.NewUpdate().
		Model(&token).
		Where("\"token\".\"authorization_id\" = ?", authorizationID).
		Where("\"token\".\"is_active\" = ?", true).
		Where("\"token\".\"expires_at\" > ?", time.Now()).
		OmitZero().
		Exec(ctx)

	if err != nil {
		log.Printf("Database operation error during token revocation: %v", err)
		return nil
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected during token revocation: %v", err)
		return nil
	}

	if rowsAffected == 0 {
		log.Println("No active tokens found to revoke for the given authorization ID.")
		return nil
	}

	return nil
}

func revokeTokenByID(ctx context.Context, db bun.IDB, id uuid.UUID, reason *string) errors.OIDCError {
	var result sql.Result
	var err error

	isActive := false
	revokedAt := time.Now().UTC()

	token := Token{
		ID:               id,
		RevocationReason: reason,
		IsActive:         &isActive,
		RevokedAt:        &revokedAt,
	}

	result, err = db.NewUpdate().
		Model(&token).
		WherePK().
		Where("\"token\".\"is_active\" = ?", true).
		Where("\"token\".\"expires_at\" > ?", time.Now()).
		OmitZero().
		Exec(ctx)

	if err != nil {
		log.Printf("Database operation error during token revocation: %v", err)
		return nil
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected during token revocation: %v", err)
		return nil
	}

	if rowsAffected == 0 {
		log.Println("No active token found to revoke.")
		return nil
	}

	return nil
}

func CreateToken(ctx context.Context, db bun.IDB, tokenType string, obj interface{}) (*Token, errors.OIDCError) {
	switch tokenType {
	case string(utils.AUTHORIZATION_CODE_TYPE), string(utils.ACCESS_TOKEN_TYPE), string(utils.REFRESH_TOKEN_TYPE):
		return createToken(ctx, db, utils.TokenType(tokenType), obj)
	case string(utils.CLIENT_CREDENTIALS_TYPE):
		return createClientCredentialsToken(ctx, db, obj)
	case utils.CUSTOM_TOKEN_TYPE:
		return createCustomToken(ctx, db, obj)
	default:
		msg := fmt.Sprintf("Unsupported token type: %s", tokenType)
		log.Printf("%s", msg)
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}
}

func ExchangeToken(ctx context.Context, db bun.IDB, tr *tokenRequest) (map[utils.TokenType]*Token, errors.OIDCError) {
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

	var authorizationCode Token
	var err error

	query := newTokenQuery(db, *tr.Code, string(utils.AUTHORIZATION_CODE_TYPE)).
		addAuthorization(true, true, "Authorization", "authorization", "token").
		query

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
	authorizationCode = Token{
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

	var tokens = make(map[utils.TokenType]*Token)

	accessToken, tokenErr := createToken(ctx, db, utils.ACCESS_TOKEN_TYPE, auth)
	if tokenErr != nil {
		return nil, tokenErr
	}
	tokens[utils.ACCESS_TOKEN_TYPE] = accessToken

	if auth.Scope != nil && utils.ContainsValue(auth.Scope, utils.OFFLINE_ACCESS) {
		refreshToken, tokenErr := createToken(ctx, db, utils.REFRESH_TOKEN_TYPE, auth)
		if tokenErr != nil {
			return nil, tokenErr
		}
		tokens[utils.REFRESH_TOKEN_TYPE] = refreshToken
	}

	return tokens, nil
}

func GetTokenByValue(ctx context.Context, db bun.IDB, value string, excludeColumns ...string) (*Token, errors.OIDCError) {
	excludeColumns = append(excludeColumns, "token_value")

	var token Token
	tokenQuery := newTokenQuery(db, value, "").
		addAuthorization(false, true, "Authorization", "authorization", "token").
		addClient(false, "Client", "client", "token").
		addUser(false, "User", "user", "token")

	err := tokenQuery.query.
		ExcludeColumn(excludeColumns...).
		Scan(ctx, &token)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusNotFound,
				Title:      errors.NOT_FOUND,
				Detail:     "Token not found or inactive.",
			}
		}

		log.Printf("Database operation error: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     "Database operation resulted in an error.",
		}
	}

	return &token, nil
}

func RevokeTokenByValue(ctx context.Context, db bun.IDB, tokenValue string, tokenTypeHint *string) errors.OIDCError {
	if tokenValue == "" {
		return nil
	}

	reason := "revoked by client request"

	var err error
	var retrievedToken Token

	tokenType := ""
	if tokenTypeHint != nil && *tokenTypeHint != "" {
		tokenType = *tokenTypeHint
	}

	err = newTokenQuery(db, tokenValue, tokenType).query.
		Column("authorization_id", "token_type", "token_id").
		Scan(ctx, &retrievedToken)

	if err != nil {
		// Do not reveal whether the token existed or not
		return nil
	}

	switch retrievedToken.Type {
	case utils.REFRESH_TOKEN_TYPE:
		return revokeTokensByAuthorizationID(ctx, db, *retrievedToken.AuthorizationID, &reason)
	case utils.ACCESS_TOKEN_TYPE:
		return revokeTokenByID(ctx, db, retrievedToken.ID, &reason)
	default:
		// return error for unsupported token types
		msg := fmt.Sprintf("Unsupported token type for revocation: %s", retrievedToken.Type)
		log.Printf("%s", msg)
		return errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.UNSUPPORTED_TOKEN_TYPE,
			Description: &msg,
		}
	}
}

func RotateToken(ctx context.Context, db bun.IDB, tr *tokenRequest) (map[utils.TokenType]*Token, errors.OIDCError) {
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

	var currentToken Token
	tokenQuery := newTokenQuery(db, *tr.RefreshToken, string(utils.REFRESH_TOKEN_TYPE)).
		addAuthorization(true, true, "Authorization", "authorization", "token")

	if tr.ClientSecret != nil && *tr.ClientSecret != "" {
		tokenQuery.query = tokenQuery.query.
			Where("\"authorization__client\".\"client_secret\" = ?", utils.HashedString(*tr.ClientSecret))
	}

	if tr.CodeVerifier != nil && *tr.CodeVerifier != "" {
		tokenQuery.query = tokenQuery.query.
			Where("\"authorization\".\"code_challenge\" = ?", utils.GeneratePKCEChallenge(*tr.CodeVerifier))
	}

	err := tokenQuery.query.
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

	tokens := make(map[utils.TokenType]*Token)

	// Create new refresh token
	newRefreshToken, err := createToken(ctx, db, utils.REFRESH_TOKEN_TYPE, auth)
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
	newAccessToken, err := createToken(ctx, db, utils.ACCESS_TOKEN_TYPE, auth)
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
