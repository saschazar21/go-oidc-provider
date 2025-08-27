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

const TOKEN_DEFAULT_RANDOM_LENGTH = 24

type Token struct {
	bun.BaseModel `bun:"oidc_tokens"`

	ID          uuid.UUID          `json:"-" schema:"-" bun:"token_id,pk,type:uuid,default:gen_random_uuid()"`                                        // Unique identifier for the token
	Type        utils.TokenType    `json:"type" schema:"type,required" validate:"required,token-type" bun:"token_type,notnull"`                       // Type of the token (e.g., access token, refresh token)
	Value       utils.HashedString `json:"token,omitempty" schema:"token,omitempty" validate:"required_without=ID" bun:"token_value,notnull"`         // Hashed value of the token for security
	RedirectURI *string            `json:"redirect_uri,omitempty" schema:"redirect_uri,omitempty" validate:"omitempty,uri,lt=512" bun:"redirect_uri"` // Optional redirect URI associated with the token

	IsActive         bool    `json:"is_active" schema:"-" bun:"is_active,default:true"`                                          // Indicates if the token is active
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
	CreatedAt
	ExpiresAt
}

var _ bun.BeforeAppendModelHook = (*Token)(nil)

func (m *Token) save(ctx context.Context, db bun.IDB, excludeColumns ...string) errors.OIDCError {
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
		result, err = db.NewInsert().
			Model(m).
			Returning("*").
			ExcludeColumn(excludeColumns...).
			Returning("*").
			Exec(ctx)
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
			// Set default expiration to 5 minutes if not set
			m.ExpiresAt.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
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

func generateTokenValue() (*utils.HashedString, error) {
	tokenValue, err := utils.RandomBase58String(TOKEN_DEFAULT_RANDOM_LENGTH)
	if err != nil {
		log.Printf("Error generating token value: %v", err)
		return nil, fmt.Errorf("failed to generate token value")
	}

	hashedToken := utils.HashedString(tokenValue)
	if err != nil {
		log.Printf("Error hashing token value: %v", err)
		return nil, fmt.Errorf("failed to generate token value")
	}

	return &hashedToken, nil
}

func CreateToken(ctx context.Context, db bun.IDB, tokenType utils.TokenType, authorization *Authorization) (*Token, errors.OIDCError) {
	token := Token{
		Type:            tokenType,
		AuthorizationID: &authorization.ID,
	}

	hashedValue, err := generateTokenValue()
	if err != nil {
		description := "Failed to generate token value."

		return nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &description,
			RedirectURI:      authorization.RedirectURI,
		}
	}

	token.Value = *hashedValue // Set the unhashed token value only on creation

	if err := token.save(ctx, db); err != nil {
		return nil, err
	}

	token.Value = *hashedValue // Return the unhashed token value only on creation

	return &token, nil
}

func CreateClientCredentialsToken(ctx context.Context, db bun.IDB, client *Client) (*Token, errors.OIDCError) {
	if client == nil || client.ID == "" {
		msg := "Client ID is required to create a client credentials token."
		log.Printf("%s", msg)

		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     msg,
		}
	}

	token := Token{
		Type:     utils.CLIENT_CREDENTIALS_TYPE,
		ClientID: &client.ID,
		ExpiresAt: ExpiresAt{
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute), // Default expiration to 5 minutes
		},
	}

	hashedValue, err := generateTokenValue()
	if err != nil {
		description := "Failed to generate token value."

		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     description,
		}
	}

	token.Value = *hashedValue // Set the unhashed token value only on creation

	if err := token.save(ctx, db); err != nil {
		return nil, err
	}

	token.Value = *hashedValue // Return the unhashed token value only on creation

	return &token, nil
}

func CreateCustomToken(ctx context.Context, db bun.IDB, token *Token) (*Token, errors.OIDCError) {
	if token.User == nil && (token.UserID == nil || *token.UserID == uuid.Nil) {
		msg := "User is required to create a custom token."
		log.Printf("%s", msg)

		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     msg,
		}
	}

	userID := token.UserID
	if userID == nil || *userID == uuid.Nil {
		userID = &token.User.ID
	}

	expiresAt := token.ExpiresAt
	if expiresAt.ExpiresAt.IsZero() {
		// Set default expiration to 24 hours if not set
		expiresAt.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	}

	t := Token{
		Type:        utils.ACCESS_TOKEN_TYPE,
		IsCustom:    true,
		UserID:      userID,
		Description: token.Description,
		Scope:       token.Scope,
		ExpiresAt:   expiresAt,
	}

	hashedValue, err := generateTokenValue()
	if err != nil {
		description := "Failed to generate token value."

		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     description,
		}
	}

	t.Value = *hashedValue // Set the unhashed token value only on creation

	if err := t.save(ctx, db); err != nil {
		return nil, err
	}

	t.Value = *hashedValue // Return the unhashed token value only on creation

	return &t, nil
}

func GetTokenByValue(ctx context.Context, db bun.IDB, tokenValue string, excludeColumns ...string) (*Token, errors.OIDCError) {
	hashedValue := utils.HashedString(tokenValue)

	excludeColumns = append(excludeColumns, "token_value")

	var token Token
	err := db.NewSelect().
		Model(&token).
		Where("\"token\".\"token_value\" = ?", hashedValue).
		Where("\"token\".\"is_active\" = ?", true).
		Where("\"token\".\"expires_at\" > ?", time.Now()).
		Relation("Authorization").
		Relation("Client").
		Relation("User").
		ExcludeColumn(excludeColumns...).
		Scan(ctx)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusNotFound,
				Title:      errors.NOT_FOUND,
				Detail:     "Token not found or inactive.",
			}
		}

		log.Printf("Error retrieving token by value: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     "Failed to retrieve token from database.",
		}
	}

	return &token, nil
}
