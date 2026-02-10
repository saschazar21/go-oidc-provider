package models

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

const RANDOM_TOKEN_LENGTH = 6 // Length of the random token for Magic Link

type MagicLinkToken struct {
	bun.BaseModel `bun:"table:oidc_magic_link_tokens"`

	ID        uuid.UUID              `json:"-" schema:"-" bun:"token_id,pk,type:uuid,default:gen_random_uuid()"`                 // Unique identifier for the token
	Token     *utils.HashedString    `json:"-" schema:"token,required" bun:"token,type:bytea,notnull"`                           // Hashed token value
	Email     *utils.HashedString    `json:"-" schema:"email,required" validate:"required,email" bun:"email,type:bytea,notnull"` // Hashed email address associated with the token
	IPAddress *utils.EncryptedString `json:"-" schema:"-" validate:"omitempty,ip|hostname_port" bun:"ip_address,type:bytea"`     // Encrypted IP address of the user
	UserAgent *string                `json:"-" schema:"-" bun:"user_agent"`                                                      // User agent string of the user

	IsActive *bool         `json:"-" schema:"-" bun:"is_active,default:true"`             // Whether the token is active
	Result   *utils.Result `json:"-" schema:"-" validate:"omitempty,result" bun:"result"` // Result of the token validation (e.g., success, failed, expired)

	User *User `json:"-" schema:"-" bun:"rel:belongs-to,join:email=email_hash"` // User associated with the token

	ConsumedAt *time.Time `json:"-" schema:"-" bun:"consumed_at"` // Timestamp when the token was consumed, if applicable
	CreatedAt
	ExpiresAt
	UpdatedAt
}

var _ bun.AfterScanRowHook = (*MagicLinkToken)(nil)
var _ bun.BeforeAppendModelHook = (*MagicLinkToken)(nil)

func (m *MagicLinkToken) determineResult(ctx context.Context, db bun.IDB) (*utils.Result, errors.HTTPError) {
	token := m.Token // store token temporarily, as it will be cleared during NewSelect() scan
	err := db.NewSelect().
		Model(m).
		WherePK().
		Relation("User", func(sq *bun.SelectQuery) *bun.SelectQuery {
			return sq.
				Where("\"user\".\"is_active\" = ?", true).
				Where("\"user\".\"is_locked\" = ?", false)
		}).
		Column("is_active", "result", "consumed_at", "expires_at").
		Scan(ctx)

	if err != nil {
		log.Printf("Error retrieving Magic Link token status: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusNotFound,
			Title:      "Not Found",
			Detail:     fmt.Sprintf("Magic Link token %s not found.", m.ID.String()),
		}
	}

	if m.Result != nil {
		if *m.Result == utils.SUCCESS {
			log.Printf("Magic Link token %s has already been consumed successfully.", m.ID.String())
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusBadRequest,
				Title:      "Magic Link Token Already Consumed",
				Detail:     "This Magic Link token has already been consumed.",
			}
		}

		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Magic Link Token",
			Detail:     "This Magic Link token is invalid.",
		}
	}

	if m.ExpiresAt.ExpiresAt.Before(time.Now().UTC()) {
		result := utils.EXPIRED
		return &result, nil
	}

	err = db.NewSelect().
		Model(m).
		WherePK().
		Where("token = ?", token).
		Column("token_id").
		Scan(ctx)

	if err != nil {
		result := utils.FAILED
		return &result, nil
	}

	result := utils.SUCCESS
	return &result, nil
}

func (m *MagicLinkToken) isUserExisting(ctx context.Context, db bun.IDB) (bool, errors.HTTPError) {
	if m.Email == nil || *m.Email == "" {
		return false, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "Email must be provided to check user existence.",
		}
	}

	isExisting, err := db.NewSelect().
		Model((*User)(nil)).
		Where("\"user\".\"email_hash\" = ?", *m.Email).
		Where("\"user\".\"is_active\" = ?", true).
		Where("\"user\".\"is_locked\" = ?", false).
		Exists(ctx)

	if err != nil {
		log.Printf("Error checking user existence by email: %v", err)
		return false, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to check user existence in the database.",
		}
	}

	return isExisting, nil

}

func (m *MagicLinkToken) save(ctx context.Context, db bun.IDB) errors.HTTPError {
	if err := m.Validate(); err != nil {
		log.Printf("Failed to validate Magic Link token: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Bad Request",
			Detail:     "Invalid Magic Link token data.",
		}
	}

	var err error
	var isExisting bool
	var result sql.Result
	var token string

	isExisting, err = m.isUserExisting(ctx, db)
	if err != nil {
		httpErr, _ := err.(errors.HTTPErrorResponse)
		return httpErr
	}

	if !isExisting {
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Email",
			Detail:     "No active user found with the provided email.",
		}
	}

	email := *m.Email // Store email to restore after hashing

	if m.ID == uuid.Nil {
		token, err = utils.RandomDigitString(RANDOM_TOKEN_LENGTH)
		if err != nil {
			log.Printf("Error generating random token: %v", err)
			return errors.JSONAPIError{
				StatusCode: http.StatusInternalServerError,
				Title:      "Internal Server Error",
				Detail:     "Failed to generate Magic Link token.",
			}
		}

		hashedToken := utils.HashedString(token)
		m.Token = &hashedToken // Set the hashed token in the struct

		result, err = db.NewInsert().
			Model(m).
			ExcludeColumn("created_at", "updated_at", "expires_at", "consumed_at", "result", "is_active").
			Returning("*").
			Exec(ctx)
	} else {
		result, err = db.NewUpdate().
			Model(m).
			WherePK().
			OmitZero().
			ExcludeColumn("created_at", "updated_at", "email", "token").
			Returning("*").
			Exec(ctx)
	}

	if err != nil {
		log.Printf("Error saving Magic Link token to the database: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to save Magic Link token to the database.",
		}
	}

	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
		log.Println("No rows affected during Magic Link token save operation.")
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Magic Link Token",
			Detail:     "Failed to save Magic Link token due to invalid format.",
		}
	}

	if token != "" {
		hashedToken := utils.HashedString(token)
		m.Token = &hashedToken // Set the plaintext token in the struct
	} else {
		m.Token = nil // Clear the token field for obscurity
	}

	m.Email = &email // Restore email after hashing

	return nil
}

func (m *MagicLinkToken) AfterScanRow(ctx context.Context) error {
	if m.User != nil {
		m.User.Hydrate()
	}

	m.Token = nil // Clear the token field for obscurity

	return nil
}

func (m *MagicLinkToken) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	now := time.Now().UTC()

	switch query.(type) {
	case *bun.InsertQuery:
		m.CreatedAt.CreatedAt = now
		m.UpdatedAt.UpdatedAt = now
		m.ExpiresAt.ExpiresAt = now.Add(5 * time.Minute) // Default expiration
	case *bun.UpdateQuery:
		m.UpdatedAt.UpdatedAt = now
	}

	return nil
}

func ConsumeMagicLinkToken(ctx context.Context, db bun.IDB, id string, token string, meta ...string) (*MagicLinkToken, errors.HTTPError) {
	if id == "" || id == uuid.Nil.String() {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Bad Request",
			Detail:     "The Magic Link token ID must be provided.",
		}
	}

	if token == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Bad Request",
			Detail:     "The Magic Link token must be provided.",
		}
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Bad Request",
			Detail:     "The Magic Link token ID is not a valid UUID.",
		}
	}

	hashedToken := utils.HashedString(token)

	m := MagicLinkToken{
		ID:    uid,
		Token: &hashedToken,
	}

	result, err := m.determineResult(ctx, db)
	if err != nil {
		httpErr, _ := err.(errors.JSONAPIError)
		return nil, httpErr
	}

	consumedAt := time.Now().UTC()
	isActive := false
	user := m.User
	email := utils.HashedString(*user.Email) // Store email hash

	m = MagicLinkToken{
		ID:       uid,
		Email:    &email,
		IsActive: &isActive,
		Result:   result,
	}

	if result != nil && *result == utils.SUCCESS {
		m.ConsumedAt = &consumedAt
		m.User = user
	}

	if len(meta) > 0 && len(meta[0]) > 0 {
		ipAddress := utils.EncryptedString(meta[0])
		m.IPAddress = &ipAddress
	}

	if len(meta) > 1 && len(meta[1]) > 0 {
		userAgent := meta[1]
		m.UserAgent = &userAgent
	}

	err = m.save(ctx, db)
	if err != nil {
		httpErr, _ := err.(errors.JSONAPIError)
		return nil, httpErr
	}

	return &m, nil
}

func CreateMagicLinkToken(ctx context.Context, db bun.IDB, email string, meta ...string) (*MagicLinkToken, errors.HTTPError) {
	if email == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Bad Request",
			Detail:     "Email is required to create a Magic Link token.",
		}
	}

	hashedEmail := utils.HashedString(email)
	token := MagicLinkToken{
		Email: &hashedEmail,
	}

	if len(meta) > 0 && len(meta[0]) > 0 {
		ipAddress := utils.EncryptedString(meta[0])
		token.IPAddress = &ipAddress
	}

	if len(meta) > 1 && len(meta[1]) > 0 {
		userAgent := meta[1]
		token.UserAgent = &userAgent
	}

	if err := token.save(ctx, db); err != nil {
		return nil, err
	}

	return &token, nil
}

func GetMagicLinkTokenByID(ctx context.Context, db bun.IDB, id string) (*MagicLinkToken, errors.HTTPError) {
	if id == "" || id == uuid.Nil.String() {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The Magic Link token ID must be provided.",
		}
	}

	var token MagicLinkToken
	err := db.NewSelect().
		Model(&token).
		Relation("User", func(sq *bun.SelectQuery) *bun.SelectQuery {
			return sq.
				Where("\"user\".\"is_active\" = ?", true).
				Where("\"user\".\"is_locked\" = ?", false)
		}).
		Where("\"magic_link_token\".\"token_id\" = ?", id).
		ExcludeColumn("token", "email").
		Scan(ctx)

	if err != nil {
		log.Printf("Error retrieving Magic Link token by ID: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to retrieve Magic Link token from the database.",
		}
	}

	return &token, nil
}
