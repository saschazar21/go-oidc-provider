package models

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

const (
	AUTHORIZATION_GRANT_LIFETIME          = time.Hour * 24 * 60 // Lifetime of an authorization grant
	REPLACED_AUTHORIZATION_GRANT_LIFETIME = time.Hour * 24 * 30 // Lifetime of a replaced authorization grant
)

type Authorization struct {
	bun.BaseModel `bun:"table:oidc_authorizations"` // Base model for the authorization table

	ID uuid.UUID `json:"-" bun:"authorization_id,pk,type:uuid,default:gen_random_uuid()"` // Unique identifier for the authorization

	Scope           []utils.Scope           `json:"scope" schema:"scope,required" validate:"required,dive,scope" bun:"scope,type:oidc_standard_scope[],notnull"`  // List of scopes associated with the authorization
	ACRValues       *[]utils.ACR            `json:"acr_values,omitempty" schema:"acr_values" validate:"omitempty,dive,acr" bun:"acr_values,type:oidc_acr_type[]"` // Authentication Context Class Reference values
	ClaimsRequested *map[string]interface{} `json:"claims_requested,omitempty" schema:"-" bun:"claims_requested,type:jsonb"`                                      // Optional claims requested by the client, stored as JSON
	ClaimsGranted   *map[string]interface{} `json:"claims_granted,omitempty" schema:"-" bun:"claims_granted,type:jsonb"`                                          // Optional claims granted by the authorization server, stored as JSON
	RedirectURI     string                  `json:"redirect_uri" schema:"redirect_uri,required" validate:"required,uri" bun:"redirect_uri,notnull"`
	ResponseType    utils.ResponseType      `json:"response_type" schema:"response_type,required" validate:"required,response-type" bun:"response_type,type:oidc_response_type,notnull"`

	CodeChallenge       *string           `json:"code_challenge,omitempty" schema:"code_challenge" bun:"code_challenge"`                                                       // Code challenge for PKCE, if applicable
	CodeChallengeMethod *utils.PKCEMethod `json:"code_challenge_method,omitempty" schema:"code_challenge_method" validate:"omitempty,pkce-method" bun:"code_challenge_method"` // Method used for the code challenge, if applicable

	State *string `json:"state,omitempty" schema:"state" bun:"state"` // State parameter for the authorization request, if applicable
	Nonce *string `json:"nonce,omitempty" schema:"nonce" bun:"nonce"` // Nonce parameter for the authorization request, if applicable

	IsActive bool              `json:"is_active" schema:"-" bun:"is_active"`
	Status   *utils.AuthStatus `json:"status" schema:"-" validate:"omitempty,auth-status" bun:"status"` // Status of the authorization (e.g., approved, pending, denied, revoked)

	ClientID string  `json:"-" schema:"client_id,required" validate:"required" bun:"client_id,notnull"` // ID of the client associated with the authorization
	Client   *Client `json:"client" schema:"-" bun:"rel:has-one,join:client_id=client_id"`              // Client associated with the authorization

	UserID uuid.UUID `json:"-" schema:"-" bun:"user_id,type:uuid,nullzero"`          // ID of the user associated with the authorization
	User   *User     `json:"user" schema:"-" bun:"rel:has-one,join:user_id=user_id"` // User associated with the authorization

	ReplacedID            uuid.UUID      `json:"-" schema:"-" bun:"replaced_id,type:uuid,nullzero"`
	ReplacedAuthorization *Authorization `json:"replaced_authorization" schema:"-" bun:"rel:has-one,join:replaced_id=authorization_id"`

	// Additional request parameters for the authorization
	ClientSecret *string       `json:"-" schema:"client_secret" bun:"-"`                                     // Optional client secret for the authorization, if applicable
	LoginHint    *string       `json:"login_hint,omitempty" schema:"login_hint" bun:"-"`                     // Optional login hint for the authorization, if applicable
	MaxAge       uint16        `json:"max_age,omitempty" schema:"max_age" validate:"omitempty,gt=0" bun:"-"` // Optional maximum age for the authorization, in seconds
	Prompt       *utils.Prompt `json:"prompt,omitempty" schema:"prompt" validate:"omitempty,prompt" bun:"-"` // Optional prompt parameter for the authorization, if applicable

	ApprovedAt *time.Time `json:"approved_at,omitempty" bun:"approved_at"` // Timestamp when the authorization was approved, if applicable
	RevokedAt  *time.Time `json:"revoked_at,omitempty" bun:"revoked_at"`   // Timestamp when the authorization was revoked, if applicable

	CreatedAt
	ExpiresAt
}

var _ bun.AfterScanRowHook = (*Authorization)(nil)
var _ bun.BeforeAppendModelHook = (*Authorization)(nil)

func (a *Authorization) deactivatePreviousAuthorizations(ctx context.Context, db bun.IDB) errors.OIDCError {
	if a.UserID == uuid.Nil || !a.IsActive {
		return nil
	}

	now := time.Now().UTC()

	var err error
	var replacedAuthorizations []Authorization
	var result sql.Result

	query := db.NewSelect().
		Model((*Authorization)(nil)).
		Where("\"authorization\".\"is_active\" = ?", true).
		Where("\"authorization\".\"user_id\" = ?", a.UserID).
		Where("\"authorization\".\"client_id\" = ?", a.ClientID).
		Order("created_at DESC").
		Column("authorization_id")

	_, err = db.NewUpdate().
		With("_auth", query).
		Model((*Token)(nil)).
		TableExpr("_auth").
		Where("\"token\".\"is_active\" = ?", true).
		Where("\"token\".\"authorization_id\" = \"_auth\".\"authorization_id\"").
		Set("is_active = ?", false).
		Set("revoked_at = ?", now).
		Set("revocation_reason = ?", "revoked by new authorization grant").
		Exec(ctx)

	if err != nil {
		log.Printf("Failed to revoke tokens from previous authorizations: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	result, err = db.NewUpdate().
		With("_auth", query).
		Model((*Authorization)(nil)).
		TableExpr("_auth").
		Where("\"authorization\".\"authorization_id\" = \"_auth\".\"authorization_id\"").
		Set("is_active = ?", false).
		Set("revoked_at = ?", now).
		Set("expires_at = ?", now.Add(REPLACED_AUTHORIZATION_GRANT_LIFETIME)). // Set expiration to 30 days from now
		Returning("*").
		OmitZero().
		Exec(ctx, &replacedAuthorizations)

	if err != nil {
		log.Printf("Failed to revoke previous authorizations: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	if rowsAffected == 0 {
		return nil
	}

	a.ReplacedID = replacedAuthorizations[0].ID
	a.ReplacedAuthorization = &replacedAuthorizations[0]

	return nil
}

func (a *Authorization) AfterScanRow(ctx context.Context) error {
	if a.User != nil {
		a.User.Hydrate()
	}

	if a.Client != nil && a.Client.Owner != nil {
		a.Client.Owner.Hydrate()
	}

	if a.ReplacedAuthorization != nil && a.ReplacedAuthorization.User != nil {
		a.ReplacedAuthorization.User.Hydrate()
	}

	return nil
}

func (a *Authorization) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		now := time.Now().UTC()

		a.CreatedAt.CreatedAt = now

		if a.ExpiresAt.ExpiresAt.IsZero() {
			a.ExpiresAt.ExpiresAt = now.Add(AUTHORIZATION_CODE_TOKEN_LIFETIME) // Default expiration equals authorization code lifetime
		}
	case *bun.UpdateQuery:
		// No special handling needed for updates at the moment
	}

	return nil
}

func (a *Authorization) IsApproved() bool {
	return a.IsActive && a.Status != nil && *a.Status == utils.APPROVED
}

func (a *Authorization) Save(ctx context.Context, db bun.IDB) errors.OIDCError {
	if err := a.Validate(); err != nil {
		return err
	}

	if err := a.deactivatePreviousAuthorizations(ctx, db); err != nil {
		log.Println("Deactivating previous authorizations failed.")
		return err
	}

	var err error
	var isExisting bool
	var result sql.Result

	if a.ID != uuid.Nil {
		isExisting, err = db.NewSelect().
			Model(a).
			WherePK().
			Column("authorization_id").
			Exists(ctx)

		if err != nil {
			log.Printf("Error checking if authorization exists: %v", err)
			return errors.OIDCErrorResponse{
				ErrorCode:   errors.SERVER_ERROR,
				RedirectURI: a.RedirectURI,
			}
		}

		if !isExisting {
			log.Printf("Authorization with ID %s does not exist", a.ID)
			return errors.OIDCErrorResponse{
				ErrorCode:   errors.INVALID_REQUEST,
				RedirectURI: a.RedirectURI,
			}
		}

		result, err = db.NewUpdate().
			Model(a).
			WherePK().
			ExcludeColumn("created_at").
			Returning("*").
			Exec(ctx, a)
	} else {
		result, err = db.NewInsert().
			Model(a).
			Returning("*").
			Exec(ctx, a)
	}

	if err != nil {
		log.Printf("Database operation error: %v", err)
		description := "Failed to store the authorization in the database."
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &description,
			RedirectURI:      a.RedirectURI,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	if rowsAffected == 0 {
		log.Println("No rows affected during authorization save operation.")
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	return nil
}

func GetAuthorizationByID(ctx context.Context, db bun.IDB, id string) (*Authorization, errors.HTTPError) {
	if id == "" || id == uuid.Nil.String() {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The authorization ID must be provided.",
		}
	}

	var authorization Authorization
	err := db.NewSelect().
		Model(&authorization).
		Where("\"authorization\".\"authorization_id\" = ?", id).
		Relation("Client").
		Relation("User").
		Relation("Client.Owner").
		Relation("ReplacedAuthorization").
		Scan(ctx)

	if err != nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusNotFound,
			Message:     errors.NOT_FOUND,
			Description: "The requested authorization was not found.",
		}
	}

	return &authorization, nil
}

func GetAuthorizationByClientAndUser(ctx context.Context, db bun.IDB, clientID string, userID uuid.UUID) (*Authorization, errors.HTTPError) {
	if clientID == "" || userID == uuid.Nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "Both client ID and user ID must be provided.",
		}
	}

	var authorization Authorization
	err := db.NewSelect().
		Model(&authorization).
		Where("\"authorization\".\"client_id\" = ? AND \"authorization\".\"user_id\" = ? AND \"authorization\".\"is_active\" = ?", clientID, userID, true).
		Relation("Client").
		Relation("User").
		Relation("Client.Owner").
		Relation("ReplacedAuthorization").
		Scan(ctx)

	if err != nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusNotFound,
			Message:     errors.NOT_FOUND,
			Description: "The requested authorization was not found.",
		}
	}

	return &authorization, nil
}
