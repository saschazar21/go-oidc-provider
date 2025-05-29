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

type Authorization struct {
	bun.BaseModel `bun:"table:oidc_authorizations"` // Base model for the authorization table

	ID uuid.UUID `json:"-" bun:"authorization_id,pk,type:uuid,default:gen_random_uuid()"` // Unique identifier for the authorization

	Scope           []utils.Scope           `json:"scope" validate:"required,dive,scope" bun:"scope,type:oidc_standard_scope[],notnull"` // List of scopes associated with the authorization
	ClaimsRequested *map[string]interface{} `json:"claims_requested,omitempty" bun:"claims_requested,type:jsonb"`                        // Optional claims requested by the client, stored as JSON
	ClaimsGranted   *map[string]interface{} `json:"claims_granted,omitempty" bun:"claims_granted,type:jsonb"`                            // Optional claims granted by the authorization server, stored as JSON
	RedirectURI     string                  `json:"redirect_uri" validate:"required,uri" bun:"redirect_uri,notnull"`
	ResponseType    utils.ResponseType      `json:"response_type" validate:"required,response-type" bun:"response_type,type:oidc_response_type,notnull"`

	CodeChallenge       *string           `json:"code_challenge,omitempty" bun:"code_challenge"`                                                // Code challenge for PKCE, if applicable
	CodeChallengeMethod *utils.PKCEMethod `json:"code_challenge_method,omitempty" validate:"omitempty,pkce-method" bun:"code_challenge_method"` // Method used for the code challenge, if applicable

	State *string `json:"state,omitempty" bun:"state"` // State parameter for the authorization request, if applicable
	Nonce *string `json:"nonce,omitempty" bun:"nonce"` // Nonce parameter for the authorization request, if applicable

	IsActive bool              `json:"is_active" bun:"is_active"`
	Status   *utils.AuthStatus `json:"status" validate:"omitempty,auth-status" bun:"status"` // Status of the authorization (e.g., approved, pending, denied, revoked)

	ClientID string  `json:"-" validate:"required" bun:"client_id,notnull"`     // ID of the client associated with the authorization
	Client   *Client `json:"client" bun:"rel:has-one,join:client_id=client_id"` // Client associated with the authorization

	UserID uuid.UUID `json:"-" bun:"user_id,type:uuid,nullzero"`          // ID of the user associated with the authorization
	User   *User     `json:"user" bun:"rel:has-one,join:user_id=user_id"` // User associated with the authorization

	ReplacedID            uuid.UUID      `json:"-" bun:"replaced_id,type:uuid,nullzero"`
	ReplacedAuthorization *Authorization `json:"replaced_authorization" bun:"rel:has-one,join:authorization_id=replaced_id"`

	ApprovedAt *time.Time `json:"approved_at,omitempty" bun:"approved_at"` // Timestamp when the authorization was approved, if applicable
	RevokedAt  *time.Time `json:"revoked_at,omitempty" bun:"revoked_at"`   // Timestamp when the authorization was revoked, if applicable
	CreatedAt
	ExpiresAt
}

var _ bun.BeforeInsertHook = (*Authorization)(nil)

func (a *Authorization) deactivatePreviousAuthorizations(ctx context.Context, db bun.IDB) errors.OIDCError {
	if a.UserID == uuid.Nil || !a.IsActive {
		return nil
	}

	// TODO: rewrite authorization reference in tokens to new authorization

	var replacedAuthorizations []Authorization
	err := db.NewSelect().
		Model((*Authorization)(nil)).
		Where("\"authorization\".\"is_active\" = ? AND \"authorization\".\"user_id\" = ? AND \"authorization\".\"client_id\" = ?", true, a.UserID, a.ClientID).
		Relation("Client").
		Relation("User").
		Order("created_at DESC").
		Scan(ctx, &replacedAuthorizations)

	if err != nil {
		log.Printf("Error retrieving authorization: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	if len(replacedAuthorizations) == 0 {
		return nil
	}

	for _, replacedAuth := range replacedAuthorizations {
		replacedAuth.IsActive = false
		replacedAuth.ExpiresAt.ExpiresAt = time.Now().UTC().Add(time.Hour * 24 * 30)

		if err := replacedAuth.Save(ctx, db); err != nil {
			log.Printf("Error deactivating previous authorization %v: %v", replacedAuth.ID, err)
			return errors.OIDCErrorResponse{
				ErrorCode:   errors.SERVER_ERROR,
				RedirectURI: a.RedirectURI,
			}
		}
	}

	a.ReplacedID = replacedAuthorizations[0].ID
	a.ReplacedAuthorization = &replacedAuthorizations[0]

	return nil
}

func (a *Authorization) BeforeInsert(ctx context.Context, query *bun.InsertQuery) error {
	if !a.CreatedAt.CreatedAt.IsZero() {
		return fmt.Errorf("CreatedAt should not be set before insert, was %v", a.CreatedAt.CreatedAt)
	}

	if a.ExpiresAt.ExpiresAt.IsZero() {
		a.ExpiresAt.ExpiresAt = time.Now().UTC().Add(time.Minute * 10) // Default expiration time of 10 minutes (initial)
	}

	return nil
}

func (a *Authorization) Save(ctx context.Context, db bun.IDB) errors.OIDCError {
	if a.ExpiresAt.ExpiresAt.IsZero() {
		a.ExpiresAt.ExpiresAt = time.Now().UTC().Add(time.Minute * 10) // Default expiration time of 10 minutes (initial)
	}

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

	// TODO: rewrite authorization reference in tokens to new authorization

	return nil
}

func GetAuthorizationByID(ctx context.Context, db bun.IDB, id string) (*Authorization, errors.HTTPError) {
	if id == "" {
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
