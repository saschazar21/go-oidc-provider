package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type Authorization struct {
	ID uuid.UUID `json:"-" bun:"id,pk,type:uuid,default:gen_random_uuid()"` // Unique identifier for the authorization

	Scope           []utils.Scope     `json:"scope" validate:"required,dive,scope" bun:"scope,type:oidc_standard_scope[],notnull"` // List of scopes associated with the authorization
	ClaimsRequested utils.Marshalable `json:"claims_requested,omitempty" bun:"claims_requested,type:jsonb"`                        // Optional claims requested by the client, stored as JSON
	ClaimsGranted   utils.Marshalable `json:"claims_granted,omitempty" bun:"claims_granted,type:jsonb"`                            // Optional claims granted by the authorization server, stored as JSON

	CodeChallenge       *string           `json:"code_challenge,omitempty" bun:"code_challenge"`                                                // Code challenge for PKCE, if applicable
	CodeChallengeMethod *utils.PKCEMethod `json:"code_challenge_method,omitempty" validate:"omitempty,pkce-method" bun:"code_challenge_method"` // Method used for the code challenge, if applicable

	State *string `json:"state,omitempty" bun:"state"` // State parameter for the authorization request, if applicable
	Nonce *string `json:"nonce,omitempty" bun:"nonce"` // Nonce parameter for the authorization request, if applicable

	Status utils.AuthStatus `json:"status" validate:"omitempty,auth-status" bun:"status"` // Status of the authorization (e.g., approved, pending, denied, revoked)

	ClientID string  `json:"-" validate:"required" bun:"client_id,notnull"`     // ID of the client associated with the authorization
	Client   *Client `json:"client" bun:"rel:has-one,join:client_id=client_id"` // Client associated with the authorization

	UserID uuid.UUID `json:"-" validate:"required" bun:"user_id,notnull"` // ID of the user associated with the authorization
	User   *User     `json:"user" bun:"rel:has-one,join:user_id=user_id"` // User associated with the authorization

	ApprovedAt *time.Time `json:"approved_at,omitempty" bun:"approved_at"` // Timestamp when the authorization was approved, if applicable
	RevokedAt  *time.Time `json:"revoked_at,omitempty" bun:"revoked_at"`   // Timestamp when the authorization was revoked, if applicable
	CreatedAt
	ExpiresAt
}
