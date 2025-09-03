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
	CLIENT_ID_PREFIX        = "cl_"
	CLIENT_ID_BYTE_SIZE     = 16
	CLIENT_SECRET_BYTE_SIZE = 32
)

type Client struct {
	bun.BaseModel `bun:"table:oidc_clients"`

	ID            string                `json:"client_id" bun:"client_id,pk"`
	Name          string                `json:"client_name" validate:"required" bun:"client_name,notnull"`                                                                    // Name of the client, used for display purposes
	Secret        *utils.HashedString   `json:"-" bun:"client_secret,type:bytea"`                                                                                             // Hashed
	Description   *string               `json:"client_description,omitempty" bun:"client_description,type:text"`                                                              // Optional description of the client
	URI           *string               `json:"client_uri,omitempty" validate:"omitempty,uri" bun:"client_uri"`                                                               // Optional URI for the client
	Logo          *string               `json:"logo_uri,omitempty" validate:"omitempty,uri" bun:"logo_uri"`                                                                   // Optional logo URI for the client
	GrantTypes    *[]utils.GrantType    `json:"grant_types,omitempty" validate:"omitempty,dive,grant-type" bun:"grant_types,type:oidc_grant_type[],notnull"`                  // List of grant types supported by the client
	ResponseTypes *[]utils.ResponseType `json:"response_types,omitempty" validate:"omitempty,dive,response-type" bun:"response_types,type:oidc_response_type[],notnull"`      // List of response types supported by the client
	AuthMethod    *utils.AuthMethod     `json:"token_endpoint_auth_method,omitempty" validate:"omitempty,auth-method" bun:"token_endpoint_auth_method,type:oidc_auth_method"` // Authentication method for the token endpoint

	RedirectURIs           []string `json:"redirect_uris" validate:"required,dive,uri" bun:"redirect_uris,type:text[]"`                                    // List of redirect URIs for the client
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty" validate:"omitempty,dive,uri" bun:"post_logout_redirect_uris,type:text[]"` // List of post logout redirect URIs for the client

	IsAuthTimeRequired bool `json:"require_auth_time,omitempty" bun:"require_auth_time"`    // Whether the client requires auth time
	IsPKCERequired     bool `json:"require_pkce,omitempty" bun:"require_pkce,default:true"` // Whether the client requires PKCE

	AccessTokenLifetime  int64 `json:"access_token_lifetime" validate:"omitempty,gt=0" bun:"access_token_lifetime,default:3600"`              // Lifetime of access tokens in seconds
	RefreshTokenLifetime int64 `json:"refresh_token_lifetime,omitempty" validate:"omitempty,gt=0" bun:"refresh_token_lifetime,default:86400"` // Lifetime of refresh tokens in seconds
	IDTokenLifetime      int64 `json:"id_token_lifetime,omitempty" validate:"omitempty,gt=0" bun:"id_token_lifetime,default:300"`             // Lifetime of ID tokens in seconds

	IsActive       *bool `json:"is_active" bun:"is_active,default:true"`              // Whether the client is active
	IsConfidential *bool `json:"is_confidential" bun:"is_confidential,default:false"` // Whether the client is confidential

	OwnerID uuid.UUID `json:"-" validate:"required" bun:"owner_id,notnull"`                       // ID of the owner of the client
	Owner   *User     `json:"owner,omitempty" bun:"rel:belongs-to,join:owner_id=user_id,notnull"` // Owner of the client

	CreatedAt
	UpdatedAt
}

var _ bun.BeforeAppendModelHook = (*Client)(nil)

func (c *Client) newSecret() (string, error) {
	secret, err := utils.RandomBase58String(CLIENT_SECRET_BYTE_SIZE)
	if err != nil {
		return "", err
	}

	hashedSecret := utils.HashedString(secret)
	c.Secret = &hashedSecret

	return secret, nil
}

func (c *Client) save(ctx context.Context, db bun.IDB, excludedColumns ...string) errors.HTTPError {
	if err := c.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "The client data is invalid.",
		}
	}

	var err error
	var isExisting bool
	var result sql.Result

	if c.ID != "" {
		isExisting, err = db.NewSelect().
			Model(c).
			WherePK().
			Column("client_id").
			Exists(ctx)

		if err != nil {
			log.Printf("Error checking if client exists: %v", err)
			return errors.JSONAPIError{
				StatusCode: http.StatusInternalServerError,
				Title:      "Failed to check client existence",
				Detail:     "An error occurred while checking if the client exists.",
			}
		}

		if !isExisting {
			return errors.JSONAPIError{
				StatusCode: http.StatusNotFound,
				Title:      "Client Not Found",
				Detail:     "The specified client ID does not exist.",
			}
		}

		result, err = db.NewUpdate().
			Model(c).
			WherePK().
			ExcludeColumn(excludedColumns...).
			Returning("*").
			Exec(ctx, c)
	} else {
		result, err = db.NewInsert().
			Model(c).
			ExcludeColumn(excludedColumns...).
			Returning("*").
			Exec(ctx, c)
	}

	if err != nil {
		log.Printf("Database operation error: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     "Storing client data in the database failed.",
		}
	}

	if rowsAffected, _ := result.RowsAffected(); rowsAffected == 0 {
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "No rows affected",
			Detail:     "The operation did not affect any rows.",
		}
	}

	c.Secret = nil // Clear the secret before returning to avoid leaking sensitive information
	return nil
}

func (c *Client) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		id, err := utils.RandomBase58String(CLIENT_ID_BYTE_SIZE, CLIENT_ID_PREFIX)

		if err != nil {
			log.Printf("Error generating client ID: %v", err)
			return errors.JSONAPIError{
				StatusCode: http.StatusInternalServerError,
				Title:      "Failed to generate client ID",
				Detail:     "An error occurred while generating the client ID.",
			}
		}

		c.ID = id
		c.CreatedAt.CreatedAt = time.Now()
		c.UpdatedAt.UpdatedAt = time.Now()
	case *bun.UpdateQuery:
		c.UpdatedAt.UpdatedAt = time.Now()
	}

	return nil
}

func (c *Client) NewSecret(ctx context.Context, db bun.IDB) (string, errors.HTTPError) {
	if c.ID == "" {
		return "", errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Client ID",
			Detail:     "Client ID must be set when generating a new secret.",
		}
	}

	if c.IsConfidential == nil || !(*c.IsConfidential) {
		return "", errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Client is not confidential",
			Detail:     "Only confidential clients can generate a new secret.",
		}
	}

	secret, err := c.newSecret()
	if err != nil {
		log.Printf("Error generating client secret: %v", err)
		return "", errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Failed to generate client secret",
			Detail:     "An error occurred while generating the client secret.",
		}
	}

	if err := c.save(ctx, db); err != nil {
		log.Println(err)
		return "", err
	}

	hashedSecret := utils.HashedString(secret)
	c.Secret = &hashedSecret
	return secret, nil
}

func (c *Client) Save(ctx context.Context, db bun.IDB) errors.HTTPError {
	if c.ID == "" && (c.IsConfidential != nil && *c.IsConfidential) {
		secret, err := c.newSecret()
		if err != nil {
			log.Printf("Error generating new client secret: %v", err)
			return errors.JSONAPIError{
				StatusCode: http.StatusInternalServerError,
				Title:      "Failed to generate client secret",
				Detail:     "An error occurred while generating the client secret.",
			}
		}

		if err := c.save(ctx, db); err != nil {
			return err
		}

		hashedSecret := utils.HashedString(secret)
		c.Secret = &hashedSecret
		return nil
	}

	return c.save(ctx, db, "client_secret")
}

func GetClientByID(ctx context.Context, db bun.IDB, id string) (*Client, errors.HTTPError) {
	if id == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "Client ID must not be empty.",
		}
	}

	client := &Client{ID: id}
	err := db.NewSelect().
		Model(client).
		WherePK().
		ExcludeColumn("client_secret").
		Scan(ctx, client)

	if err != nil {
		log.Printf("Error fetching client by ID: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Failed to fetch client",
			Detail:     "The specified client does not exist.",
		}
	}

	client.Secret = nil // Clear the secret before returning to avoid leaking sensitive information

	return client, nil
}

func GetClientByIDAndSecret(ctx context.Context, db bun.IDB, id string, secret string) (*Client, errors.HTTPError) {
	if id == "" || secret == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "Client ID and secret must not be empty.",
		}
	}

	hashedSecret := utils.HashedString(secret)
	client := &Client{ID: id, Secret: &hashedSecret}
	err := db.NewSelect().
		Model(client).
		ExcludeColumn("client_secret").
		Where("client.client_id = ?", id).
		Where("client.client_secret = ?", client.Secret).
		Scan(ctx, client)

	if err != nil {
		log.Printf("Error fetching client by ID and secret: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusNotFound,
			Title:      "Invalid Client Credentials",
			Detail:     "The specified client/client secret combination does not exist.",
		}
	}

	client.Secret = nil // Clear the secret before returning to avoid leaking sensitive information

	return client, nil
}
