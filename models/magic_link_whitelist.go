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

type MagicLinkWhitelist struct {
	bun.BaseModel `bun:"table:oidc_magic_link_whitelist"`

	ID        uuid.UUID              `json:"-" schema:"-" bun:"whitelist_id,pk,type:uuid,default:gen_random_uuid()"`                        // Unique identifier for the whitelist entry
	Email     *utils.EncryptedString `json:"email" schema:"email,required" validate:"required,email" bun:"email,type:bytea,unique,notnull"` // Encrypted email address to whitelist
	EmailHash *utils.HashedString    `json:"-" schema:"-" bun:"email_hash,type:bytea,unique,notnull"`                                       // Hashed email address for uniqueness
	Reason    *string                `json:"reason,omitempty" schema:"reason" validate:"omitempty,max=255" bun:"reason"`                    // Optional reason for whitelisting the email address
	Notes     *string                `json:"notes,omitempty" schema:"notes" validate:"omitempty,max=500" bun:"notes"`                       // Optional notes about the whitelist entry

	AddedByID *uuid.UUID `json:"added_by_id,omitempty" schema:"added_by" validate:"omitempty,uuid4" bun:"added_by,type:uuid"` // ID of the user who added the whitelist entry
	AddedBy   *User      `json:"-" schema:"-" bun:"rel:belongs-to,join:added_by=user_id"`                                     // User who added the whitelist entry

	CreatedAt
	ExpiresAt
}

var _ bun.BeforeAppendModelHook = (*MagicLinkWhitelist)(nil)

func (m *MagicLinkWhitelist) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		now := time.Now().UTC()
		m.CreatedAt.CreatedAt = now

		if m.ExpiresAt.ExpiresAt.IsZero() {
			m.ExpiresAt.ExpiresAt = now.Add(24 * time.Hour) // Default expiration
		}

		if m.Email != nil {
			hashedEmail := utils.HashedString(string(*m.Email))
			m.EmailHash = &hashedEmail // Hash the email for uniqueness
		}
	case *bun.UpdateQuery:
		if m.Email != nil {
			hashedEmail := utils.HashedString(string(*m.Email))
			m.EmailHash = &hashedEmail // Hash the email for uniqueness
		}
	}

	return nil
}

func (m *MagicLinkWhitelist) Save(ctx context.Context, db bun.IDB) errors.HTTPError {
	if err := m.Validate(); err != nil {
		log.Printf("Failed to validate Magic Link whitelist entry: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Magic Link Whitelist Entry",
		}
	}

	email := *m.Email

	var err error
	var result sql.Result

	if m.ID == uuid.Nil {
		result, err = db.NewInsert().
			Model(m).
			ExcludeColumn("created_at").
			Returning("*").
			Exec(ctx)
	} else {
		result, err = db.NewUpdate().
			Model(m).
			WherePK().
			ExcludeColumn("created_at").
			OmitZero().
			Returning("*").
			Exec(ctx)
	}

	if err != nil {
		log.Printf("Error saving Magic Link whitelist entry: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to store Magic Link whitelist entry into the database.",
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected for Magic Link whitelist entry: %v", err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to determine the number of rows affected by the Magic Link whitelist entry operation.",
		}
	}

	if rowsAffected == 0 {
		log.Printf("No rows affected when saving Magic Link whitelist entry for email %s", email)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "No rows were affected when trying to save the Magic Link whitelist entry.",
		}
	}

	*m.Email = email // restore e-mail after encryption

	return nil
}

func (m MagicLinkWhitelist) String() string {
	str := fmt.Sprintf("\"%s\" expires at %s]", string(*m.Email), m.ExpiresAt.ExpiresAt.Format(time.RFC822))
	if m.Reason != nil {
		str += fmt.Sprintf("\nReason: %s", *m.Reason)
	}
	if m.Notes != nil {
		str += fmt.Sprintf("\nNotes: %s", *m.Notes)
	}
	return str
}

func DeleteMagicLinkWhitelistByEmail(ctx context.Context, db bun.IDB, email string) errors.HTTPError {
	if email == "" {
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Email",
			Detail:     "Email cannot be empty.",
		}
	}

	_, err := db.NewDelete().
		Model((*MagicLinkWhitelist)(nil)).
		Where("\"magic_link_whitelist\".\"email_hash\" = ?", utils.HashedString(email)).
		Exec(ctx)

	if err != nil {
		log.Printf("Error deleting Magic Link whitelist entry for email %s: %v", email, err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to delete Magic Link whitelist entry from the database.",
		}
	}

	return nil
}

func GetMagicLinkWhitelistByEmail(ctx context.Context, db bun.IDB, email string) (*MagicLinkWhitelist, errors.HTTPError) {
	if email == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Email",
			Detail:     "Email cannot be empty.",
		}
	}

	var entry MagicLinkWhitelist
	err := db.NewSelect().
		Model(&entry).
		Relation("AddedBy", func(sq *bun.SelectQuery) *bun.SelectQuery {
			return sq.
				WhereGroup(" AND ", func(sq *bun.SelectQuery) *bun.SelectQuery {
					return sq.
						Where("\"magic_link_whitelist\".\"added_by\" IS NULL").
						WhereGroup(" OR ", func(sq *bun.SelectQuery) *bun.SelectQuery {
							return sq.
								Where("\"added_by\".\"is_active\" = ?", true).
								Where("\"added_by\".\"is_locked\" = ?", false)
						})
				})
		}).
		Where("\"magic_link_whitelist\".\"email_hash\" = ?", utils.HashedString(email)).
		Where("\"magic_link_whitelist\".\"expires_at\" > ?", time.Now().UTC()).
		Scan(ctx)

	if err != nil {
		log.Printf("Error retrieving Magic Link whitelist entry for email %s: %v", email, err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     "Failed to retrieve Magic Link whitelist entry from the database.",
		}
	}

	return &entry, nil
}
