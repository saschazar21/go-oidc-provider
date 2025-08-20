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

type Session struct {
	bun.BaseModel `bun:"table:oidc_sessions"`

	ID         uuid.UUID              `json:"-" schema:"-" bun:"session_id,pk,type:uuid,default:gen_random_uuid()"`
	IPAddress  *utils.EncryptedString `json:"-" schema:"-" validate:"omitempty,ip_addr" bun:"ip_address,type:bytea"`               // Encrypted IP address of the session
	UserAgent  *string                `json:"-" schema:"-" bun:"user_agent"`                                                       // User agent string of the session
	DeviceInfo *string                `json:"-" schema:"-" bun:"device_info"`                                                      // Optional device information for the session
	Scope      *[]utils.Scope         `json:"-" schema:"-" validate:"omitempty,dive,scope" bun:"scope,type:oidc_standard_scope[]"` // List of scopes associated with the session
	ACRValues  *[]utils.ACR           `json:"-" schema:"-" validate:"omitempty,dive,acr" bun:"acr_values,type:oidc_acr_type[]"`    // Authentication Context Class Reference (ACR) that initiated the session
	AMR        *[]utils.AMR           `json:"-" schema:"-" validate:"omitempty,dive,amr" bun:"amr,type:oidc_amr_type[]"`           // Authentication Methods References (AMR) that initiated the session

	IsActive     *bool   `json:"is_active" schema:"-" bun:"is_active,default:true"`                                              // Whether the session is active
	LogoutReason *string `json:"logout_reason,omitempty" validate:"omitempty,lt=100" schema:"logout_reason" bun:"logout_reason"` // Optional reason for session logout

	RedirectURI *string `json:"-" schema:"-" validate:"omitempty,uri" bun:"-"`

	ClientID *string `json:"-" schema:"-" bun:"client_id"`                               // ID of the client that initiated the session
	Client   *Client `json:"-" schema:"-" bun:"rel:belongs-to,join:client_id=client_id"` // Client which initiated the session

	UserID uuid.UUID `json:"-" schema:"-" validate:"required,uuid4" bun:"user_id,type:uuid,notnull"` // ID of the user associated with the session
	User   *User     `json:"-" schema:"-" bun:"rel:belongs-to,join:user_id=user_id,notnull"`         // User associated with the session

	AuthTime       time.Time `json:"-" schema:"-" validate:"omitempty,time-lt-now" bun:"auth_time,default:now()"`        // Timestamp of the authentication time for the session
	LastAccessedAt time.Time `json:"-" schema:"-" validate:"omitempty,time-lt-now" bun:"last_accessed_at,default:now()"` // Timestamp of the last access to the session

	ExpiresAt
	CreatedAt
	UpdatedAt
}

var _ bun.AfterSelectHook = (*Session)(nil)
var _ bun.BeforeUpdateHook = (*Session)(nil)

func (s *Session) save(ctx context.Context, db bun.IDB, excludeColumns ...string) errors.OIDCError {
	var redirectURI string
	if s.RedirectURI != nil {
		redirectURI = *s.RedirectURI
	}

	var err error
	var result sql.Result

	defaultMsg := "Failed to store session in database"

	if s.ID != uuid.Nil {
		defaultMsg = "Failed to update session in database"

		result, err = db.NewUpdate().
			Model(s).
			WherePK().
			ExcludeColumn(excludeColumns...).
			OmitZero().
			Returning("*").
			Exec(ctx, s)
	} else {
		result, err = db.NewInsert().
			Model(s).
			Returning("*").
			ExcludeColumn(excludeColumns...).
			Returning("*").
			Exec(ctx, s)
	}

	if err != nil {
		log.Printf("Database operation error: %v", err)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectURI,
		}
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Error getting rows affected: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectURI,
		}
	}

	if rowsAffected == 0 {
		log.Printf("No rows affected when saving session with ID %s", s.ID.String())
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectURI,
		}
	}

	return nil
}

func (s *Session) AfterSelect(ctx context.Context, query *bun.SelectQuery) error {
	model := query.GetModel().Value()

	s, ok := model.(*Session)
	if !ok {
		log.Println("AfterSelect: model is not a Session")

		return nil
	}

	if s.ID == uuid.Nil {
		log.Println("AfterSelect: Session ID is nil")

		return nil
	}

	defaultMsg := "Failed to update last accessed time for session."

	var redirectURI string
	if s.RedirectURI != nil {
		redirectURI = *s.RedirectURI
	}

	session := Session{ID: s.ID, LastAccessedAt: time.Now()}
	session.ExpiresAt.ExpiresAt = time.Now().Add(24 * time.Hour) // Extend for default expiration time

	_, err := query.DB().NewUpdate().
		Model(&session).
		WherePK().
		Where("is_active = ?", true).
		Where("expires_at > ?", time.Now()).
		OmitZero().
		Returning("last_accessed_at").
		Exec(ctx, &session)

	if err != nil {
		log.Printf("Error updating last accessed time for session %s: %v", s.ID.String(), err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &defaultMsg,
			RedirectURI:      redirectURI,
		}
	}

	return nil
}

func (s *Session) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	if s.ID == uuid.Nil {
		i := query.GetModel().Value()
		session, ok := i.(*Session)

		if !ok {
			log.Println("BeforeUpdate: model is not a Session")
			return nil
		}

		s = session
	}

	if s.ID == uuid.Nil {
		log.Println("BeforeUpdate: Session ID is nil")
		return nil
	}

	s.UpdatedAt.UpdatedAt = time.Now()

	return nil
}

func (s *Session) Save(ctx context.Context, db bun.IDB) errors.OIDCError {
	var redirectURI string
	if s.RedirectURI != nil {
		redirectURI = *s.RedirectURI
	}

	if err := s.Validate(); err != nil {
		msg := "Invalid session data"

		log.Printf("Failed to validate session: %v", err)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			RedirectURI:      redirectURI,
		}
	}

	var isExisting bool
	var err error
	if s.ID != uuid.Nil {
		isExisting, err = db.NewSelect().
			Model(s).
			WherePK(s.ID.String()).
			Column("session_id").
			Exists(ctx)

		if err != nil {
			msg := "Invalid Session"
			description := "Session ID does not exist or is invalid."

			log.Printf("Error checking session existence for ID %s: (error: %v)", s.ID.String(), err)

			return errors.HTTPErrorResponse{
				StatusCode:  http.StatusUnauthorized,
				Message:     msg,
				Description: description,
				Headers: map[string]string{
					"WWW-Authenticate": fmt.Sprintf("Bearer realm=\"login\" error=\"%s\", error_description=\"%s\"", msg, description),
				},
			}
		}
	}

	excludeColumns := []string{"session_id", "created_at", "updated_at", "last_accessed_at"}

	if !isExisting {
		s.ID = uuid.Nil
		excludeColumns = append(excludeColumns, "expires_at")
	}

	return s.save(ctx, db, excludeColumns...)
}

func GetSessionByID(ctx context.Context, db bun.IDB, id string) (*Session, errors.HTTPError) {
	if id == "" {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The session ID cannot be nil.",
		}
	}

	uid, parseErr := uuid.Parse(id)

	if parseErr != nil {
		log.Printf("Invalid session ID format: %v", parseErr)

		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The session ID must be a valid UUID.",
		}
	}

	session := Session{ID: uid, LastAccessedAt: time.Now()}

	err := db.NewSelect().
		Model(&session).
		WherePK().
		Where("\"session\".\"is_active\" = ?", true).
		Where("\"session\".\"expires_at\" > ?", time.Now()).
		Relation("User", func(sq *bun.SelectQuery) *bun.SelectQuery {
			return sq.
				Where("\"user\".\"is_active\" = ?", true).
				Where("\"user\".\"is_locked\" = ?", false)
		}).
		Relation("Client").
		Scan(ctx, &session)

	if err != nil {
		log.Printf("Error retrieving session by ID %s: %v", id, err)
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     errors.INTERNAL_SERVER_ERROR,
			Description: "Failed to retrieve session from database.",
		}
	}

	return &session, nil
}

func LogoutSession(ctx context.Context, db bun.IDB, sessionID string, reason *string) errors.OIDCError {
	if sessionID == "" {
		return nil
	}

	uid, err := uuid.Parse(sessionID)
	if err != nil || uid == uuid.Nil {
		log.Printf("Invalid session ID format: %v", err)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The session ID must be a valid UUID.",
		}
	}

	isActive := false

	session := &Session{
		ID:           uid,
		IsActive:     &isActive,
		LogoutReason: reason,
	}

	if session.ID != uuid.Nil {
		isExisting, err := db.NewSelect().
			Model(session).
			WherePK().
			Column("session_id").
			Exists(ctx)

		if !isExisting || err != nil {
			log.Printf("Attempting to log out invalid session ID %s (error: %v)", sessionID, err)
			return nil
		}
	}

	excludeColumns := []string{"session_id", "user_id", "client_id", "created_at", "updated_at", "last_accessed_at"}

	if err := session.save(ctx, db, excludeColumns...); err != nil {
		log.Printf("Failed to log out session %s: %v", sessionID, err)
		return err
	}

	return nil
}
