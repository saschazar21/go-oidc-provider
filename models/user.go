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

type Address struct {
	bun.BaseModel `bun:"table:oidc_addresses"`

	ID            uuid.UUID              `json:"-" bun:"address_id,type:uuid,pk,default:gen_random_uuid()"`
	UserID        uuid.UUID              `json:"-" bun:"user_id,type:uuid,notnull"`
	StreetAddress *utils.EncryptedString `json:"street_address" bun:"street_address"` // encrypt
	Locality      *utils.EncryptedString `json:"locality" bun:"locality"`             // encrypt
	Region        *utils.EncryptedString `json:"region" bun:"region"`                 // encrypt
	PostalCode    *utils.EncryptedString `json:"postal_code" bun:"postal_code"`       // encrypt
	Country       *string                `json:"country" bun:"country"`               // encrypt
	Formatted     *string                `json:"formatted" bun:"-"`

	*CreatedAt // Pointer to avoid marshaling zero value in JWT
	*UpdatedAt // Pointer to avoid marshaling zero value in JWT
}

var _ bun.AfterScanRowHook = (*Address)(nil)
var _ bun.BeforeUpdateHook = (*Address)(nil)

func (a *Address) formatAddress() {
	if a == nil {
		return
	}

	formatted := ""

	if a.StreetAddress != nil {
		formatted += fmt.Sprintf("%s\n", *a.StreetAddress)
	}

	if a.Locality != nil && a.PostalCode != nil {
		formatted += fmt.Sprintf("%s, %s\n", *a.Locality, *a.PostalCode)
	}

	if a.Region != nil {
		formatted += fmt.Sprintf("%s\n", *a.Region)
	}

	if a.Country != nil {
		formatted += *a.Country
	}

	a.Formatted = &formatted
}

func (a *Address) AfterScanRow(ctx context.Context) error {
	a.formatAddress()

	return nil
}

func (a *Address) BeforeUpdate(ctx context.Context, query *bun.UpdateQuery) error {
	a.UpdatedAt = &UpdatedAt{
		time.Now().UTC(),
	}

	return nil
}

func (a *Address) GetID() string {
	if a.ID == uuid.Nil {
		return ""
	}
	return a.ID.String()
}

func (a *Address) String() string {
	if a == nil {
		return ""
	}

	if a.Formatted == nil {
		a.formatAddress()
	}

	return *a.Formatted
}

func (a *Address) Save(ctx context.Context, db bun.IDB) errors.HTTPError {
	err := storeUserDataInDB(ctx, db, a)

	if err != nil {
		return err
	}

	return nil
}

type User struct {
	bun.BaseModel `bun:"table:oidc_users"`

	ID                    uuid.UUID              `json:"sub" bun:"user_id,type:uuid,pk,default:gen_random_uuid()"`
	Email                 *utils.EncryptedString `json:"email,omitempty" validate:"required,email" bun:"email,type:bytea,unique,notnull"` // encrypt
	EmailHash             *utils.HashedString    `json:"-" bun:"email_hash,type:bytea,unique,notnull"`                                    // hashed base64-url-encoded
	IsEmailVerified       *bool                  `json:"email_verified,omitempty" bun:"email_verified,notnull"`
	PhoneNumber           *string                `json:"phone_number,omitempty" validate:"omitempty,e164" bun:"phone_number,type:bytea,unique"` // encrypt
	IsPhoneNumberVerified *bool                  `json:"phone_number_verified,omitempty" bun:"phone_number_verified"`
	GivenName             *utils.EncryptedString `json:"given_name,omitempty" validate:"omitempty,alphanumunicode" bun:"given_name,type:bytea"`   // encrypt
	FamilyName            *utils.EncryptedString `json:"family_name,omitempty" validate:"omitempty,alphanumunicode" bun:"family_name,type:bytea"` // encrypt
	MiddleName            *utils.EncryptedString `json:"middle_name,omitempty" validate:"omitempty,alphanumunicode" bun:"middle_name,type:bytea"` // encrypt
	Name                  *string                `json:"name,omitempty" bun:"-"`
	Nickname              *string                `json:"nickname,omitempty" validate:"omitempty,alphanum" bun:"nickname"`
	PreferredUsername     *string                `json:"preferred_username,omitempty" validate:"omitempty,alphanum" bun:"preferred_username"`
	Profile               *utils.EncryptedString `json:"profile,omitempty" validate:"omitempty,http_url" bun:"profile"`
	Picture               *utils.EncryptedString `json:"picture,omitempty" validate:"omitempty,http_url" bun:"picture"`
	Website               *utils.EncryptedString `json:"website,omitempty" validate:"omitempty,http_url" bun:"website"`
	Gender                *utils.EncryptedString `json:"gender,omitempty" validate:"omitempty,alphanumunicode" bun:"gender,type:bytea"`   // encrypt
	Birthdate             *utils.EncryptedDate   `json:"birthdate,omitempty" validate:"omitempty,time-lt-now" bun:"birthdate,type:bytea"` // encrypt
	Zoneinfo              *string                `json:"zoneinfo,omitempty" validate:"omitempty,timezone" bun:"zoneinfo"`
	Locale                *string                `json:"locale,omitempty" validate:"omitempty,bcp47_language_tag" bun:"locale"`

	LastLoginAt *time.Time `json:"last_login_at,omitempty" validate:"omitempty,time-lte-now" bun:"last_login_at"`
	IsActive    *bool      `json:"is_active,omitempty" bun:"is_active,notnull,default:true"`
	IsLocked    *bool      `json:"is_locked,omitempty" bun:"is_locked,notnull,default:false"`

	CustomClaims *map[string]interface{} `json:"custom_claims,omitempty" validate:"omitempty" bun:"custom_claims,type:jsonb"`

	Address *Address `json:"address,omitempty" validate:"omitempty" bun:"rel:has-one,join:user_id=user_id"`

	*CreatedAt // Pointer to avoid marshaling zero value in JWT
	*UpdatedAt // Pointer to avoid marshaling zero value in JWT
}

var _ bun.AfterScanRowHook = (*User)(nil)
var _ bun.BeforeAppendModelHook = (*User)(nil)

func (u *User) formatName() {
	if u == nil {
		return
	}

	name := ""

	if u.GivenName != nil {
		name += string(*u.GivenName)
	}

	if u.MiddleName != nil {
		name += fmt.Sprintf(" %s", string(*u.MiddleName))
	}

	if u.FamilyName != nil {
		name += fmt.Sprintf(" %s", string(*u.FamilyName))
	}

	u.Name = &name
}

func (u *User) AfterScanRow(ctx context.Context) error {
	u.formatName()

	if u.Address != nil {
		u.Address.formatAddress()
	}

	return nil
}

func (u *User) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	now := time.Now().UTC()

	switch query.(type) {
	case *bun.InsertQuery:
		u.CreatedAt = &CreatedAt{
			now,
		}
		u.UpdatedAt = &UpdatedAt{
			now,
		}

		if u.IsActive == nil {
			isActive := true
			u.IsActive = &isActive
		}
		if u.IsLocked == nil {
			isLocked := false
			u.IsLocked = &isLocked
		}
		if u.EmailHash == nil && u.Email != nil {
			u.EmailHash = (*utils.HashedString)(u.Email)
		}
	case *bun.UpdateQuery:
		u.UpdatedAt = &UpdatedAt{
			now,
		}

		if u.EmailHash == nil && u.Email != nil {
			u.EmailHash = (*utils.HashedString)(u.Email)
		}
	}

	return nil
}

func (u *User) GetClaimsBasedOnScopes(scopes []utils.Scope) *User {
	var user User
	for _, scope := range scopes {
		switch scope {
		case utils.OPENID:
			user.ID = u.ID
		case utils.EMAIL:
			user.Email = u.Email
			user.IsEmailVerified = u.IsEmailVerified
		case utils.PHONE:
			user.PhoneNumber = u.PhoneNumber
			user.IsPhoneNumberVerified = u.IsPhoneNumberVerified
		case utils.ADDRESS:
			user.Address = u.Address
			user.Address.CreatedAt = nil // avoid marshaling zero value
			user.Address.UpdatedAt = nil
		case utils.PROFILE:
			user.Name = u.Name
			user.GivenName = u.GivenName
			user.FamilyName = u.FamilyName
			user.MiddleName = u.MiddleName
			user.Nickname = u.Nickname
			user.PreferredUsername = u.PreferredUsername
			user.Birthdate = u.Birthdate
			user.Zoneinfo = u.Zoneinfo
			user.Locale = u.Locale
			user.Picture = u.Picture
			user.Profile = u.Profile
			user.Website = u.Website
			user.Gender = u.Gender
		}
	}

	user.CreatedAt = nil // avoid marshaling zero value
	user.UpdatedAt = nil

	return &user
}

func (u *User) GetID() string {
	if u.ID == uuid.Nil {
		return ""
	}
	return u.ID.String()
}

func (u *User) Sanitize() {
	sanitizedEmail := utils.SanitizeString(string(*u.Email))
	u.Email = (*utils.EncryptedString)(&sanitizedEmail)

	if u.PhoneNumber != nil {
		sanitizedPhone := utils.SanitizeString(*u.PhoneNumber)
		u.PhoneNumber = &sanitizedPhone
	}

	if u.GivenName != nil {
		sanitizedGivenName := utils.SanitizeString(string(*u.GivenName))
		u.GivenName = (*utils.EncryptedString)(&sanitizedGivenName)
	}

	if u.FamilyName != nil {
		sanitizedFamilyName := utils.SanitizeString(string(*u.FamilyName))
		u.FamilyName = (*utils.EncryptedString)(&sanitizedFamilyName)
	}

	if u.MiddleName != nil {
		sanitizedMiddleName := utils.SanitizeString(string(*u.MiddleName))
		u.MiddleName = (*utils.EncryptedString)(&sanitizedMiddleName)
	}

	if u.Nickname != nil {
		sanitizedNickname := utils.SanitizeString(*u.Nickname)
		u.Nickname = &sanitizedNickname
	}

	if u.PreferredUsername != nil {
		sanitizedPreferredUsername := utils.SanitizeString(*u.PreferredUsername)
		u.PreferredUsername = &sanitizedPreferredUsername
	}

	if u.Gender != nil {
		sanitizedGender := utils.SanitizeString(string(*u.Gender))
		u.Gender = (*utils.EncryptedString)(&sanitizedGender)
	}
}

func (u *User) String() string {
	if u == nil {
		return ""
	}

	if u.Name == nil {
		u.formatName()
	}

	stringified := *u.Name

	if stringified == "" {
		stringified = fmt.Sprintf("%s %s", string(*u.GivenName), string(*u.FamilyName))
	}

	stringified = fmt.Sprintf("[%s]: %s (%s)", u.ID.String(), stringified, string(*u.Email))

	return stringified
}

func (u *User) Save(ctx context.Context, db bun.IDB) errors.HTTPError {
	if u.Email == nil || *u.Email == "" {
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "E-Mail address must not be empty",
		}
	}

	u.Sanitize()

	email := *u.Email                            // store e-mail before hashing
	u.EmailHash = (*utils.HashedString)(u.Email) // for avoiding re-hashing the already hashed e-mail

	err := storeUserDataInDB(ctx, db, u)

	if err != nil {
		return err
	}

	*u.Email = email // restore e-mail after hashing
	u.EmailHash = nil

	if u.Address != nil {
		u.Address.UserID = u.ID

		if err := u.Address.Save(ctx, db); err != nil {
			return err
		}
	}

	return nil
}

func storeUserDataInDB(ctx context.Context, db bun.IDB, model ValidatabaleModelWithID) errors.HTTPError {
	var defaultMsg string
	var t string

	switch m := model.(type) {
	case *User:
		t = "user"
	case *Address:
		t = "address"
	default:
		log.Printf("unknown model type: %T", m)
		defaultMsg = fmt.Sprintf("Storing %s data in the database failed", t)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     defaultMsg,
		}
	}

	if err := model.Validate(); err != nil {
		log.Printf("failed to validate %s: %v", t, err)
		return errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     fmt.Sprintf("%s data contains invalid structure, check the request body", t),
		}
	}

	var err error
	var isExisting bool
	var result sql.Result

	if model.GetID() != "" {
		isExisting, err = db.NewSelect().
			Model(model).
			Column(fmt.Sprintf("%s_id", t)).
			Where(fmt.Sprintf("\"%s\".\"%s_id\" = ?", t, t), model.GetID()).
			Exists(ctx)

		if err != nil {
			log.Printf("failed to check if %s exists: %v", t, err)
			return errors.JSONAPIError{
				StatusCode: http.StatusInternalServerError,
				Title:      errors.INTERNAL_SERVER_ERROR,
				Detail:     defaultMsg,
			}
		}
	}

	if isExisting {
		result, err = db.NewUpdate().
			Model(model).
			Where(fmt.Sprintf("\"%s\".\"%s_id\" = ?", t, t), model.GetID()).
			ExcludeColumn(fmt.Sprintf("%s_id", t), "created_at", "updated_at").
			OmitZero().
			Returning("*").
			Exec(ctx, model)
	} else {
		result, err = db.NewInsert().
			Model(model).
			ExcludeColumn(fmt.Sprintf("%s_id", t), "created_at", "updated_at").
			Returning("*").
			Exec(ctx, model)
	}

	if err != nil {
		log.Printf("failed to insert or update %s: %v", t, err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     defaultMsg,
		}
	}

	if rows, err := result.RowsAffected(); err != nil || rows == 0 {
		log.Printf("failed to insert or update %s: %v", t, err)
		return errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.INTERNAL_SERVER_ERROR,
			Detail:     defaultMsg,
		}
	}

	return nil
}

func GetUserByID(ctx context.Context, db bun.IDB, id string) (*User, errors.HTTPError) {
	if id == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "User ID must not be empty",
		}
	}

	var user User

	err := db.NewSelect().
		Model(&user).
		Where("\"user\".\"user_id\" = ?", id).
		Relation("Address").
		Scan(ctx)

	if err != nil {
		log.Printf("failed to get user by ID: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.NOT_FOUND,
			Detail:     fmt.Sprintf("fetching user with ID: %s failed", id),
		}
	}

	return &user, nil
}

func GetUserByEmail(ctx context.Context, db bun.IDB, email string) (*User, errors.HTTPError) {
	if email == "" {
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      errors.BAD_REQUEST,
			Detail:     "E-Mail address must not be empty",
		}
	}

	hashed := utils.Hash([]byte(email))

	var user User

	err := db.NewSelect().
		Model(&user).
		Where("\"user\".\"email_hash\" = ?", hashed).
		Relation("Address").
		Scan(ctx)

	if err != nil {
		log.Printf("failed to get user by email: %v", err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      errors.NOT_FOUND,
			Detail:     fmt.Sprintf("fetching user with email: %s failed", email),
		}
	}

	return &user, nil
}
