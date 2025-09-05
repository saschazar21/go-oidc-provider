package helpers

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type createMagicLinkTokenRequest struct {
	Email string `json:"-" schema:"email" validate:"required,email"`
}

type validateMagicLinkTokenRequest struct {
	ID    string `json:"-" schema:"id" validate:"omitempty,uuid4"`
	Token string `json:"-" schema:"token" validate:"required"`
}

func createWhitelistedUser(ctx context.Context, db bun.IDB, email string) (*models.User, errors.OIDCError) {
	encryptedEmail := utils.EncryptedString(email)
	user := models.User{
		Email: &encryptedEmail,
	}

	if err := user.Save(ctx, db); err != nil {
		log.Printf("Failed to create new user with e-mail %s: %v", email, err)
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     fmt.Sprintf("Failed to create new user with e-mail: %s.", email),
		}
	}

	if err := models.DeleteMagicLinkWhitelistByEmail(ctx, db, email); err != nil {
		log.Printf("Failed to delete Magic Link whitelist entry for e-mail %s: %v", email, err)
		// Not returning error to avoid breaking the user creation flow
	}

	return &user, nil
}

func validateEmail(ctx context.Context, db bun.IDB, email string) bool {
	// Basic email format validation
	if email == "" {
		return false
	}

	var err error

	// Check if user with the given email exists
	var user *models.User
	user, err = models.GetUserByEmail(ctx, db, email)
	if err == nil && user != nil && *user.IsActive && !*user.IsLocked {
		return true
	}

	var magicLinkWhitelist *models.MagicLinkWhitelist
	magicLinkWhitelist, err = models.GetMagicLinkWhitelistByEmail(ctx, db, email)
	if err == nil && magicLinkWhitelist != nil {
		if _, err := createWhitelistedUser(ctx, db, email); err != nil {
			log.Printf("Failed to create whitelisted user with e-mail %s: %v", email, err)

			return false
		}

		return true
	}

	return false
}

func decodeMagicLinkTokenRequest(r *http.Request, dest interface{}) errors.OIDCError {
	msg := "Failed to decode request parameters."
	responseErr := errors.JSONAPIError{
		StatusCode: http.StatusBadRequest,
		Title:      "Invalid Request",
		Detail:     msg,
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Failed to parse form data: %v", err)
		return responseErr
	}

	decoder := utils.NewCustomDecoder()
	if err := decoder.Decode(dest, r.PostForm); err != nil {
		log.Printf("Failed to decode request parameters: %v", err)
		return responseErr
	}

	return nil
}

func ConsumeMagicLinkToken(ctx context.Context, db bun.IDB, r *http.Request, w http.ResponseWriter) (*models.MagicLinkToken, errors.OIDCError) {
	if r.Method != http.MethodPost {
		msg := "Invalid request method. Only POST is allowed."
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     errors.METHOD_NOT_ALLOWED,
			Description: msg,
			Headers: map[string]string{
				"Allow": "POST",
			},
		}
	}

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Invalid content type. Only application/x-www-form-urlencoded is allowed."
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: msg,
		}
	}

	var req validateMagicLinkTokenRequest
	err := decodeMagicLinkTokenRequest(r, &req)
	if err != nil {
		return nil, err
	}

	if err := req.Validate(); err != nil {
		log.Printf("Failed to validate validate magic link token request: %v", err)
		msg := "Either token is missing or request contents are invalid."
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Request",
			Detail:     msg,
		}
	}

	magicLinkCookie, _ := utils.NewCookieStore().Get(r, MAGIC_LINK_COOKIE_NAME)

	if req.ID == "" { // ID provided from form takes precedence over cookie
		id, ok := magicLinkCookie.Values[MAGIC_LINK_ID].(string)
		if !ok || id == "" {
			log.Printf("Failed to parse magic link ID from cookie, redirecting to login...")

			magicLinkCookie.Options.MaxAge = -1 // Delete cookie
			if err := magicLinkCookie.Save(r, w); err != nil {
				log.Printf("Error deleting invalid magic link cookie: %v", err)
			}

			msg := "Insufficient magic link token contents. Please request a new one."
			return nil, errors.JSONAPIError{
				StatusCode: http.StatusBadRequest,
				Title:      "Invalid Request",
				Detail:     msg,
			}
		}

		req.ID = id
	}

	var magicLink *models.MagicLinkToken
	magicLink, err = models.ConsumeMagicLinkToken(ctx, db, req.ID, req.Token)
	if err != nil {
		log.Printf("Failed to consume magic link token: %v", err)
		return nil, err
	}

	magicLinkCookie.Options.MaxAge = -1 // Delete cookie
	if err := magicLinkCookie.Save(r, w); err != nil {
		log.Printf("Error deleting magic link cookie: %v", err)
	}

	return magicLink, nil
}

func CreateMagicLinkToken(ctx context.Context, db bun.IDB, r *http.Request, w http.ResponseWriter) (*models.MagicLinkToken, errors.OIDCError) {
	if r.Method != http.MethodPost {
		msg := "Invalid request method. Only POST is allowed."
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     errors.METHOD_NOT_ALLOWED,
			Description: msg,
			Headers: map[string]string{
				"Allow": "POST",
			},
		}
	}

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Invalid content type. Only application/x-www-form-urlencoded is allowed."
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: msg,
		}
	}

	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.Header.Get("X-Real-IP")
	}
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}

	userAgent := r.Header.Get("User-Agent")

	var req createMagicLinkTokenRequest
	err := decodeMagicLinkTokenRequest(r, &req)
	if err != nil {
		return nil, err
	}

	if err := req.Validate(); err != nil {
		log.Printf("Failed to validate create magic link token request: %v", err)
		msg := "Invalid e-mail address."
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusBadRequest,
			Title:      "Invalid Request",
			Detail:     msg,
		}
	}

	var magicLink *models.MagicLinkToken
	var uid string

	if validateEmail(ctx, db, req.Email) {
		magicLink, err = models.CreateMagicLinkToken(ctx, db, req.Email, ipAddress, userAgent)
		if err != nil {
			log.Println("Failed to create magic link token.")
			return nil, err
		}

		uid = magicLink.ID.String()
	} else {
		log.Printf("E-mail address %s not found or not whitelisted", req.Email)
		uid = uuid.New().String() // Generate random UUID to avoid user enumeration
	}

	magicLinkSession, _ := utils.NewCookieStore().Get(r, MAGIC_LINK_COOKIE_NAME)
	magicLinkSession.Values[MAGIC_LINK_ID] = uid
	magicLinkSession.Values[MAGIC_LINK_EMAIL] = req.Email
	if err := magicLinkSession.Save(r, w); err != nil {
		log.Printf("Error saving magic link session cookie: %v", err)
		msg := "Failed to save magic link session."
		return nil, errors.JSONAPIError{
			StatusCode: http.StatusInternalServerError,
			Title:      "Internal Server Error",
			Detail:     msg,
		}
	}

	return magicLink, nil
}
