package helpers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func HandleClientRegistration(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (*models.Client, errors.OIDCError) {
	if r.Method != http.MethodPost {
		msg := "Unsupported request method. Only POST is allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "POST, OPTIONS",
			},
		}

		return nil, err
	}

	if r.Header.Get("Content-Type") != "application/json" {
		msg := "Unsupported Content-Type. Only application/json is allowed."
		log.Printf("%s Got %s", msg, r.Header.Get("Content-Type"))
		err := errors.JSONError{
			StatusCode:  http.StatusUnsupportedMediaType,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}

		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		msg := "Failed to parse client registration request."
		log.Printf("%s Error: %v", msg, err)
		errResp := errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}

		return nil, errResp
	}

	user, authErr := authenticateUser(ctx, db, w, r)
	if authErr != nil {
		log.Printf("User authentication failed: %v", authErr)
		return nil, authErr
	}

	var client models.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		msg := "Failed to decode client registration request body."
		log.Printf("%s Error: %v", msg, err)
		errResp := errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}

		return nil, errResp
	}

	client.OwnerID = user.ID

	if err := client.Save(ctx, db); err != nil {
		msg := "Client data is invalid."
		log.Printf("%s Error: %v", msg, err)
		errResp := errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}

		return nil, errResp
	}

	return &client, nil
}

func authenticateUser(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (*models.User, errors.OIDCError) {
	sessionStore := utils.NewCookieStore()
	session, err := sessionStore.Get(r, SESSION_COOKIE_NAME)
	if err == nil && !session.IsNew {
		if sessionUserID, ok := session.Values[SESSION_COOKIE_ID].(string); ok {
			session, err := models.GetSessionByID(ctx, db, sessionUserID)
			if err == nil {
				return session.User, nil
			}
		}

		log.Printf("Failed to retrieve user from session cookie: %v", err)

		session.Options.MaxAge = -1 // Delete cookie
		if err := session.Save(r, w); err != nil {
			log.Printf("Error deleting invalid session cookie: %v", err)
		}
	}

	msg := "User is not authenticated."
	oidcErr := errors.JSONError{
		StatusCode:  http.StatusUnauthorized,
		ErrorCode:   errors.INVALID_REQUEST,
		Description: &msg,
	}

	var tokenValue string
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// extract the token from the "Bearer <token>" format
		re := regexp.MustCompile(`^Bearer\s*(.+)$`)
		matches := re.FindStringSubmatch(authHeader)
		if len(matches) > 1 {
			tokenValue = matches[1]
		}
	}

	if tokenValue != "" {
		token, err := models.GetTokenByValue(ctx, db, tokenValue)
		if err != nil {
			log.Printf("Failed to retrieve user from bearer token: %v", err)
			return nil, oidcErr
		}

		if !token.IsCustom || token.Type != utils.ACCESS_TOKEN_TYPE || token.User == nil || token.User.ID == uuid.Nil {
			log.Printf("Bearer token is not a custom token and/or does not have associated user")
			return nil, oidcErr
		}

		return token.User, nil
	}

	return nil, oidcErr
}
