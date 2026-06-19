package helpers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func deleteCookie(w http.ResponseWriter, cookieName string) {
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		MaxAge: -1, // Delete cookie
		Value:  "",
		Path:   "/",
	})
}

func getSessionIdFromCookie(w http.ResponseWriter, r *http.Request) (string, errors.HTTPError) {
	var statusCode int
	switch r.Method {
	case http.MethodGet:
		statusCode = http.StatusFound
	case http.MethodPost:
		statusCode = http.StatusSeeOther
	default:
		statusCode = http.StatusTemporaryRedirect
	}

	session, err := parseCookieFromRequest(r, SESSION_COOKIE_NAME)
	id := session.Values[SESSION_COOKIE_ID]

	if id == nil {
		if err != nil {
			log.Printf("Error retrieving session cookie: %v", err)
		} else {
			log.Printf("No session cookie found, redirecting to login...")
		}

		deleteCookie(w, SESSION_COOKIE_NAME)

		return "", errors.InternalRedirectError{
			StatusCode: statusCode,
			Location:   LOGIN_ENDPOINT,
		}
	}

	sessionId, ok := id.(string)
	if !ok || sessionId == "" {
		log.Printf("Failed to parse session ID to string, redirecting to login...")

		deleteCookie(w, SESSION_COOKIE_NAME)

		return "", errors.InternalRedirectError{
			StatusCode: statusCode,
			Location:   LOGIN_ENDPOINT,
		}
	}

	return sessionId, nil
}

func ParseSession(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (*models.Session, errors.HTTPError) {
	var id string
	var err errors.HTTPError

	id, err = getSessionIdFromCookie(w, r)
	if err != nil {
		return nil, err
	}

	session, err := models.GetSessionByID(ctx, db, id)

	if err != nil {
		log.Printf("Error retrieving session by ID %s: %v", id, err)

		deleteCookie(w, SESSION_COOKIE_NAME)

		return nil, errors.InternalRedirectError{
			StatusCode: http.StatusFound,
			Location:   LOGIN_ENDPOINT,
		}
	}

	return session, nil
}

func SaveSession(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request, session *models.Session) errors.HTTPError {
	if session.ID == uuid.Nil {
		if err := session.Save(ctx, db); err != nil {
			log.Printf("Error saving session: %v", err)
			return errors.HTTPErrorResponse{
				StatusCode:  http.StatusInternalServerError,
				Message:     "Internal Server Error",
				Description: "Failed to create user session.",
			}
		}
	}

	cookieSession, err := utils.NewCookieStore().Get(r, SESSION_COOKIE_NAME)
	if err != nil {
		log.Printf("Error retrieving session cookie: %v", err)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to retrieve session cookie.",
		}
	}

	cookieSession.Values[SESSION_COOKIE_ID] = session.ID.String()
	cookieSession.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(session.ExpiresAt.ExpiresAt.Sub(time.Now().UTC()).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}

	if err := cookieSession.Save(r, w); err != nil {
		log.Printf("Error saving session cookie: %v", err)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to save session cookie.",
		}
	}

	return nil
}
