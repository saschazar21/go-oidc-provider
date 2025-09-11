package helpers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

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

	cookieStore := utils.NewCookieStore()

	session, err := cookieStore.Get(r, SESSION_COOKIE_NAME)
	id := session.Values[SESSION_COOKIE_ID]

	if id == nil {
		if err != nil {
			log.Printf("Error retrieving session cookie: %v", err)
		} else {
			log.Printf("No session cookie found, redirecting to login...")
		}

		session.Options.MaxAge = -1 // Delete cookie
		if err := session.Save(r, w); err != nil {
			log.Printf("Error deleting invalid session cookie: %v", err)
		}

		return "", errors.InternalRedirectError{
			StatusCode: statusCode,
			Location:   LOGIN_PATH,
		}
	}

	sessionId, ok := id.(string)
	if !ok {
		log.Printf("Failed to parse session ID to string, redirecting to login...")

		session.Options.MaxAge = -1 // Delete cookie
		if err := session.Save(r, w); err != nil {
			log.Printf("Error deleting invalid session cookie: %v", err)
		}

		return "", errors.InternalRedirectError{
			StatusCode: statusCode,
			Location:   LOGIN_PATH,
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

		cookie := http.Cookie{
			Name:   SESSION_COOKIE_NAME,
			MaxAge: -1, // Delete cookie
		}

		http.SetCookie(w, &cookie)

		return nil, errors.InternalRedirectError{
			StatusCode: http.StatusFound,
			Location:   LOGIN_PATH,
		}
	}

	return session, nil
}

func SaveSession(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request, session *models.Session) errors.HTTPError {
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
	cookieSession.Options.HttpOnly = true
	cookieSession.Options.SameSite = http.SameSiteStrictMode
	cookieSession.Options.Secure = true
	cookieSession.Options.Path = "/"
	cookieSession.Options.MaxAge = int(session.ExpiresAt.ExpiresAt.Sub(time.Now().UTC()).Seconds())

	if err := cookieSession.Save(nil, w); err != nil {
		log.Printf("Error saving session cookie: %v", err)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to save session cookie.",
		}
	}

	return nil
}
