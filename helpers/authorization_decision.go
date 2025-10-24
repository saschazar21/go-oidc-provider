package helpers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type authorizationDecision struct {
	Action *utils.AuthStatus `json:"-" schema:"action" validate:"required,oneof=approved denied"`

	auth    *models.Authorization `json:"-" schema:"-"`
	session *models.Session       `json:"-" schema:"-"`
}

func (ad *authorizationDecision) Sanitize() {
	if ad.Action != nil {
		status := strings.ToLower(strings.TrimSpace(string(*ad.Action)))
		ad.Action = (*utils.AuthStatus)(&status)
	}
}

func (ad *authorizationDecision) updateAuthorization(ctx context.Context, db bun.IDB) errors.OIDCError {
	ad.auth.IsActive = ad.Action != nil && *ad.Action == utils.APPROVED
	ad.auth.Status = ad.Action
	ad.auth.UserID = ad.session.UserID
	ad.auth.User = ad.session.User

	if ad.auth.IsActive {
		now := time.Now().UTC()
		ad.auth.ApprovedAt = &now
	}

	if err := ad.auth.Save(ctx, db); err != nil {
		msg := fmt.Sprintf("Failed to save %s authorization", string(*ad.auth.Status))
		log.Printf("%s: %v", msg, err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			StatusCode:       http.StatusInternalServerError,
		}
	}

	return nil
}

func (ad *authorizationDecision) parseAuthorizationCookie(ctx context.Context, db bun.IDB, r *http.Request) errors.OIDCError {
	cookie, err := parseCookieFromRequest(r, AUTHORIZATION_COOKIE_NAME)
	id := cookie.Values[AUTHORIZATION_COOKIE_ID]
	if err != nil || id == nil {
		msg := "No valid authorization cookie found"
		log.Printf("%s: %v", msg, err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			StatusCode:       http.StatusBadRequest,
		}
	}

	authId, ok := id.(string)
	if !ok {
		msg := "Failed to parse authorization ID from cookie"
		log.Printf("%s", msg)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			StatusCode:       http.StatusBadRequest,
		}
	}

	auth, oidcErr := models.GetAuthorizationByID(ctx, db, authId)
	if oidcErr != nil {
		return oidcErr
	}

	ad.auth = auth
	return nil
}

func (ad *authorizationDecision) parseSessionCookie(ctx context.Context, db bun.IDB, r *http.Request) errors.OIDCError {
	cookie, err := parseCookieFromRequest(r, SESSION_COOKIE_NAME)
	id := cookie.Values[SESSION_COOKIE_ID]
	if err != nil || id == nil {
		msg := "No valid session cookie found"
		log.Printf("%s: %v", msg, err)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusForbidden,
			Message:     errors.FORBIDDEN,
			Description: msg,
		}
	}

	sessionId, ok := id.(string)
	if !ok {
		msg := "Failed to parse session ID from cookie"
		log.Printf("%s", msg)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusForbidden,
			Message:     errors.FORBIDDEN,
			Description: msg,
		}
	}

	session, oidcErr := models.GetSessionByID(ctx, db, sessionId)
	if oidcErr != nil {
		msg := "Failed to find session in database"
		log.Printf("%s: %v", msg, oidcErr)
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusForbidden,
			Message:     errors.FORBIDDEN,
			Description: msg,
		}
	}

	ad.session = session
	return nil
}

func HandleAuthorizationDecision(ctx context.Context, db bun.IDB, r *http.Request) (utils.Writable, errors.OIDCError) {
	if r.Method != http.MethodPost {
		msg := "Unsupported request method. Only POST is allowed."
		log.Printf("%s Got %s", msg, r.Method)

		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     "Method Not Allowed",
			Description: msg,
			Headers: map[string]string{
				"Allow": "POST",
			},
		}
		return nil, err
	}

	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Unsupported Content-Type. Only application/x-www-form-urlencoded is allowed."
		log.Printf("%s Got %s", msg, r.Header.Get("Content-Type"))
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusUnsupportedMediaType,
			Message:     "Unsupported Media Type",
			Description: msg,
		}
		return nil, err
	}

	return handleAuthorizationDecision(ctx, db, r)
}

func handleAuthorizationDecision(ctx context.Context, db bun.IDB, r *http.Request) (utils.Writable, errors.OIDCError) {
	var decision authorizationDecision

	if err := decision.parseSessionCookie(ctx, db, r); err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		msg := "Failed to parse form data"
		log.Printf("%s: %v", msg, err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: msg,
		}
		return nil, err
	}

	decoder := utils.NewCustomDecoder()
	if err := decoder.Decode(&decision, r.PostForm); err != nil {
		msg := "Failed to decode authorization decision"
		log.Printf("%s: %v", msg, err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: msg,
		}
		return nil, err
	}

	if decision.Action == nil {
		msg := "Authorization decision 'action' is required"
		log.Printf("%s", msg)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: msg,
		}
		return nil, err
	}

	decision.Sanitize()

	if err := decision.parseAuthorizationCookie(ctx, db, r); err != nil {
		return nil, err
	}

	// Process the authorization decision (approve/deny)
	switch *decision.Action {
	case utils.APPROVED, utils.DENIED:
		// Handle decision
		if err := decision.updateAuthorization(ctx, db); err != nil {
			return nil, err
		}

		if *decision.Action == utils.DENIED {
			// If denied, return an error response
			msg := "The end-user denied the authorization request"
			log.Printf("%s", msg)
			err := errors.OIDCErrorResponse{
				ErrorCode:        errors.ACCESS_DENIED,
				ErrorDescription: &msg,
				RedirectURI:      decision.auth.RedirectURI,
				State:            decision.auth.State,
				IsFragment:       decision.auth.ResponseType != "" && decision.auth.ResponseType != utils.CODE,
				StatusCode:       http.StatusSeeOther,
			}
			return err, nil // return error response as Writable, so that transaction can be committed
		}

		ar, err := NewAuthorizationResponse(ctx, db, decision.auth)
		if err != nil {
			return nil, err
		}

		ar.StatusCode = http.StatusSeeOther
		return ar, nil
	default:
		msg := "Unsupported authorization decision"
		log.Printf("%s: %v", msg, decision.Action)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: msg,
		}
		return nil, err
	}
}
