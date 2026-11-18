package endpoints

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func HandleMagicLinkToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		origin, err := parseOrigin(r)
		if err != nil {
			err.Write(w)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		// Handle GET request here
		handleMagicLinkToken(w, r)
	case http.MethodPost:
		handleConsumeMagicLinkToken(w, r)
	default:
		msg := "Unsupported request method. Only GET & POST are allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     "Method Not Allowed",
			Description: msg,
			Headers: map[string]string{
				"Allow": "GET, POST, OPTIONS",
			},
		}

		err.Write(w)
	}
}

func handleMagicLinkToken(w http.ResponseWriter, r *http.Request) {
	// Implementation of the magic link token endpoint /login/magic
	templateData := struct {
		FormPostURI string
		Token       string
		ID          string
		Year        int
	}{
		FormPostURI: helpers.CONSUME_MAGIC_LINK_ENDPOINT,
		Token:       r.FormValue("token"),
		ID:          r.FormValue("id"),
		Year:        time.Now().UTC().Year(),
	}

	tmpl, err := template.New("magic_link").Parse(DEFAULT_MAGIC_LINK_TEMPLATE)
	if err != nil {
		log.Printf("Failed to parse magic link template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render magic link page",
		}

		err.Write(w)
		return
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Printf("Failed to execute magic link template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render magic link page",
		}

		err.Write(w)
		return
	}
}

func handleConsumeMagicLinkToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Implementation of the consume magic link token endpoint /login/magic
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		msg := "Unsupported Content-Type. Only application/x-www-form-urlencoded is allowed."
		log.Println(msg)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusUnsupportedMediaType,
			Message:     "Unsupported Media Type",
			Description: msg,
		}

		err.Write(w)
		return
	}

	if r.FormValue("token") == "" {
		msg := "Token is required."
		log.Println(msg)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: msg,
		}

		err.Write(w)
		return
	}

	ctx := r.Context()
	conn := db.Connect(ctx)
	defer conn.Close()

	trx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to process request",
		}

		err.Write(w)
		return
	}

	defer trx.Rollback()

	token, err := helpers.ConsumeMagicLinkToken(ctx, trx, w, r)
	if err != nil {
		if err := trx.Rollback(); err != nil {
			log.Printf("Failed to rollback transaction: %v", err)
		}
		log.Printf("Failed to consume magic link token: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: "Invalid or expired magic link token",
		}

		err.Write(w)
		return
	}

	if token == nil || token.Result == nil || *token.Result != utils.SUCCESS || token.User == nil {
		// FAILED and EXPIRED are terminal model outcomes, not Go errors. Persist
		// them before rejecting so a second attempt cannot reuse the token.
		if err := trx.Commit(); err != nil {
			log.Printf("Failed to commit rejected magic link token: %v", err)
			errors.HTTPErrorResponse{StatusCode: http.StatusInternalServerError, Message: "Internal Server Error", Description: "Failed to process request"}.Write(w)
			return
		}
		errors.HTTPErrorResponse{StatusCode: http.StatusBadRequest, Message: "Bad Request", Description: "Invalid or expired magic link token"}.Write(w)
		return
	}

	ipAddress := utils.EncryptedString(utils.ParseClientIP(r))
	userAgent := r.Header.Get("User-Agent")
	methods := []utils.AMR{utils.AMR_EMAIL}

	session := models.Session{
		UserID:    token.User.ID,
		User:      token.User,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		AMR:       &methods,
		AuthTime:  time.Now().UTC(),
	}

	if err := session.Save(ctx, trx); err != nil {
		if err := trx.Rollback(); err != nil {
			log.Printf("Failed to rollback transaction: %v", err)
		}
		log.Printf("Failed to save session after consuming magic link token: %v", err)

		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to create user session",
		}

		err.Write(w)
		return
	}

	if err := trx.Commit(); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to process request",
		}

		err.Write(w)
		return
	}

	if err := helpers.WriteSessionCookie(w, r, &session); err != nil {
		err.Write(w)
		return
	}

	cookieSession := utils.NewCookieStore()
	redirectSession, _ := cookieSession.Get(r, helpers.AUTHORIZATION_COOKIE_NAME)
	authId, ok := redirectSession.Values[helpers.AUTHORIZATION_COOKIE_ID].(string)
	if ok && authId != "" {
		log.Printf("Redirecting to authorization endpoint for handling authorization ID: %s", authId)
		http.Redirect(w, r, helpers.AUTHORIZATION_GRANT_ENDPOINT, http.StatusSeeOther)
		return
	}

	redirectCookie, err := r.Cookie(helpers.REDIRECT_COOKIE_NAME) // make sure to access plaintext cookie here
	if err == nil {
		log.Printf("Redirecting to URI set in cookie: %s", redirectCookie.Value)
		// remove redirect cookie after use
		expiredCookie := &http.Cookie{
			Name:     helpers.REDIRECT_COOKIE_NAME,
			Value:    "",
			MaxAge:   -1,
			HttpOnly: true,
			Path:     "/",
			Secure:   true,
		}

		http.SetCookie(w, expiredCookie)
		location := "/"
		if isSafeMagicLinkRedirect(redirectCookie.Value) {
			location = redirectCookie.Value
		}
		http.Redirect(w, r, location, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func isSafeMagicLinkRedirect(location string) bool {
	parsed, err := url.Parse(location)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Opaque != "" {
		return false
	}
	// Check the decoded path too, so encoded slashes/backslashes cannot turn a
	// local continuation into a browser-interpreted network-path reference.
	for _, value := range []string{location, parsed.Path} {
		if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, `\`) || strings.ContainsFunc(value, unicode.IsControl) {
			return false
		}
	}
	return true
}
