package endpoints

import (
	"html/template"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

const (
	DEFAULT_MAGIC_LINK_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Magic Link</title>
</head>
<body>
		<h1>Magic Link</h1>
		<form method="POST" action="{.FormPostURI}">
			<label for="token">Token:</label>
			<input type="text" id="token" name="token" value="{.Token}" required autofocus>
			<input type="hidden" name="id" value="{.ID}">
			<button type="submit">Submit</button>
		</form>
</body>
</html>`
)

func HandleMagicLinkToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Allow", "GET, POST, OPTIONS")
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
	}{
		FormPostURI: helpers.CONSUME_MAGIC_LINK_ENDPOINT,
		Token:       r.FormValue("token"),
		ID:          r.FormValue("id"),
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

	ipAddress := utils.EncryptedString(utils.ParseClientIP(r))
	userAgent := r.Header.Get("User-Agent")

	session := models.Session{
		UserID:    token.User.ID,
		User:      token.User,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
	}

	if err := helpers.SaveSession(ctx, conn, w, r, &session); err != nil {
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

	cookieSession := utils.NewCookieStore()
	redirectSession, _ := cookieSession.Get(r, helpers.REDIRECT_COOKIE_NAME)
	redirectURI, ok := redirectSession.Values[helpers.REDIRECT_URI].(string)
	if ok && redirectURI != "" {
		// Clear redirect cookie
		redirectSession.Options.MaxAge = -1
		if err := redirectSession.Save(r, w); err != nil {
			log.Printf("Error deleting redirect cookie: %v", err)
		}

		http.Redirect(w, r, redirectURI, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
