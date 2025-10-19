package endpoints

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/utils"
)

const (
	DEFAULT_LOGIN_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login</title>
</head>
<body>
		<h1>Login</h1>
		<form method="POST" action="{.FormPostURI}">
			<label for="email">E-Mail:</label>
			<input type="email" id="email" name="email" required autofocus>
			<button type="submit">Login</button>
		</form>
</body>
</html>`
)

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Allow", "GET, POST, OPTIONS")
	case http.MethodGet:
		// Handle GET request here
		handleLogin(w, r)
	case http.MethodPost:
		// Handle POST request here
		handleLoginPost(w, r)
	default:
		msg := "Unsupported request method. Only GET & POST are allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     "Method Not Allowed",
			Description: msg,
			Headers: map[string]string{
				"Allow": "GET, OPTIONS",
			},
		}

		err.Write(w)
	}
}

func handleLogin(w http.ResponseWriter, _ *http.Request) {
	// Implementation of the login endpoint /login
	templateData := struct {
		FormPostURI string
	}{
		FormPostURI: helpers.LOGIN_ENDPOINT,
	}

	tmpl, err := template.New("login").Parse(DEFAULT_LOGIN_TEMPLATE)
	if err != nil {
		log.Printf("Failed to parse login template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render login page",
		}

		err.Write(w)
		return
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Printf("Failed to execute login template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render login page",
		}

		err.Write(w)
		return
	}
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	// Implementation of the login POST endpoint /login
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

	if r.FormValue("email") == "" {
		msg := "Email is required."
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
		msg := "Failed to begin database transaction."
		log.Printf("%s: %v", msg, err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: msg,
		}

		err.Write(w)
		return
	}

	magicLinkToken, err := helpers.CreateMagicLinkToken(ctx, trx, w, r)
	if err != nil {
		if err := trx.Rollback(); err != nil {
			log.Printf("Failed to rollback transaction: %v", err)
		}

		log.Printf("Failed to create magic link token: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to create magic link token",
		}

		err.Write(w)
		return
	}

	if err := trx.Commit(); err != nil {
		msg := "Failed to commit database transaction."
		log.Printf("%s: %v", msg, err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: msg,
		}

		err.Write(w)
		return
	}

	if magicLinkToken != nil {
		log.Printf("Magic link token created with ID %s for e-mail %s", magicLinkToken.ID.String(), magicLinkToken.Email)
	} else {
		log.Printf("No magic link token created for e-mail %s (not found or not whitelisted)", r.FormValue("email"))
	}

	url, err := url.Parse(os.Getenv(utils.ISSUER_URL_ENV))
	if err != nil {
		log.Printf("Failed to parse issuer URL: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to parse issuer URL",
		}

		err.Write(w)
		return
	}

	url.Path = helpers.CONSUME_MAGIC_LINK_ENDPOINT

	// In demo mode, append token and id as query parameters for easy access, since there is no e-mail sent
	if os.Getenv("DEMO_MODE") == "true" && magicLinkToken != nil {
		q := url.Query()
		q.Set("token", string(*magicLinkToken.Token))
		q.Set("id", magicLinkToken.ID.String())
		url.RawQuery = q.Encode()
	}

	http.Redirect(w, r, url.String(), http.StatusSeeOther)
}
