package endpoints

import (
	"html/template"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func HandleEndSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		origin, err := parseOrigin(r)
		if err != nil {
			err.Write(w)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet, http.MethodPost:
		handleEndSession(w, r)
	default:
		msg := "Unsupported request method. Only GET and POST are allowed."
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

func handleEndSession(w http.ResponseWriter, r *http.Request) {
	// Implementation of the end session endpoint /logout
	ers, err := helpers.ParseEndSessionRequest(r)
	if err != nil {
		log.Printf("Failed to parse end_session request: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     "Bad Request",
			Description: "Failed to parse end_session request",
		}

		err.Write(w)
		return
	}

	ctx := r.Context()
	conn := db.Connect(ctx)
	defer conn.Close()
	if err := ers.ValidatePostLogoutRedirect(ctx, conn); err != nil {
		log.Printf("Invalid post-logout redirect request: %v", err)
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		mediaType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/x-www-form-urlencoded" {
			http.Error(w, "Unsupported logout request content type", http.StatusUnsupportedMediaType)
			return
		}
	}
	if r.Method == http.MethodGet {
		csrf, err := helpers.SaveLogoutConfirmation(w, r)
		if err != nil {
			http.Error(w, "Failed to start logout confirmation", http.StatusInternalServerError)
			return
		}
		renderLogoutConfirmation(w, csrf, ers.IDTokenHint, ers.ClientID, ers.PostLogoutRedirectURI, ers.State)
		return
	}
	if !helpers.ValidateLogoutConfirmation(r, ers.CSRF) || ers.Confirm != "yes" {
		http.Error(w, "Invalid logout confirmation", http.StatusBadRequest)
		return
	}

	if err := ers.LogoutSessions(ctx, conn, w); err != nil {
		log.Printf("Failed to logout sessions: %v", err)
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	if cookie, err := utils.NewCookieStore().Get(r, helpers.LOGOUT_COOKIE_NAME); err == nil {
		cookie.Options = &sessions.Options{Path: helpers.LOGOUT_ENDPOINT, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
		if err := cookie.Save(r, w); err != nil {
			log.Printf("Failed to clear logout confirmation cookie: %v", err)
		}
	}

	http.SetCookie(w, &http.Cookie{Name: helpers.SESSION_COOKIE_NAME, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})

	var location *url.URL
	if ers.PostLogoutRedirectURI != "" {
		location, _ = url.Parse(ers.PostLogoutRedirectURI)
		if ers.State != nil {
			q := location.Query()
			q.Set("state", *ers.State)
			location.RawQuery = q.Encode()
		}
	}

	var dest string
	if location != nil {
		dest = location.String()
	} else {
		issuer, _ := url.Parse(os.Getenv(utils.ISSUER_URL_ENV))
		issuer.Path = helpers.LOGIN_ENDPOINT
		dest = issuer.String()
	}

	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func renderLogoutConfirmation(w http.ResponseWriter, csrf, idTokenHint, clientID, redirectURI string, stateValue *string) {
	// This form is intentionally rendered by the OP so the user must actively
	// confirm logout, as required for requests without an ID Token hint.
	const page = `<!doctype html><html><head><meta charset="utf-8"><title>Confirm logout</title></head><body><main><h1>Confirm logout</h1><p>Do you want to log out of this provider?</p><form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="confirm" value="yes"><input type="hidden" name="id_token_hint" value="{{.IDTokenHint}}"><input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="post_logout_redirect_uri" value="{{.RedirectURI}}"><input type="hidden" name="state" value="{{.State}}"><button type="submit">Log out</button></form></main></body></html>`
	tmpl, err := template.New("logout-confirmation").Parse(page)
	if err != nil {
		http.Error(w, "Failed to render logout confirmation", http.StatusInternalServerError)
		return
	}
	state := ""
	if stateValue != nil {
		state = *stateValue
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, struct {
		Action      string
		CSRF        string
		IDTokenHint string
		ClientID    string
		RedirectURI string
		State       string
	}{helpers.LOGOUT_ENDPOINT, csrf, idTokenHint, clientID, redirectURI, state}); err != nil {
		log.Printf("Failed to render logout confirmation page: %v", err)
	}
}
