package endpoints

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func HandleEndSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	case http.MethodGet:
		handleEndSession(w, r)
	default:
		msg := "Unsupported request method. Only GET is allowed."
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

	if err := ers.LogoutSessions(ctx, conn, w); err != nil {
		log.Printf("Failed to logout sessions: %v", err)
	}

	w.Header().Set("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")

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

	http.Redirect(w, r, dest, http.StatusTemporaryRedirect)
}
