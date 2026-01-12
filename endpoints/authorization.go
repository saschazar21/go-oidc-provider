package endpoints

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func HandleAuthorization(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		// Handle GET request here
		handleAuthorization(w, r)
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

func handleAuthorization(w http.ResponseWriter, r *http.Request) {
	// Implementation of the authorization endpoint /authorize
	ctx := r.Context()
	conn := db.Connect(ctx)
	defer conn.Close()

	trx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		msg := "Failed to start database transaction"
		log.Printf("%s: %v", msg, err)

		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: msg,
		}

		err.Write(w)
		return
	}

	var auth *models.Authorization
	var authResponse utils.Writable
	var oidcErr errors.OIDCError

	if authResponse, auth, oidcErr = helpers.HandleAuthorizationRequest(ctx, trx, w, r); oidcErr != nil {
		log.Printf("Failed to handle authorization request: %v", oidcErr)
		if rbErr := trx.Rollback(); rbErr != nil {
			log.Printf("Failed to rollback transaction: %v", rbErr)
		}

		oidcErr.Write(w)
		return
	}

	if err := trx.Commit(); err != nil {
		msg := "Failed to commit database transaction"
		log.Printf("%s: %v", msg, err)

		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: msg,
		}

		err.Write(w)
		return
	}

	if authResponse != nil {
		authResponse.Write(w)
		return
	}

	// render authorization consent page, if user interaction is required
	templateData := struct {
		FormPostURI string
		Client      *models.Client
		Scope       []utils.Scope
		Year        int
	}{
		FormPostURI: helpers.AUTHORIZATION_DECISION_ENDPOINT,
		Client:      auth.Client,
		Scope:       auth.Scope,
		Year:        time.Now().UTC().Year(),
	}

	tmpl, err := template.New("authorization").Parse(DEFAULT_AUTHORIZATION_TEMPLATE)
	if err != nil {
		log.Printf("Failed to parse authorization template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render authorization page",
		}

		err.Write(w)
		return
	}

	if err := tmpl.Execute(w, templateData); err != nil {
		log.Printf("Failed to execute authorization template: %v", err)
		err := errors.HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "Failed to render authorization page",
		}

		err.Write(w)
		return
	}
}
