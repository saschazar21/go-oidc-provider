package endpoints

import (
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
)

func HandleAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost:
		handleAuthorizationDecision(w, r)
	default:
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

		err.Write(w)
	}
}

func handleAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	// Implementation of the authorization decision endpoint /authorize/decision
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

	decisionResponse, oidcErr := helpers.HandleAuthorizationDecision(ctx, trx, r)
	if oidcErr != nil || decisionResponse == nil {
		log.Printf("Failed to handle authorization decision: %v", oidcErr)
		if rbErr := trx.Rollback(); rbErr != nil {
			log.Printf("Failed to rollback transaction: %v", rbErr)
		}

		if oidcErr == nil {
			msg := "Unknown error during authorization decision handling"
			oidcErr = &errors.HTTPErrorResponse{
				StatusCode:  http.StatusInternalServerError,
				Message:     "Internal Server Error",
				Description: msg,
			}
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

	decisionResponse.Write(w)
}
