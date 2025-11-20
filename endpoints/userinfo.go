package endpoints

import (
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
)

func HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		origin, err := parseOrigin(r)
		if err != nil {
			err.Write(w)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet, http.MethodPost:
		handleUserinfo(w, r)
	default:
		msg := "Unsupported request method. Only GET and POST are allowed."
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "GET, POST, OPTIONS",
			},
		}
		err.Write(w)
	}
}

func handleUserinfo(w http.ResponseWriter, r *http.Request) {
	// Implementation of the UserInfo endpoint /userinfo
	msg := "Error while processing userinfo request"
	var oidcErr errors.HTTPError = errors.JSONError{
		StatusCode:  http.StatusInternalServerError,
		ErrorCode:   errors.SERVER_ERROR,
		Description: &msg,
	}

	ctx := r.Context()
	db := db.Connect(ctx)
	defer db.Close()

	tx, txErr := db.BeginTx(ctx, nil)
	if txErr != nil {
		log.Printf("Error starting database transaction: %v", txErr)
		oidcErr.Write(w)
		return
	}

	user, err := helpers.HandleUserinfoRequest(ctx, tx, r)
	if err != nil {
		tx.Rollback()
		log.Printf("Error handling userinfo request: %v", err)
		err.Write(w)
		return
	}

	if err := tx.Commit(); err != nil {
		msg := "Error committing database transaction"
		log.Printf("%s: %v", msg, err)
		oidcErr.Write(w)
		return
	}

	user.Write(w)
}
