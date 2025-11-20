package endpoints

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
)

func HandleTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		origin, err := parseOrigin(r)
		if err != nil {
			err.Write(w)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
		handleTokenIntrospection(w, r)
	default:
		msg := "Unsupported request method. Only POST is allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "POST, OPTIONS",
			},
		}

		err.Write(w)
	}
}

func handleTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	// Implementation of the token introspection endpoint /introspect
	msg := "Error while fetching token from database"
	var oidcErr errors.HTTPError = errors.JSONError{
		StatusCode:  http.StatusInternalServerError,
		ErrorCode:   errors.SERVER_ERROR,
		Description: &msg,
	}

	ctx := r.Context()
	conn := db.Connect(ctx)
	defer conn.Close()

	tx, txErr := conn.BeginTx(ctx, nil)
	if txErr != nil {
		msg := "Failed to start database transaction"
		log.Printf("%s: %v", msg, txErr)
		oidcErr.Write(w)
		return
	}

	ti, err := helpers.ParseTokenIntrospectionRequest(ctx, tx, r)
	if err != nil {
		log.Printf("Failed to parse token introspection request: %v", err)
		tx.Rollback()

		err.Write(w)
		return
	}

	res := ti.CreateResponse(ctx, tx)

	if commitErr := tx.Commit(); commitErr != nil {
		msg := "Failed to commit database transaction"
		log.Printf("%s: %v", msg, commitErr)
		oidcErr.Write(w)
		return
	}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("Failed to write token introspection response: %v", err)
		oidcErr.Write(w)
		return
	}
}
