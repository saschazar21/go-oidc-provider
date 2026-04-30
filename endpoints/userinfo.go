package endpoints

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

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
		w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, %s, %s, %s", http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions))
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Accept, Accept-Language, Cache-Control, Content-Type")
		w.Header().Set("Allow", fmt.Sprintf("%s, %s, %s, %s", http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions))

		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead, http.MethodGet, http.MethodPost:
		handleUserinfo(w, r)
	default:
		msg := "Unsupported request method. Only GET and POST are allowed."
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": fmt.Sprintf("%s, %s, %s, %s", http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions),
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

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "Cache-Control")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	buf, httpErr := json.Marshal(user)
	if httpErr != nil {
		msg := "Error encoding userinfo response to JSON"
		log.Printf("%s: %v", msg, httpErr)
		oidcErr.Write(w)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}

	w.Write(buf)
}
