package endpoints

import (
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/db"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
)

func HandleToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fallthrough
	case http.MethodHead:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	case http.MethodPost:
		// Handle POST request here
		handleToken(w, r)
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

func handleToken(w http.ResponseWriter, r *http.Request) {
	// Implementation of the token endpoint /token
	tr, err := helpers.ParseTokenRequest(r)
	if err != nil {
		log.Printf("Failed to parse token request: %v", err)

		err.Write(w)
		return
	}

	ctx := r.Context()
	conn := db.Connect(ctx)
	defer conn.Close()

	tx, txErr := conn.BeginTx(ctx, nil)
	if txErr != nil {
		msg := "Failed to start database transaction"
		log.Printf("%s: %v", msg, txErr)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}

	tokenMap, err := tr.HandleRequest(ctx, conn)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			log.Printf("Failed to rollback transaction: %v", rbErr)
		}

		log.Printf("Failed to handle token request: %v", err)
		err.Write(w)
		return
	}

	if err := tx.Commit(); err != nil {
		msg := "Failed to commit database transaction"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}

	var tokens []*models.Token
	for _, token := range tokenMap {
		tokens = append(tokens, token)
	}

	resp := helpers.NewTokenResponse(tokens...)
	resp.Write(w)
}
