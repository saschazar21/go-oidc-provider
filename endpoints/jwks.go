package endpoints

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
)

func HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// Implementation of the JWKS endpoint /.well-known/jwks.json

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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Allow", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet:
		handleJWKS(w, r)
	default:
		msg := "Unsupported request method. Only GET is allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "GET, OPTIONS",
			},
		}

		err.Write(w)
	}
}

func handleJWKS(w http.ResponseWriter, _ *http.Request) {
	keys, err := idtoken.LoadKeys()
	if err != nil {
		msg := "Failed to load JWKs"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}

	var jwks []interface{}

	for alg, key := range keys {
		if strings.HasPrefix(alg, "HS") {
			// skip symmetric keys
			continue
		}

		jwk, err := idtoken.PublicKeyToJWK(key, alg)
		if err != nil {
			msg := "Failed to convert public key to JWK"
			log.Printf("%s: %v", msg, err)

			err := errors.JSONError{
				StatusCode:  http.StatusInternalServerError,
				ErrorCode:   errors.SERVER_ERROR,
				Description: &msg,
			}

			err.Write(w)
			return
		}
		jwks = append(jwks, jwk)
	}

	resp := struct {
		Keys []interface{} `json:"keys"`
	}{
		Keys: jwks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		msg := "Failed to encode JWKS response to JSON"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}
}
