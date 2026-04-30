package endpoints

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/idtoken"
)

func HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// Implementation of the JWKS endpoint /.well-known/jwks.json

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Cache-Control, Content-Type")
		w.Header().Set("Allow", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))

		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead, http.MethodGet:
		handleJWKS(w, r)
	default:
		msg := "Unsupported request method. Only GET is allowed."
		log.Printf("%s Got %s", msg, r.Method)
		err := errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
			Headers: map[string]string{
				"Allow": fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions),
			},
		}

		err.Write(w)
	}
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Cache-Control, Content-Type")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	buf, err := json.Marshal(resp)
	if err != nil {
		msg := "Failed to marshal JWKS response to JSON"
		log.Printf("%s: %v", msg, err)

		err := errors.JSONError{
			StatusCode:  http.StatusInternalServerError,
			ErrorCode:   errors.SERVER_ERROR,
			Description: &msg,
		}

		err.Write(w)
		return
	}

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Write(buf)
}
