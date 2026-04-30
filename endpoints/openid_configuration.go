package endpoints

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func HandleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// Implementation of the OpenID Connect Discovery endpoint /.well-known/openid-configuration

	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Cache-Control, Content-Type")
		w.Header().Set("Allow", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))

		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead:
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet:
		handleOpenIDConfiguration(w, r)
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

func handleOpenIDConfiguration(w http.ResponseWriter, _ *http.Request) {
	customConfig := &models.OpenIDConfiguration{
		JWKSURI:                    helpers.JWKS_ENDPOINT,
		AuthorizationEndpoint:      helpers.AUTHORIZATION_GRANT_ENDPOINT,
		TokenEndpoint:              helpers.TOKEN_ENDPOINT,
		TokenIntrospectionEndpoint: helpers.TOKEN_INTROSPECTION_ENDPOINT,
		UserInfoEndpoint:           helpers.USERINFO_ENDPOINT,
		EndSessionEndpoint:         helpers.LOGOUT_ENDPOINT,
		ResponseTypesSupported: []utils.ResponseType{
			utils.CODE,
			utils.ID_TOKEN,
			utils.ID_TOKEN_TOKEN,
		},
	}

	config, err := helpers.NewOpenIDConfiguration(customConfig)
	if err != nil {
		err.Write(w)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, %s, %s", http.MethodGet, http.MethodHead, http.MethodOptions))
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Cache-Control, Content-Type")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(config); err != nil {
		msg := "Failed to encode OpenID configuration response to JSON"
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
