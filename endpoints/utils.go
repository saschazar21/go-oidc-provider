package endpoints

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/saschazar21/go-oidc-provider/errors"
)

func parseOrigin(r *http.Request) (string, errors.HTTPError) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err == nil && u.Scheme != "" && u.Host != "" {
			origin = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		} else {
			origin = ""
		}
	}

	if origin == "" {
		log.Printf("No Origin header provided in CORS preflight request")
		msg := "Invalid origin, cannot process CORS request"
		err := errors.JSONError{
			StatusCode:  http.StatusForbidden,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
		return "", err
	}

	return origin, nil
}
