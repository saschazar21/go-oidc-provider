package errors

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/saschazar21/go-oidc-provider/utils"
)

type OIDCError interface {
	Error() string
	Write(w http.ResponseWriter)
}

type OIDCErrorResponse struct {
	ErrorCode        OIDCErrorCode `json:"error" schema:"error,required"`
	ErrorDescription *string       `json:"error_description,omitempty" schema:"error_description"`
	ErrorURI         *string       `json:"error_uri,omitempty" validate:"omitempty,http_url" schema:"error_uri"`
	State            *string       `json:"state,omitempty" schema:"state"`

	RedirectURI string `json:"-" validate:"http_url" schema:"-"`
	IsFragment  bool   `json:"-" schema:"-"`
	StatusCode  int    `json:"-" schema:"-"`
}

func (e OIDCErrorResponse) Error() string {
	if e.ErrorDescription != nil {
		return fmt.Sprintf("%s: %s", e.ErrorCode, *e.ErrorDescription)
	}
	return string(e.ErrorCode)
}

func (e OIDCErrorResponse) Write(w http.ResponseWriter) {
	log.Println(e.Error())
	u, err := url.Parse(e.RedirectURI)

	if err == nil {
		validate := utils.NewCustomValidator()
		err = validate.Struct(e)
	}

	if err != nil {
		var description string
		if e.ErrorDescription != nil {
			description = *e.ErrorDescription
		}

		var redirectURI string
		if e.RedirectURI != "" {
			redirectURI = e.RedirectURI
		}

		err := HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     string(e.ErrorCode),
			Description: description,
			RedirectURI: redirectURI,
		}

		err.Write(w)

		return
	}

	encoder := utils.NewCustomEncoder()

	var query url.Values
	if err := encoder.Encode(e, query); err != nil {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}

	if e.IsFragment {
		u.Fragment = query.Encode()
	} else {
		u.RawQuery = query.Encode()
	}

	if e.StatusCode < 100 {
		e.StatusCode = http.StatusFound
	}

	w.WriteHeader(e.StatusCode)
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", u.String())
	w.Write([]byte(fmt.Sprintf("<html><body><script>window.location.href='%s';</script><a href='%s'>Back to %s</a></body></html>", u.String(), u.String(), e.RedirectURI)))
}
