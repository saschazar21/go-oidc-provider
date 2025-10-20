package helpers

import (
	"log"
	"net/http"
	"net/url"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func (ad *authorizationDecision) Validate() errors.OIDCError {
	validator := utils.NewCustomValidator()
	if err := validator.Struct(ad); err != nil {
		msg := "Authorization decision validation failed"
		log.Printf("%s: %v", msg, err)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			StatusCode:       http.StatusBadRequest,
		}
	}
	return nil
}

func (ar *authorizationRequest) Validate() errors.OIDCError {
	switch ar.r.Method {
	case http.MethodGet:
		ar.params = ar.r.URL.Query()
	case http.MethodPost:
		if err := ar.r.ParseForm(); err != nil {
			return errors.HTTPErrorResponse{
				StatusCode:  http.StatusBadRequest,
				Message:     errors.BAD_REQUEST,
				Description: "Failed to parse form data.",
			}
		}
		ar.params = ar.r.PostForm
	default:
		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusMethodNotAllowed,
			Message:     errors.METHOD_NOT_ALLOWED,
			Description: "Unsupported request method. Only GET and POST are allowed.",
			Headers: map[string]string{
				"Allow": "GET, POST",
			},
		}
	}

	var auth models.Authorization
	decoder := utils.NewCustomDecoder()

	if err := decoder.Decode(&auth, ar.params); err != nil {
		redirectUri := ar.params.Get("redirect_uri")

		msg := "Failed to decode authorization request parameters"
		log.Printf("%s: %v", msg, err)

		if _, err := url.ParseRequestURI(redirectUri); err != nil {
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &msg,
				RedirectURI:      redirectUri,
			}
		}

		return errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: msg,
		}
	}

	ar.authorization = &auth

	return nil
}

func (ar *authorizationResponse) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(ar)

	return
}

func (cr *createMagicLinkTokenRequest) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(cr)

	return
}

func (ers *endSessionRequest) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(ers)

	return
}

func (tr *tokenRequest) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(tr)

	return
}

func (tr *tokenResponse) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(tr)

	return
}

func (vr *validateMagicLinkTokenRequest) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(vr)

	return
}
