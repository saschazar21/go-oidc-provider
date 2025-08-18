package models

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-playground/validator/v10"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
)

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

	var auth Authorization
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

func (a *Address) Validate() error {
	if err := utils.NewCustomValidator().Struct(a); err != nil {
		return err
	}
	return nil
}

func (a *Authorization) Validate() errors.OIDCError {
	err := utils.NewCustomValidator().Struct(a)

	if err != nil {
		log.Printf("Validation error in authorization: %v", err)
		switch t := err.(type) {
		case *validator.InvalidValidationError:
			description := t.Error()
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
				RedirectURI:      a.RedirectURI,
			}
		case *validator.ValidationErrors:
			firstError := (*t)[0]
			if firstError.Field() == "Scope" {
				description := fmt.Sprintf("invalid scope: %s", firstError.Value())
				return errors.OIDCErrorResponse{
					ErrorCode:        errors.INVALID_SCOPE,
					ErrorDescription: &description,
					RedirectURI:      a.RedirectURI,
				}
			}

			if firstError.Field() == "ResponseType" {
				description := fmt.Sprintf("unsupported response_type: %s", firstError.Value())
				return errors.OIDCErrorResponse{
					ErrorCode:        errors.UNSUPPORTED_RESPONSE_TYPE,
					ErrorDescription: &description,
					RedirectURI:      a.RedirectURI,
				}
			}

			description := fmt.Sprintf("invalid %s: %s", firstError.Field(), firstError.Value())
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
				RedirectURI:      a.RedirectURI,
			}
		default:
			description := "invalid authorization request"
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
				RedirectURI:      a.RedirectURI,
			}
		}
	}

	if a.Client == nil {
		log.Println("Client is not populated in authorization.")
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	client := a.Client

	if err := client.Validate(); err != nil {
		log.Printf("Validation error in client: %v", err)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	if a.Client.IsPKCERequired && (a.CodeChallenge == nil || *a.CodeChallenge == "") {
		description := "PKCE is required for this client, but no code_challenge provided"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:   errors.SERVER_ERROR,
			RedirectURI: a.RedirectURI,
		}
	}

	isFound := false
	for _, redirectUri := range a.Client.RedirectURIs {
		if a.RedirectURI == redirectUri {
			isFound = true
			break
		}
	}
	if !isFound {
		description := fmt.Sprintf("redirect_uri %s is not allowed for this client", a.RedirectURI)
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
			RedirectURI:      a.RedirectURI,
		}
	}

	isFound = false
	for _, responseType := range *a.Client.ResponseTypes {
		if a.ResponseType == responseType {
			isFound = true
			break
		}
	}
	if !isFound {
		description := fmt.Sprintf("response_type %s is not allowed for this client", a.ResponseType)
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
			RedirectURI:      a.RedirectURI,
		}
	}

	return nil
}

func (c *Client) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(c)

	return
}

func (s *Session) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(s)

	return
}

func (u *User) Validate() error {
	if err := utils.NewCustomValidator().Struct(u); err != nil {
		return err
	}

	if u.Address != nil {
		if err := u.Address.Validate(); err != nil {
			return err
		}
	}

	return nil
}
