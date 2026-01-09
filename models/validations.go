package models

import (
	"fmt"
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/utils"
)

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

	if (a.Client.IsPKCERequired != nil && *a.Client.IsPKCERequired) && (a.CodeChallenge == nil || *a.CodeChallenge == "") {
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

func (c *Client) Validate() errors.OIDCError {
	err := utils.NewCustomValidator().Struct(c)

	if err != nil {
		log.Printf("Validation error in client: %v", err)
		switch t := err.(type) {
		case *validator.InvalidValidationError:
			description := t.Error()
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
			}
		case *validator.ValidationErrors:
			firstError := (*t)[0]
			description := fmt.Sprintf("invalid %s: %s", firstError.Field(), firstError.Value())
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
			}
		default:
			description := "invalid client"
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &description,
			}
		}
	}

	if (utils.ContainsValue(*c.GrantTypes, utils.CLIENT_CREDENTIALS) || utils.ContainsValue(*c.GrantTypes, utils.REFRESH_TOKEN)) && (c.IsConfidential == nil || !*c.IsConfidential) {
		description := "public clients cannot use client_credentials or refresh_token grant type"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	if utils.ContainsValue(*c.GrantTypes, utils.REFRESH_TOKEN) && !utils.ContainsValue(*c.GrantTypes, utils.AUTHORIZATION_CODE) && !utils.ContainsValue(*c.GrantTypes, utils.CLIENT_CREDENTIALS) {
		description := "refresh_token grant type requires authorization_code or client_credentials grant type"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	if utils.ContainsValue(*c.ResponseTypes, utils.TOKEN) && !utils.ContainsValue(*c.GrantTypes, utils.IMPLICIT) {
		description := "response_type 'token' requires 'implicit' grant type"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	if utils.ContainsValue(*c.ResponseTypes, utils.CODE_TOKEN) && !(utils.ContainsValue(*c.GrantTypes, utils.IMPLICIT) && utils.ContainsValue(*c.GrantTypes, utils.AUTHORIZATION_CODE)) {
		description := "response_type 'code token' requires 'implicit' and 'authorization_code' grant types"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	if utils.ContainsValue(*c.ResponseTypes, utils.CODE_ID_TOKEN) && !(utils.ContainsValue(*c.GrantTypes, utils.IMPLICIT) && utils.ContainsValue(*c.GrantTypes, utils.AUTHORIZATION_CODE)) {
		description := "response_type 'code id_token' requires 'implicit' and 'authorization_code' grant types"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	if utils.ContainsValue(*c.ResponseTypes, utils.CODE_ID_TOKEN_TOKEN) && !(utils.ContainsValue(*c.GrantTypes, utils.IMPLICIT) && utils.ContainsValue(*c.GrantTypes, utils.AUTHORIZATION_CODE)) {
		description := "response_type 'code id_token token' requires 'implicit' and 'authorization_code' grant types"
		log.Println(description)
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &description,
		}
	}

	return nil
}

func (m *MagicLinkToken) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(m)

	return err
}

func (m *MagicLinkWhitelist) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(m)

	return
}

func (o *OpenIDConfiguration) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(o)

	return
}

func (s *Session) Validate() (err error) {
	err = utils.NewCustomValidator().Struct(s)

	return
}

func (t *Token) Validate() (err error) {
	if err = utils.NewCustomValidator().Struct(t); err != nil {
		return err
	}

	if t.IsCustom {
		if t.Type != utils.ACCESS_TOKEN_TYPE {
			return fmt.Errorf("custom tokens must be of type access_token")
		}

		if t.UserID == nil || *t.UserID == uuid.Nil {
			return fmt.Errorf("custom token must be associated with a user")
		}

		if t.ClientID != nil || t.AuthorizationID != nil {
			return fmt.Errorf("custom token cannot be associated with a client or authorization")
		}
	} else {
		if t.UserID != nil {
			return fmt.Errorf("non-custom tokens cannot be associated with a user")
		}

		if (t.AuthorizationID == nil || *t.AuthorizationID == uuid.Nil) && t.Type != utils.CLIENT_CREDENTIALS_TYPE {
			return fmt.Errorf("non-client_credentials tokens must be associated with an authorization")
		}
	}

	if t.Type == utils.CLIENT_CREDENTIALS_TYPE {
		if t.ClientID == nil || *t.ClientID == "" {
			return fmt.Errorf("client credentials token must be associated with a client")
		}
		if t.UserID != nil || t.AuthorizationID != nil {
			return fmt.Errorf("client credentials token cannot be associated with a user or authorization")
		}
	}

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
