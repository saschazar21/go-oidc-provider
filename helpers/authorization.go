package helpers

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/uptrace/bun"
)

type authorizationRequest struct {
	r             *http.Request         `json:"-"`
	authorization *models.Authorization `json:"-"`

	params url.Values `json:"-"`
}

func (ar *authorizationRequest) AuthenticateClient(ctx context.Context, db bun.IDB) errors.OIDCError {
	if ar.authorization.ClientID == "" {
		msg := "Client ID is required for authentication."
		log.Printf("%s", msg)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
		}
	}

	var client *models.Client
	var err errors.OIDCError
	if ar.authorization.ClientSecret != nil && *ar.authorization.ClientSecret != "" {
		client, err = models.GetClientByIDAndSecret(ctx, db, ar.authorization.ClientID, *ar.authorization.ClientSecret)
	} else {
		client, err = models.GetClientByID(ctx, db, ar.authorization.ClientID)
	}

	if err != nil {
		log.Printf("Error retrieving client by ID: %v", err)
		msg := "Invalid client credentials."

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_CLIENT,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
		}
	}

	if client.IsConfidential != nil && *client.IsConfidential && (ar.authorization.ClientSecret == nil || *ar.authorization.ClientSecret == "") {
		msg := "Client secret is required for confidential clients."
		log.Printf("%s", msg)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_CLIENT,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
		}
	}

	if client.IsPKCERequired && (ar.authorization.CodeChallenge == nil || *ar.authorization.CodeChallenge == "") {
		msg := "PKCE is required for this client, but no code_challenge provided."
		log.Printf("%s", msg)

		return errors.OIDCErrorResponse{
			ErrorCode:        errors.INVALID_REQUEST,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
		}
	}

	ar.authorization.Client = client

	return nil
}

func ParseAuthorizationRequest(ctx context.Context, db bun.IDB, r *http.Request) (_ *models.Authorization, err errors.OIDCError) {
	if r == nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The request cannot be nil.",
		}
	}

	ar := authorizationRequest{
		r,
		nil,
		url.Values{},
	}

	if err = ar.Validate(); err != nil {
		log.Printf("Validation error: %v", err)
		return
	}

	if err = ar.AuthenticateClient(ctx, db); err != nil {
		log.Printf("Client authentication error: %v", err)
		return
	}

	auth := ar.authorization

	if err = auth.Save(ctx, db); err != nil {
		log.Printf("Failed to store authorization in database: %v", err)
		return
	}

	// TODO: check for user's authentication and redirect, if necessary

	return auth, nil
}
