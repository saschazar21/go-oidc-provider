package helpers

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type authorizationRequest struct {
	r             *http.Request         `json:"-"`
	w             http.ResponseWriter   `json:"-"`
	authorization *models.Authorization `json:"-"`

	params url.Values `json:"-"`
}

func (ar *authorizationRequest) getCorrectRedirectStatusCode() int {
	switch ar.r.Method {
	case http.MethodGet:
		return http.StatusFound
	case http.MethodPost:
		return http.StatusSeeOther
	default:
		return http.StatusTemporaryRedirect
	}
}

func (ar *authorizationRequest) parseSession(ctx context.Context, db bun.IDB) errors.OIDCError {
	session, err := ParseSession(ctx, db, ar.w, ar.r)
	if err != nil {
		log.Printf("Error parsing session: %v", err)
		return err
	}

	ar.authorization.User = session.User // do not set UserID yet, will be set in HandleAuthorizationRequest

	return nil
}

func (ar *authorizationRequest) willScopeChange(grantedScopes []utils.Scope) bool {
	requestedScopes := ar.authorization.Scope
	if len(requestedScopes) == 0 {
		return false // No scopes requested, so nothing to check
	}

	// look for any requested scope that is not in the granted scopes
	for _, reqScope := range requestedScopes {
		found := false
		for _, grantedScope := range grantedScopes {
			if reqScope == grantedScope {
				found = true
				break
			}
		}
		if !found {
			return true // Found a requested scope that is not granted
		}
	}

	return false // All requested scopes are in the granted scopes
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

func (ar *authorizationRequest) HandleAuthorizationRequest(ctx context.Context, db bun.IDB) errors.OIDCError {
	if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.LOGIN {
		log.Printf("Prompt is set to 'login', redirecting to login page")
		return errors.InternalRedirectError{
			StatusCode: ar.getCorrectRedirectStatusCode(),
			Location:   LOGIN_ENDPOINT,
		}
	}

	err := ar.parseSession(ctx, db)

	if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.NONE && (err != nil || ar.authorization.User == nil) {
		log.Printf("Prompt is set to 'none' but no valid session found, cannot authenticate user")
		msg := "Prompt is set to 'none', but user is not logged in."
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.LOGIN_REQUIRED,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
		}
	}

	if err != nil {
		return err
	}

	auth := ar.authorization

	existingAuth, err := models.GetAuthorizationByClientAndUser(ctx, db, auth.ClientID, auth.User.ID)
	if err != nil {
		log.Printf("Error checking existing authorization: %v", err)
		return nil
	}

	log.Printf("Existing authorization found for client %s and user %s", auth.ClientID, auth.User.ID)

	ar.authorization.ReplacedID = existingAuth.ID
	ar.authorization.ReplacedAuthorization = existingAuth

	if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.CONSENT {
		log.Printf("Prompt is set to 'consent', re-authorization required for client %s and user %s", ar.authorization.ClientID, ar.authorization.User.ID)
		return nil
	}

	if ar.willScopeChange(existingAuth.Scope) {
		if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.NONE {
			log.Printf("Prompt is set to 'none', but scope has changed for client %s and user %s", ar.authorization.ClientID, ar.authorization.User.ID)
			msg := "Prompt is set to 'none', but requested scope differs from previously granted scope."
			return errors.OIDCErrorResponse{
				ErrorCode:        errors.CONSENT_REQUIRED,
				ErrorDescription: &msg,
				RedirectURI:      ar.authorization.RedirectURI,
			}
		}

		log.Printf("Requested scopes %v differ from previously granted scopes %v", auth.Scope, existingAuth.Scope)
		// Scope has changed, require re-authorization
		return nil
	}

	status := utils.APPROVED

	ar.authorization.UserID = ar.authorization.User.ID
	ar.authorization.Status = &status
	ar.authorization.IsActive = true

	log.Printf("No re-authorization needed for client %s and user %s", auth.ClientID, auth.User.ID)

	return nil
}

func (ar *authorizationRequest) GetAuthorization() *models.Authorization {
	return ar.authorization
}

func (ar *authorizationRequest) GetParams() url.Values {
	return ar.params
}

func parseAuthorizationFromCookie(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (*models.Authorization, errors.OIDCError) {
	cookie, _ := utils.NewCookieStore().Get(r, AUTHORIZATION_COOKIE_NAME)

	id, ok := cookie.Values[AUTHORIZATION_COOKIE_ID].(string)
	if !ok || id == "" {
		msg := "No authorization data found in cookie."
		log.Printf("%s", msg)

		cookie.Options.MaxAge = -1 // Delete cookie
		if err := cookie.Save(r, w); err != nil {
			log.Printf("Error deleting invalid authorization cookie: %v", err)
		}

		if r.Method == http.MethodGet {
			return nil, errors.HTTPErrorResponse{
				StatusCode:  http.StatusBadRequest,
				Message:     errors.BAD_REQUEST,
				Description: msg,
			}
		}
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	auth, err := models.GetAuthorizationByID(ctx, db, id)
	if err != nil {
		log.Printf("Error retrieving authorization by ID from cookie: %v", err)

		cookie.Options.MaxAge = -1 // Delete cookie
		if err := cookie.Save(r, w); err != nil {
			log.Printf("Error deleting invalid authorization cookie: %v", err)
		}

		msg := "Failed to retrieve authorization data from cookie."
		if r.Method == http.MethodGet {
			return nil, errors.HTTPErrorResponse{
				StatusCode:  http.StatusBadRequest,
				Message:     errors.BAD_REQUEST,
				Description: msg,
			}
		}
		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	return auth, nil
}

func parseAuthorizationRequest(w http.ResponseWriter, r *http.Request) (*authorizationRequest, errors.OIDCError) {
	if r == nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The request cannot be nil.",
		}
	}

	var params url.Values

	switch r.Method {
	case http.MethodGet:
		params = r.URL.Query()
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			msg := "Invalid content type. Only application/x-www-form-urlencoded is allowed."
			return nil, errors.JSONError{
				StatusCode:  http.StatusUnsupportedMediaType,
				ErrorCode:   errors.INVALID_REQUEST,
				Description: &msg,
			}
		}
		if err := r.ParseForm(); err != nil {
			msg := "Failed to parse form data."
			log.Printf("%s: %v", msg, err)
			return nil, errors.JSONError{
				StatusCode:  http.StatusBadRequest,
				ErrorCode:   errors.INVALID_REQUEST,
				Description: &msg,
			}
		}
		params = r.PostForm
	default:
		msg := "Unsupported request method. Only GET and POST are allowed."
		return nil, errors.JSONError{
			StatusCode:  http.StatusMethodNotAllowed,
			ErrorCode:   errors.METHOD_NOT_ALLOWED,
			Description: &msg,
			Headers: map[string]string{
				"Allow": "GET, POST",
			},
		}
	}

	if len(params) == 0 {
		log.Printf("No parameters found in the request")
		return &authorizationRequest{
			r:             r,
			w:             w,
			authorization: nil,
			params:        params,
		}, nil
	}

	decoder := utils.NewCustomDecoder()

	var auth models.Authorization
	if err := decoder.Decode(&auth, params); err != nil {
		redirectUri := params.Get("redirect_uri")

		msg := "Failed to decode authorization request parameters"
		log.Printf("%s: %v", msg, err)

		if _, err := url.ParseRequestURI(redirectUri); err != nil {
			return nil, errors.OIDCErrorResponse{
				ErrorCode:        errors.INVALID_REQUEST,
				ErrorDescription: &msg,
				RedirectURI:      redirectUri,
			}
		}

		if r.Method == http.MethodGet {
			return nil, errors.HTTPErrorResponse{
				StatusCode:  http.StatusBadRequest,
				Message:     errors.BAD_REQUEST,
				Description: msg,
			}
		}

		return nil, errors.JSONError{
			StatusCode:  http.StatusBadRequest,
			ErrorCode:   errors.INVALID_REQUEST,
			Description: &msg,
		}
	}

	ar := authorizationRequest{
		r:             r,
		w:             w,
		authorization: &auth,
		params:        params,
	}

	return &ar, nil
}

func HandleAuthorizationRequest(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (_ utils.Writable, _ *models.Authorization, err errors.OIDCError) {
	ar, err := ParseAuthorizationRequest(ctx, db, w, r)
	if err != nil {
		return
	}

	err = ar.HandleAuthorizationRequest(ctx, db)

	auth := ar.authorization

	if auth.Prompt != nil && *auth.Prompt == utils.NONE && auth.ReplacedID == uuid.Nil {
		if err != nil {
			if oidcErr, ok := err.(errors.OIDCErrorResponse); ok {
				return nil, nil, oidcErr
			}
		}
		description := "Prompt is set to 'none', but user has not previously authorized this client."
		log.Println(description)
		return nil, nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.INTERACTION_REQUIRED,
			ErrorDescription: &description,
			RedirectURI:      auth.RedirectURI,
		}
	}

	// Store the (intermediate) authorization in the database
	if err := auth.Save(ctx, db); err != nil {
		log.Printf("Failed to store authorization in database: %v", err)
		return nil, nil, err
	}

	if auth.IsApproved() { // create authorization response if authorization can be completed without user interaction
		log.Printf("Authorization approved for client %s and user %s", auth.ClientID, auth.UserID)

		arResponse, oidcErr := NewAuthorizationResponse(ctx, db, auth)
		if oidcErr != nil {
			log.Printf("Failed to create authorization response: %v", oidcErr)
			return nil, nil, oidcErr
		}

		return arResponse, nil, nil
	}

	cookieStore, _ := utils.NewCookieStore().Get(r, AUTHORIZATION_COOKIE_NAME)
	cookieStore.Values[AUTHORIZATION_COOKIE_ID] = auth.ID.String()
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.MaxAge = int(auth.ExpiresAt.ExpiresAt.Sub(time.Now().UTC()).Seconds())
	cookieStore.Options.Path = "/"
	cookieStore.Options.SameSite = http.SameSiteLaxMode
	cookieStore.Options.Secure = true

	if err := cookieStore.Save(r, w); err != nil {
		log.Printf("Error saving authorization cookie: %v", err)
		msg := "Failed to save authorization session."
		return nil, nil, errors.OIDCErrorResponse{
			ErrorCode:        errors.SERVER_ERROR,
			ErrorDescription: &msg,
			StatusCode:       http.StatusInternalServerError,
			RedirectURI:      auth.RedirectURI,
		}
	}

	if err != nil { // error means redirect to /login
		log.Printf("No valid session found or prompt=\"login\" detected: %v", err)
		return err, nil, nil
	}

	// nil means user interaction is required, therefore render authorization decision form
	return nil, auth, nil
}

func ParseAuthorizationRequest(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (_ *authorizationRequest, err errors.OIDCError) {
	if r == nil {
		return nil, errors.HTTPErrorResponse{
			StatusCode:  http.StatusBadRequest,
			Message:     errors.BAD_REQUEST,
			Description: "The request cannot be nil.",
		}
	}

	var ar *authorizationRequest
	ar, err = parseAuthorizationRequest(w, r)
	if err != nil {
		return
	}

	if ar.authorization != nil {
		if err = ar.Validate(); err != nil {
			log.Printf("Validation error: %v", err)
			return
		}

		if err = ar.AuthenticateClient(ctx, db); err != nil {
			log.Printf("Client authentication error: %v", err)
			return
		}
	} else {
		log.Printf("Fallback to authorization cookie.")
		auth, err := parseAuthorizationFromCookie(ctx, db, w, r)
		if err != nil {
			return nil, err
		}

		ar.authorization = auth
	}

	return ar, nil
}
