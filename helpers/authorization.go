package helpers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/errors"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type authorizationRequest struct {
	r             *http.Request         `json:"-"`
	w             http.ResponseWriter   `json:"-"`
	authorization *models.Authorization `json:"-"`

	params              url.Values `json:"-"`
	reauthenticateAfter *time.Time
}

const authorizationReauthenticateAfter = "reauthenticate_after"

// Read without Session.AfterSelect: its pooled UPDATE can otherwise take a
// session lock before the user lock, or deadlock against our own transaction.
// Both reads are side-effect free; only the second supplies trusted evidence.
func lockedIssuanceSession(ctx context.Context, db bun.IDB, id string) (*models.Session, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	load := func(locked bool) (*models.Session, error) {
		var session models.Session
		query := db.NewSelect().Model(&session).Relation("User").Relation("Client").
			Where(`"session"."session_id" = ?`, uid).
			Where(`"session"."is_active" = TRUE`).
			Where(`"session"."expires_at" > clock_timestamp()`).
			Where(`"user"."is_active" = TRUE`).Where(`"user"."is_locked" = FALSE`)
		if locked {
			query = query.For(`UPDATE OF "session"`)
		}
		err := db.NewRaw(query.String()).Scan(ctx, &session)
		return &session, err
	}
	session, err := load(false)
	if err != nil {
		return nil, err
	}
	userID := session.UserID
	if err := lockIssuanceUser(ctx, db, userID); err != nil {
		return nil, err
	}
	session, err = load(true)
	if err != nil {
		return nil, err
	}
	if session.UserID != userID || session.User == nil {
		return nil, sql.ErrNoRows
	}
	// Preserve sliding-session usage tracking, but on this transaction rather
	// than the pool used by the model hook.
	now := time.Now().UTC()
	_, err = db.NewUpdate().Model((*models.Session)(nil)).
		Set("last_accessed_at = ?", now).Set("expires_at = ?", now.Add(24*time.Hour)).
		Where("session_id = ?", session.ID).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// The signed continuation cookie binds freshness to this authorization, rather
// than replaying prompt=login/max_age=0 forever after successful authentication.
func authorizationReauthenticationTime(r *http.Request, id uuid.UUID) *time.Time {
	cookie, err := parseCookieFromRequest(r, AUTHORIZATION_COOKIE_NAME)
	if err != nil || cookie.Values[AUTHORIZATION_COOKIE_ID] != id.String() {
		return nil
	}
	if micros, ok := cookie.Values[authorizationReauthenticateAfter].(int64); ok {
		at := time.UnixMicro(micros).UTC()
		return &at
	}
	return nil
}

func (ar *authorizationRequest) requireLogin(ctx context.Context) errors.OIDCError {
	if _, configured := ctx.Value(authenticationPolicyKey{}).(authenticationPolicy); configured && ar.reauthenticateAfter == nil {
		now := time.Now().UTC().Truncate(time.Microsecond)
		ar.reauthenticateAfter = &now
	}
	return errors.InternalRedirectError{StatusCode: ar.getCorrectRedirectStatusCode(), Location: LOGIN_ENDPOINT}
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
	ctx = authenticationPolicyContext(ctx, ar.r)
	id, cookieErr := getSessionIdFromCookie(ar.w, ar.r)
	if cookieErr != nil {
		return cookieErr
	}
	session, err := lockedIssuanceSession(ctx, db, id)
	if err != nil {
		log.Printf("Error parsing session: %v", err)
		deleteCookie(ar.w, SESSION_COOKIE_NAME)
		return ar.requireLogin(ctx)
	}
	if session.User == nil || !AuthenticationMethodsSatisfied(ctx, session.AMR) ||
		(ar.reauthenticateAfter != nil && !session.AuthTime.After(*ar.reauthenticateAfter)) {
		return ar.requireLogin(ctx)
	}

	ar.authorization.User = session.User // do not set UserID yet, will be set in HandleAuthorizationRequest
	authTime := session.AuthTime
	ar.authorization.AuthTime = &authTime
	ar.authorization.AMR = copyAuthenticationMethods(session.AMR)

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

	publicClient := client.IsConfidential == nil || !*client.IsConfidential
	pkceRequired := publicClient || (client.IsPKCERequired != nil && *client.IsPKCERequired)
	if pkceRequired && (ar.authorization.CodeChallenge == nil || *ar.authorization.CodeChallenge == "") {
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
	ctx = authenticationPolicyContext(ctx, ar.r)
	// Cookie-backed authorizations may already be approved. Never retain their
	// identity or approval when current-session validation requires a login.
	ar.authorization.User = nil
	ar.authorization.UserID = uuid.Nil
	ar.authorization.AuthTime = nil
	ar.authorization.AMR = nil
	ar.authorization.IsActive = false
	ar.authorization.Status = nil
	if (ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.LOGIN) ||
		(ar.authorization.MaxAge != nil && *ar.authorization.MaxAge == 0) {
		log.Printf("Prompt is set to 'login', redirecting to login page")
		return ar.requireLogin(ctx)
	}

	err := ar.parseSession(ctx, db)

	if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.NONE && (err != nil || ar.authorization.User == nil) {
		log.Printf("Prompt is set to 'none' but no valid session found, cannot authenticate user")
		msg := "Prompt is set to 'none', but user is not logged in."
		return errors.OIDCErrorResponse{
			ErrorCode:        errors.LOGIN_REQUIRED,
			ErrorDescription: &msg,
			RedirectURI:      ar.authorization.RedirectURI,
			State:            ar.authorization.State,
			IsFragment:       ar.authorization.ResponseType != utils.CODE,
		}
	}

	if err != nil {
		return err
	}
	if ar.authorization.MaxAge != nil {
		if ar.authorization.AuthTime == nil || time.Since(*ar.authorization.AuthTime).Seconds() > float64(*ar.authorization.MaxAge) {
			if ar.authorization.Prompt != nil && *ar.authorization.Prompt == utils.NONE {
				msg := "Prompt is set to 'none', but the authentication is too old."
				return errors.OIDCErrorResponse{ErrorCode: errors.LOGIN_REQUIRED, ErrorDescription: &msg, RedirectURI: ar.authorization.RedirectURI, State: ar.authorization.State, IsFragment: ar.authorization.ResponseType != utils.CODE}
			}
			return ar.requireLogin(ctx)
		}
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
	type result struct {
		response utils.Writable
		auth     *models.Authorization
	}
	value, oidcErr := runOIDCIssuance(ctx, db, func(ctx context.Context, tx bun.IDB) (result, errors.OIDCError) {
		response, auth, err := handleAuthorizationRequest(ctx, tx, w, r)
		return result{response, auth}, err
	})
	return value.response, value.auth, oidcErr
}

func handleAuthorizationRequest(ctx context.Context, db bun.IDB, w http.ResponseWriter, r *http.Request) (_ utils.Writable, _ *models.Authorization, err errors.OIDCError) {
	if r != nil {
		ctx = authenticationPolicyContext(ctx, r)
	}
	ar, err := ParseAuthorizationRequest(ctx, db, w, r)
	if err != nil {
		return
	}

	err = ar.HandleAuthorizationRequest(ctx, db)
	if err != nil {
		if _, redirect := err.(errors.InternalRedirectError); !redirect {
			return nil, nil, err
		}
	}

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

	auth.ReplacedAuthorization = nil // clear replaced authorization to avoid deep validation errors (e.g. expires_at, etc...)

	// Store the (intermediate) authorization in the database
	if err := auth.Save(ctx, db); err != nil {
		log.Printf("Failed to store authorization in database: %v", err)
		return nil, nil, err
	}

	if err == nil && auth.IsApproved() { // only validated current sessions may reuse approval
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
	delete(cookieStore.Values, authorizationReauthenticateAfter)
	if ar.reauthenticateAfter != nil {
		cookieStore.Values[authorizationReauthenticateAfter] = ar.reauthenticateAfter.UnixMicro()
	}
	cookieStore.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   int(auth.ExpiresAt.ExpiresAt.Sub(time.Now().UTC()).Seconds()),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}

	if auth.State != nil && *auth.State != "" {
		cookieStore.Values[AUTHORIZATION_COOKIE_STATE] = *auth.State
	}

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
	if ar.params.Has("request") {
		msg := "Request Objects are not supported."
		return nil, errors.OIDCErrorResponse{ErrorCode: errors.REQUEST_NOT_SUPPORTED, ErrorDescription: &msg, RedirectURI: ar.params.Get("redirect_uri")}
	}
	if ar.params.Has("request_uri") {
		msg := "Request URI processing is not supported."
		return nil, errors.OIDCErrorResponse{ErrorCode: errors.REQUEST_URI_NOT_SUPPORTED, ErrorDescription: &msg, RedirectURI: ar.params.Get("redirect_uri")}
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
		ar.reauthenticateAfter = authorizationReauthenticationTime(r, auth.ID)
	}

	return ar, nil
}
