package helpers

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type endSessionRequest struct {
	IDTokenHint           string  `json:"-" schema:"id_token_hint"`
	ClientID              string  `json:"-" schema:"client_id"`
	PostLogoutRedirectURI string  `json:"-" schema:"post_logout_redirect_uri" validate:"omitempty,url"`
	State                 *string `json:"-" schema:"state"`
	CSRF                  string  `json:"-" schema:"csrf"`
	Confirm               string  `json:"-" schema:"confirm"`

	r *http.Request `json:"-"`
}

func (ers *endSessionRequest) validateIDTokenHint() (*idtoken.Claims, error) {
	if ers.IDTokenHint == "" {
		return nil, nil
	}
	claims, err := idtoken.ParseJWT(ers.IDTokenHint)
	if claims == nil {
		return nil, fmt.Errorf("failed to parse ID token hint: %w", err)
	}
	if err != nil && err.Error() != "token has expired" {
		return nil, fmt.Errorf("invalid ID token hint: %w", err)
	}
	issuer := os.Getenv(utils.ISSUER_URL_ENV)
	if issuer == "" {
		issuer = utils.GetDeploymentURL()
	}
	if issuer == "" || claims.Issuer != issuer {
		return nil, fmt.Errorf("ID token hint was not issued by this provider")
	}
	return claims, nil
}

func (ers *endSessionRequest) ValidatePostLogoutRedirect(ctx context.Context, db bun.IDB) error {
	claims, err := ers.validateIDTokenHint()
	if err != nil {
		return err
	}
	if ers.PostLogoutRedirectURI == "" {
		if claims != nil && ers.ClientID != "" && !containsAudience([]string(claims.Audience), ers.ClientID) {
			return fmt.Errorf("client_id does not match the ID token hint audience")
		}
		return nil
	}
	clientID := ers.ClientID
	if claims != nil {
		if clientID == "" {
			if len(claims.Audience) != 1 {
				return fmt.Errorf("client_id is required when ID token hint has multiple audiences")
			}
			clientID = claims.Audience[0]
		} else if !containsAudience([]string(claims.Audience), clientID) {
			return fmt.Errorf("client_id does not match the ID token hint audience")
		}
	}
	if clientID == "" {
		return fmt.Errorf("client_id or a single-audience ID token hint is required for post-logout redirection")
	}

	client, clientErr := models.GetClientByID(ctx, db, clientID)
	if clientErr != nil {
		return fmt.Errorf("failed to retrieve client for post-logout redirection")
	}
	for _, registeredURI := range client.PostLogoutRedirectURIs {
		if ers.PostLogoutRedirectURI == registeredURI {
			return nil
		}
	}
	return fmt.Errorf("post_logout_redirect_uri is not registered for this client")
}

func containsAudience(audiences []string, clientID string) bool {
	for _, audience := range audiences {
		if audience == clientID {
			return true
		}
	}
	return false
}

func (ers *endSessionRequest) logoutSessionByCookie(ctx context.Context, db bun.IDB) error {
	cookieStore := utils.NewCookieStore()

	session, _ := cookieStore.Get(ers.r, SESSION_COOKIE_NAME)
	id := session.Values[SESSION_COOKIE_ID]

	if id == nil {
		return nil
	}

	sessionId, ok := id.(string)
	if !ok {
		return nil
	}

	if err := models.LogoutSession(ctx, db, sessionId, LOGOUT_REASON_END_SESSION); err != nil {
		log.Printf("Failed to logout session by cookie: %v", err)
		return fmt.Errorf("failed to logout session by cookie")
	}

	return nil
}

func (ers *endSessionRequest) logoutSessionsByIDTokenHint(ctx context.Context, db bun.IDB) error {
	if ers.IDTokenHint == "" {
		return nil
	}

	claims, err := ers.validateIDTokenHint() // expired hints are accepted only when their signature and issuer are valid
	if claims == nil || err != nil {
		log.Printf("Failed to parse ID token hint: %v", err)
		return fmt.Errorf("failed to parse ID token hint")
	}

	if claims.User == nil || claims.User.ID == uuid.Nil {
		return fmt.Errorf("id token hint does not contain user information")
	}

	if err := models.LogoutSessionsByUserID(ctx, db, claims.User.ID.String(), LOGOUT_REASON_ID_TOKEN_HINT); err != nil {
		log.Printf("Failed to logout sessions by user ID: %v", err)
		return fmt.Errorf("failed to logout sessions by user ID")
	}

	return nil
}

func (ers *endSessionRequest) LogoutSessions(ctx context.Context, db bun.IDB, w http.ResponseWriter) (err error) {
	if err = ers.logoutSessionByCookie(ctx, db); err != nil {
		log.Printf("Failed to logout session by cookie: %v", err)
	}

	if err = ers.logoutSessionsByIDTokenHint(ctx, db); err != nil {
		log.Printf("Failed to logout sessions by ID token hint: %v", err)
	}

	return err
}

func ParseEndSessionRequest(r *http.Request) (*endSessionRequest, error) {
	req := endSessionRequest{r: r}
	params := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("failed to parse end session form")
		}
		params = r.PostForm
	}
	if err := utils.NewCustomDecoder().Decode(&req, params); err != nil {
		log.Printf("Failed to decode end session request parameters: %v", err)
		return nil, fmt.Errorf("failed to decode end session request parameters")
	}

	if err := req.Validate(); err != nil {
		log.Printf("End session request validation failed: %v", err)
		return nil, fmt.Errorf("end session request validation failed")
	}

	return &req, nil
}

func ValidateLogoutConfirmation(r *http.Request, csrf string) bool {
	session, err := utils.NewCookieStore().Get(r, LOGOUT_COOKIE_NAME)
	if err != nil || session == nil {
		return false
	}
	savedCSRF, ok := session.Values[LOGOUT_COOKIE_CSRF].(string)
	return ok && len(savedCSRF) == len(csrf) && subtle.ConstantTimeCompare([]byte(savedCSRF), []byte(csrf)) == 1
}

func SaveLogoutConfirmation(w http.ResponseWriter, r *http.Request) (string, error) {
	session, err := utils.NewCookieStore().Get(r, LOGOUT_COOKIE_NAME)
	if err != nil {
		return "", err
	}
	csrf := uuid.NewString()
	session.Values[LOGOUT_COOKIE_CSRF] = csrf
	session.Options = &sessions.Options{Path: LOGOUT_ENDPOINT, MaxAge: 300, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
	if err := session.Save(r, w); err != nil {
		return "", err
	}
	return csrf, nil
}
