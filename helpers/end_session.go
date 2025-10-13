package helpers

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type endSessionRequest struct {
	IDTokenHint           string  `json:"-" schema:"id_token_hint"`
	PostLogoutRedirectURI string  `json:"-" schema:"post_logout_redirect_uri" validate:"omitempty,url"`
	State                 *string `json:"-" schema:"state"`

	r *http.Request `json:"-"`
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

	claims, err := idtoken.ParseJWT(ers.IDTokenHint) // allow invalid token to support logout with expired id_token_hint
	if claims == nil {
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

	if err := utils.NewCustomDecoder().Decode(&req, r.URL.Query()); err != nil {
		log.Printf("Failed to decode end session request parameters: %v", err)
		return nil, fmt.Errorf("failed to decode end session request parameters")
	}

	if err := req.Validate(); err != nil {
		log.Printf("End session request validation failed: %v", err)
		return nil, fmt.Errorf("end session request validation failed")
	}

	return &req, nil
}
