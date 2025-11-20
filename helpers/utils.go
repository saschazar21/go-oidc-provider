package helpers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/idtoken"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func loadUserFixture(t *testing.T) *models.User {
	var user models.User
	if err := test.LoadFixture("user.json", &user); err != nil {
		t.Fatalf("Failed to create user from file: %v", err)
	}

	return &user
}

func loadClientFixture(t *testing.T) *models.Client {
	var client models.Client
	if err := test.LoadFixture("client.json", &client); err != nil {
		t.Fatalf("Failed to create client from file: %v", err)
	}

	return &client
}

func loadAuthFixture(t *testing.T) *models.Authorization {
	var auth models.Authorization
	if err := test.LoadFixture("authorization_approved.json", &auth); err != nil {
		t.Fatalf("Failed to create authorization from file: %v", err)
	}

	return &auth
}

func parseBearerTokenFromRequest(r *http.Request) (token string, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		msg := "No valid bearer token provided in Authorization header"
		log.Printf("%s", msg)
		return "", fmt.Errorf("%s", msg)
	}

	bearer := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return bearer, nil
}

func parseCookieFromRequest(r *http.Request, cookieName string) (cookie *sessions.Session, err error) {
	cookieStore := utils.NewCookieStore()

	cookie, err = cookieStore.Get(r, cookieName)
	if err != nil {
		log.Printf("Error parsing %s cookie: %v", cookieName, err)
		err = fmt.Errorf("error parsing %s cookie", cookieName)
	}

	return cookie, err
}

func validateBearerToken(ctx context.Context, db bun.IDB, r *http.Request) (token *models.Token, err error) {
	bearer, err := parseBearerTokenFromRequest(r)
	if err != nil {
		return nil, err
	}

	var claims *idtoken.Claims
	if claims, err = idtoken.ParseJWT(bearer); err == nil && claims != nil {
		log.Printf("Bearer token is a valid JWT.")
		isActive := true
		scope := []utils.Scope(claims.Scope)
		return &models.Token{
			IsActive:  &isActive,
			Scope:     &scope,
			Type:      utils.ACCESS_TOKEN_TYPE,
			Value:     utils.HashedString(bearer),
			ClientID:  &claims.Audience[0],
			UserID:    &claims.User.ID,
			CreatedAt: models.CreatedAt{CreatedAt: time.Time(claims.IssuedAt)},
			ExpiresAt: models.ExpiresAt{ExpiresAt: time.Time(claims.ExpiresAt)},
		}, nil
	}

	if token, err = models.GetTokenByValue(ctx, db, bearer); err != nil || token == nil {
		msg := "Invalid bearer token"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}

	return token, nil
}

func validateClientCredentials(ctx context.Context, db bun.IDB, r *http.Request) (client *models.Client, err error) {
	var clientId, clientSecret string
	var ok bool

	if clientId, clientSecret, ok = r.BasicAuth(); !ok {
		msg := "No valid client credentials provided in Authorization header"
		log.Printf("%s", msg)
		return nil, fmt.Errorf("%s", msg)
	}

	if client, err = models.GetClientByIDAndSecret(ctx, db, clientId, clientSecret); err != nil || client == nil {
		msg := "Invalid client credentials"
		log.Printf("%s for client ID %s: %v", msg, clientId, err)
		return nil, fmt.Errorf("%s", msg)
	}

	return client, nil
}
