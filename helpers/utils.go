package helpers

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/test"
	"github.com/saschazar21/go-oidc-provider/utils"
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

func parseCookieFromRequest(r *http.Request, cookieName string) (cookie *sessions.Session, err error) {
	cookieStore := utils.NewCookieStore()

	cookie, err = cookieStore.Get(r, cookieName)
	if err != nil {
		log.Printf("Error parsing %s cookie: %v", cookieName, err)
		err = fmt.Errorf("error parsing %s cookie", cookieName)
	}

	return cookie, err
}
