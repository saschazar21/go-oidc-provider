package oidc

import (
	"crypto/rand"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/schema"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func getIssuerURL() *url.URL {
	u := os.Getenv(ISSUER_ENV)
	if u == "" {
		log.Println("ISSUER_URL environment variable is not set, falling back to the deployment URL")
		u = utils.GetDeploymentURL()
		if u == "" {
			log.Println("deployment URL is also not set")
			return nil
		}
	}
	issuerURL, err := url.Parse(u)
	if err != nil {
		log.Println("failed to parse issuer URL from environment variable")
		return nil
	}
	return issuerURL
}

func GetCallbackURL() string {
	issuerURL := getIssuerURL()
	if issuerURL == nil {
		log.Printf("issuer URL returned nil")
		return ""
	}
	issuerURL.Path = URL_PATH_CALLBACK
	return issuerURL.String()
}

func RandomString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("failed to generate random string: %v", err)
		return ""
	}
	for i := 0; i < n; i++ {
		b[i] = RANDOM_ALPHABET[int(b[i])%len(RANDOM_ALPHABET)]
	}

	return string(b)
}

func ParseCallbackRequest(r *http.Request, dest interface{}) error {
	q := r.URL.Query()
	decoder := schema.NewDecoder()
	err := decoder.Decode(dest, q)
	if err != nil {
		return err
	}
	return nil
}

func StoreStateCookie(w http.ResponseWriter, state string) {
	cookie := &http.Cookie{
		Name:     COOKIE_STATE_NAME,
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		Path:     URL_PATH_CALLBACK,
		MaxAge:   3600,
	}
	http.SetCookie(w, cookie)
}

func DeleteStateCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     COOKIE_STATE_NAME,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Path:     URL_PATH_CALLBACK,
		MaxAge:   0,
	}
	http.SetCookie(w, cookie)
}
