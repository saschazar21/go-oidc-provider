package utils

import (
	"encoding/base64"
	"log"
	"os"

	"github.com/gorilla/sessions"
)

var _cookieStore *sessions.CookieStore

func NewCookieStore() *sessions.CookieStore {
	if _cookieStore != nil {
		return _cookieStore
	}

	authKey := os.Getenv(COOKIE_AUTH_KEY_ENV)
	if authKey == "" {
		log.Fatal("COOKIE_AUTH_KEY env must be set!")
	}

	var err error

	var authKeyBytes []byte
	authKeyBytes, err = base64.StdEncoding.DecodeString(authKey)

	if err != nil {
		log.Fatalf("COOKIE_AUTH_KEY env failed to decode, make sure it's a valid base64-encoding: %v", err)
	}

	if len(authKeyBytes) != 32 && len(authKeyBytes) != 64 {
		log.Fatalf("COOKIE_AUTH_KEY env must be set and either 32 or 64 bytes long!")
	}

	var encKeyBytes []byte = nil

	encKey := os.Getenv(COOKIE_ENC_KEY_ENV)
	if encKey != "" {
		encKeyBytes, err = base64.StdEncoding.DecodeString(encKey)

		if err != nil {
			log.Printf("COOKIE_ENC_KEY env failed to decode, make sure it's a valid base64-encoding: %v", err)
			encKeyBytes = nil
		}

		if len(encKeyBytes) > 0 && len(encKeyBytes) != 16 && len(encKeyBytes) != 24 && len(encKeyBytes) != 32 {
			log.Printf("COOKIE_ENC_KEY env must be set and either 16, 24, or 32 bytes long! Omitting encryption.")
			encKeyBytes = nil
		}
	}

	_cookieStore = sessions.NewCookieStore(authKeyBytes, encKeyBytes)

	return _cookieStore
}
