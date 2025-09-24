package idtoken

import (
	"fmt"
	"log"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func loadSigningKey(alg ...string) (string, interface{}, error) {
	keys, err := LoadKeys()
	if err != nil {
		log.Printf("Keyring initialization failed: %v", err)
		return "", nil, fmt.Errorf("keyring initialization failed")
	}

	var algorithm string
	var key interface{}
	if len(alg) > 0 {
		for _, a := range alg {
			if k, isExisting := keys[a]; isExisting {
				algorithm = a
				key = k
				break
			}
		}
		if algorithm == "" {
			log.Printf("no key found for any of the desired algorithms, falling back to default...")
		}
	}

	if algorithm == "" {
		// default to first available key
		for a := range keys {
			algorithm = a
			key = keys[a]
			break
		}
	}
	return algorithm, key, nil
}

func getKey(token *jwt.Token) (interface{}, error) {
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid alg in token header")
	}

	if alg == "none" {
		return nil, nil
	}

	if strings.HasPrefix(alg, "HS") {
		key, err := GetKey(alg)
		if err != nil {
			log.Printf("Error retrieving key for algorithm %s: %v", alg, err)
			return nil, fmt.Errorf("error retrieving key for algorithm %s", alg)
		}
		return key, nil
	}

	key, err := GetPublicKey(alg)
	if err != nil {
		log.Printf("Error retrieving key for algorithm %s: %v", alg, err)
		return nil, fmt.Errorf("error retrieving key for algorithm %s", alg)
	}

	return key, nil
}

func NewSignedJWT(tokens *map[utils.TokenType]*models.Token, alg ...string) (string, error) {
	algorithm, key, err := loadSigningKey(alg...)
	if err != nil {
		return "", err
	}

	if algorithm == "" || key == nil {
		log.Printf("no signing key available")
		return "", fmt.Errorf("no signing key available")
	}

	claims, err := NewClaims(tokens)
	if err != nil {
		log.Printf("Failed to create claims for ID token: %v", err)
		return "", fmt.Errorf("failed to create claims for ID token")
	}

	signingMethod := jwt.GetSigningMethod(algorithm)
	if signingMethod == nil {
		log.Printf("Unsupported signing algorithm: %s", algorithm)
		return "", fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		log.Printf("Failed to sign JWT: %v", err)
		return "", fmt.Errorf("failed to sign JWT")
	}

	return signedToken, nil
}

func ParseJWT(tokenString string) (*Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, getKey)
	if err != nil {
		log.Printf("Failed to parse JWT: %v", err)
		return nil, fmt.Errorf("failed to parse JWT")
	}

	if !token.Valid {
		log.Printf("Invalid JWT token")
		return nil, fmt.Errorf("invalid JWT token")
	}

	return &claims, nil
}
