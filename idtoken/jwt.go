package idtoken

import (
	"fmt"
	"log"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type idToken struct {
	alg string
	key interface{}

	*models.Authorization
}

func (i *idToken) loadSigningKey(client *models.Client) error {
	keys, err := LoadKeys()
	if err != nil {
		log.Printf("Keyring initialization failed: %v", err)
		return fmt.Errorf("keyring initialization failed")
	}

	var algorithm string
	var key interface{}
	if client != nil && client.IDTokenSignedResponseAlg != nil {
		algorithm = string(*client.IDTokenSignedResponseAlg)
		if k, ok := keys[algorithm]; ok {
			key = k
		} else if algorithm == "none" {
			log.Printf("client requested \"none\", so no signing key will be used...")
		} else {
			log.Printf("no key found for any of the desired algorithms, falling back to default...")

			algorithm = ""
			key = nil
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

	i.alg = algorithm
	i.key = key

	return nil
}

func (i *idToken) encode(claims *Claims) (string, error) {
	if err := i.loadSigningKey(i.Authorization.Client); err != nil {
		return "", err
	}

	if i.alg == "" || (i.alg != "none" && i.key == nil) {
		log.Printf("no signing key available")
		return "", fmt.Errorf("no signing key available")
	}

	signingMethod := jwt.GetSigningMethod(i.alg)
	if signingMethod == nil {
		log.Printf("Unsupported signing algorithm: %s", i.alg)
		return "", fmt.Errorf("unsupported signing algorithm: %s", i.alg)
	}

	jwt := jwt.NewWithClaims(signingMethod, claims)

	if i.alg == "none" {
		singingString, err := jwt.SigningString()
		if err != nil {
			log.Printf("Failed to create unsigned JWT: %v", err)
			return "", fmt.Errorf("failed to create unsigned JWT")
		}
		return fmt.Sprintf("%s.", singingString), nil
	}

	if !strings.HasPrefix(i.alg, "HS") {
		jwk, err := PublicKeyToJWK(i.key, i.alg)
		if err != nil {
			log.Printf("Failed to convert public key to JWK: %v", err)
			return "", fmt.Errorf("failed to convert public key to JWK")
		}
		jwt.Header["kid"] = jwk.Kid
	}

	signedToken, err := jwt.SignedString(i.key)
	if err != nil {
		log.Printf("Failed to sign JWT: %v", err)
		return "", fmt.Errorf("failed to sign JWT")
	}

	return signedToken, nil
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

func NewSignedJWTFromAuthorization(auth *models.Authorization) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("no authorization data provided")
	}

	claims, err := NewClaimsFromAuthorization(auth)
	if err != nil {
		log.Printf("Failed to create claims for ID token: %v", err)
		return "", fmt.Errorf("failed to create claims for ID token")
	}

	token := &idToken{
		Authorization: auth,
	}

	return token.encode(claims)
}

func NewSignedJWTFromTokens(tokens *map[utils.TokenType]*models.Token) (string, error) {
	if tokens == nil || len(*tokens) == 0 {
		return "", fmt.Errorf("at least one token must be provided")
	}

	claims, err := NewClaimsFromTokens(tokens)
	if err != nil {
		log.Printf("Failed to create claims for ID token: %v", err)
		return "", fmt.Errorf("failed to create claims for ID token")
	}

	var auth *models.Authorization
	if _, ok := (*tokens)[utils.ACCESS_TOKEN_TYPE]; ok {
		auth = (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization
	} else if _, ok := (*tokens)[utils.AUTHORIZATION_CODE_TYPE]; ok {
		auth = (*tokens)[utils.AUTHORIZATION_CODE_TYPE].Authorization
	} else {
		return "", fmt.Errorf("at least one token must be of type access_token or authorization_code")
	}

	token := &idToken{
		Authorization: auth,
	}

	return token.encode(claims)
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
