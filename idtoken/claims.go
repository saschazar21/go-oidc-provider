package idtoken

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type Claims struct {
	Issuer    string           `json:"iss,omitempty" validate:"required,url"`
	ExpiresAt utils.Epoch      `json:"exp,omitempty" validate:"required,gtfield=IssuedAt"`
	IssuedAt  utils.Epoch      `json:"iat,omitempty" validate:"required"`
	NotBefore utils.Epoch      `json:"nbf,omitempty" validate:"omitempty,gtefield=IssuedAt"`
	Audience  jwt.ClaimStrings `json:"aud,omitempty" validate:"omitempty,dive,required"`
	JTI       string           `json:"jti,omitempty" validate:"omitempty,uuid4"`

	Scope           utils.ScopeSlice `json:"scope,omitempty" validate:"omitempty,dive,scope"`
	Nonce           string           `json:"nonce,omitempty"`
	AccessTokenHash string           `json:"at_hash,omitempty"`
	CodeHash        string           `json:"c_hash,omitempty"`
	StateHash       string           `json:"s_hash,omitempty"`

	*models.User `validate:"-"`   // Embedded user claims, no validation on the struct itself
	UpdatedAt    *jwt.NumericDate `json:"updated_at,omitempty"` // prints the correct format for "profile" scope
}

func (c *Claims) populateClaimsFromToken(token *models.Token) error {
	switch token.Type {
	case utils.ACCESS_TOKEN_TYPE:
		hash, err := token.GenerateTokenHash()
		if err != nil {
			return fmt.Errorf("failed to generate at_hash: %w", err)
		}
		c.AccessTokenHash = hash
	case utils.AUTHORIZATION_CODE_TYPE:
		hash, err := token.GenerateTokenHash()
		if err != nil {
			return fmt.Errorf("failed to generate c_hash: %w", err)
		}
		c.CodeHash = hash
		fallthrough
	default:
		return nil
	}

	return nil
}

func (c *Claims) Validate() error {
	if err := utils.NewCustomValidator().Struct(c); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			fields := make([]string, 0, len(validationErrors))
			for _, ve := range validationErrors {
				log.Printf("Validation error on field '%s': %s - %v", ve.Field(), ve.Tag(), ve.Value())
				fields = append(fields, ve.Field())
			}
			return fmt.Errorf("invalid claims: %s", strings.Join(fields, ", "))
		}
		return fmt.Errorf("%s", "claims validation failed")
	}

	return nil
}

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if time.Time(c.ExpiresAt).IsZero() {
		return nil, fmt.Errorf("expires_at is not set")
	}
	return jwt.NewNumericDate(time.Time(c.ExpiresAt)), nil
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if time.Time(c.IssuedAt).IsZero() {
		return nil, fmt.Errorf("issued_at is not set")
	}
	return jwt.NewNumericDate(time.Time(c.IssuedAt)), nil
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if time.Time(c.NotBefore).IsZero() {
		return nil, fmt.Errorf("not_before is not set")
	}
	return jwt.NewNumericDate(time.Time(c.NotBefore)), nil
}

func (c Claims) GetSubject() (string, error) {
	if c.User == nil || c.User.ID == uuid.Nil {
		return "", fmt.Errorf("subject is not set")
	}
	return c.User.ID.String(), nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	if len(c.Audience) == 0 {
		return nil, fmt.Errorf("audience is not set")
	}
	return c.Audience, nil
}

func (c Claims) GetIssuer() (string, error) {
	if c.Issuer == "" {
		return "", fmt.Errorf("issuer is not set")
	}
	return c.Issuer, nil
}

func NewClaimsFromAuthorization(auth *models.Authorization) (*Claims, error) {
	if auth == nil {
		return nil, fmt.Errorf("no authorization data provided")
	}

	if auth.User == nil {
		return nil, fmt.Errorf("user must be set in authorization")
	}

	if auth.Client == nil {
		return nil, fmt.Errorf("client must be set in authorization")
	}

	if !utils.ContainsValue(auth.Scope, utils.OPENID) {
		return nil, fmt.Errorf("authorization must contain openid scope")
	}

	var issuer string
	if os.Getenv(utils.ISSUER_URL_ENV) != "" {
		issuer = os.Getenv(utils.ISSUER_URL_ENV)
	} else {
		issuer = utils.GetDeploymentURL()
	}

	if issuer == "" {
		return nil, fmt.Errorf("issuer URL is not set, please set the %s environment variable", utils.ISSUER_URL_ENV)
	}

	claims := Claims{
		Issuer: issuer,
	}

	now := time.Now().UTC()
	claims.IssuedAt = utils.Epoch(now)
	claims.NotBefore = utils.Epoch(now)

	lifetime := DEFAULT_ID_TOKEN_LIFETIME
	if auth.Client.IDTokenLifetime > 0 {
		lifetime = auth.Client.IDTokenLifetime
	}

	claims.ExpiresAt = utils.Epoch(now.Add(time.Duration(lifetime) * time.Second))

	if auth.ClientID != "" {
		claims.Audience = jwt.ClaimStrings{auth.ClientID}
	}

	claims.Scope = auth.Scope
	claims.User = auth.User.GetClaimsBasedOnScopes(auth.Scope)

	if auth.User.UpdatedAt != nil && utils.ContainsValue(auth.Scope, utils.PROFILE) {
		claims.UpdatedAt = jwt.NewNumericDate(auth.User.UpdatedAt.UpdatedAt)
	}

	if auth.Nonce != nil && *auth.Nonce != "" {
		claims.Nonce = *auth.Nonce
	}

	if auth.State != nil && *auth.State != "" {
		hash := utils.HashS256([]byte(*auth.State))
		enc := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

		claims.StateHash = enc
	}

	return &claims, nil
}

func NewClaimsFromTokens(tokens *map[utils.TokenType]*models.Token) (*Claims, error) {
	if tokens == nil || len(*tokens) == 0 {
		return nil, fmt.Errorf("tokens must be set")
	}

	var auth *models.Authorization
	if _, ok := (*tokens)[utils.ACCESS_TOKEN_TYPE]; ok {
		auth = (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization
	} else if _, ok := (*tokens)[utils.AUTHORIZATION_CODE_TYPE]; ok {
		auth = (*tokens)[utils.AUTHORIZATION_CODE_TYPE].Authorization
	} else {
		return nil, fmt.Errorf("at least one token must be of type access_token or authorization_code")
	}

	claims, err := NewClaimsFromAuthorization(auth)
	if err != nil {
		return nil, err
	}

	for _, token := range *tokens {
		if err := claims.populateClaimsFromToken(token); err != nil {
			log.Printf("Failed to populate claims from %s: %v", token.Type, err)
			return nil, err
		}
	}

	return claims, nil
}
