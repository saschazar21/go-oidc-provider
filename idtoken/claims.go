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

	c.Scope = token.Authorization.Scope
	c.NotBefore = utils.Epoch(token.CreatedAt.CreatedAt)
	c.ExpiresAt = utils.Epoch(token.ExpiresAt.ExpiresAt)
	c.IssuedAt = utils.Epoch(token.CreatedAt.CreatedAt)

	if token.Authorization.Client != nil && token.Authorization.Client.IDTokenLifetime > 0 {
		// if client contains a custom ID token lifetime, override the expires_at claim
		c.ExpiresAt = utils.Epoch(token.CreatedAt.CreatedAt.Add(time.Duration(token.Authorization.Client.IDTokenLifetime) * time.Second))
	}

	if token.Authorization.UserID == uuid.Nil {
		return fmt.Errorf("user_id is not set in authorization")
	}

	if token.Authorization.ClientID != "" {
		c.Audience = jwt.ClaimStrings{token.Authorization.ClientID}
	}

	if token.Authorization.Nonce != nil && *token.Authorization.Nonce != "" {
		c.Nonce = *token.Authorization.Nonce
	}

	if token.Authorization.State != nil && *token.Authorization.State != "" {
		hash := utils.HashS256([]byte(*token.Authorization.State))
		enc := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

		c.StateHash = enc
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

func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if time.Time(c.ExpiresAt).IsZero() {
		return nil, fmt.Errorf("expires_at is not set")
	}
	return jwt.NewNumericDate(time.Time(c.ExpiresAt)), nil
}

func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if time.Time(c.IssuedAt).IsZero() {
		return nil, fmt.Errorf("issued_at is not set")
	}
	return jwt.NewNumericDate(time.Time(c.IssuedAt)), nil
}

func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if time.Time(c.NotBefore).IsZero() {
		return nil, fmt.Errorf("not_before is not set")
	}
	return jwt.NewNumericDate(time.Time(c.NotBefore)), nil
}

func (c *Claims) GetSubject() (string, error) {
	if c.User == nil || c.User.ID == uuid.Nil {
		return "", fmt.Errorf("subject is not set")
	}
	return c.User.ID.String(), nil
}

func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
	if len(c.Audience) == 0 {
		return nil, fmt.Errorf("audience is not set")
	}
	return c.Audience, nil
}

func (c *Claims) GetIssuer() (string, error) {
	if c.Issuer == "" {
		return "", fmt.Errorf("issuer is not set")
	}
	return c.Issuer, nil
}

func validateTokens(tokens *map[utils.TokenType]*models.Token) error {
	if tokens == nil || len(*tokens) == 0 {
		return fmt.Errorf("tokens must be set")
	}

	if _, ok := (*tokens)[utils.ACCESS_TOKEN_TYPE]; !ok {
		return fmt.Errorf("access token must be set")
	}

	if (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization == nil {
		return fmt.Errorf("authorization must be set in access token")
	}

	if (*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.User == nil {
		return fmt.Errorf("user must be set in authorization")
	}

	if !utils.ContainsValue((*tokens)[utils.ACCESS_TOKEN_TYPE].Authorization.Scope, utils.OPENID) {
		return fmt.Errorf("authorization must contain openid scope")
	}
	return nil
}

func NewClaims(tokens *map[utils.TokenType]*models.Token) (*Claims, error) {
	if err := validateTokens(tokens); err != nil {
		return nil, err
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

	for _, token := range *tokens {
		if err := claims.populateClaimsFromToken(token); err != nil {
			log.Printf("Failed to populate claims from %s: %v", token.Type, err)
			return nil, err
		}

		if token.Type == utils.ACCESS_TOKEN_TYPE {
			claims.User = token.Authorization.User.GetClaimsBasedOnScopes(token.Authorization.Scope)

			if utils.ContainsValue(token.Authorization.Scope, utils.PROFILE) {
				claims.UpdatedAt = jwt.NewNumericDate(token.Authorization.User.UpdatedAt.UpdatedAt.UTC())
			}
		}
	}

	return &claims, nil
}
