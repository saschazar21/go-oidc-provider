package idtoken

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

type Claims struct {
	Issuer    string           `json:"iss,omitempty" validate:"required,url"`
	Subject   string           `json:"sub,omitempty" validate:"required"`
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty" validate:"required,gtfield=IssuedAt"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty" validate:"omitempty,gtfield=IssuedAt"`
	Audience  jwt.ClaimStrings `json:"aud,omitempty" validate:"optional,dive,required"`
	JTI       string           `json:"jti,omitempty" validate:"omitempty,uuid4"`

	Scope           utils.ScopeSlice `json:"scope,omitempty" validate:"omitempty,dive,scope"`
	Nonce           string           `json:"nonce,omitempty"`
	AccessTokenHash string           `json:"at_hash,omitempty"`
	CodeHash        string           `json:"c_hash,omitempty"`
	StateHash       string           `json:"s_hash,omitempty"`

	token *map[utils.TokenType]models.Token `json:"-"`
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
	c.ExpiresAt = jwt.NewNumericDate(token.ExpiresAt.ExpiresAt)
	c.IssuedAt = jwt.NewNumericDate(token.CreatedAt.CreatedAt)

	if token.Authorization.UserID == uuid.Nil {
		return fmt.Errorf("user_id is not set in authorization")
	}
	c.Subject = token.Authorization.UserID.String()

	if token.ClientID != nil && *token.ClientID != "" {
		c.Audience = jwt.ClaimStrings{*token.ClientID}
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
	if c.token == nil || len(*c.token) == 0 {
		return fmt.Errorf("token must be set")
	}

	if err := utils.NewCustomValidator().Struct(c); err != nil {
		return fmt.Errorf("claims validation failed: %w", err)
	}

	return nil
}

func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == nil {
		return nil, fmt.Errorf("expires_at is not set")
	}
	return c.ExpiresAt, nil
}

func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == nil {
		return nil, fmt.Errorf("issued_at is not set")
	}
	return c.IssuedAt, nil
}

func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == nil {
		return nil, fmt.Errorf("not_before is not set")
	}
	return c.NotBefore, nil
}

func (c *Claims) GetSubject() (string, error) {
	if c.Subject == "" {
		return "", fmt.Errorf("subject is not set")
	}
	return c.Subject, nil
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

func NewClaims(tokens *map[utils.TokenType]*models.Token) (*Claims, error) {
	if tokens == nil || len(*tokens) == 0 {
		return nil, fmt.Errorf("tokens are not set")
	}

	if _, ok := (*tokens)[utils.ACCESS_TOKEN_TYPE]; !ok {
		return nil, fmt.Errorf("access token is required to create ID token claims")
	}

	var claims Claims
	for _, token := range *tokens {
		if token.Authorization == nil {
			return nil, fmt.Errorf("authorization is not set in %s", token.Type)
		}

		if err := claims.populateClaimsFromToken(token); err != nil {
			log.Printf("Failed to populate claims from %s: %v", token.Type, err)
			return nil, err
		}
	}

	return &claims, nil
}
