package models

import (
	"time"
)

type CreatedAt struct {
	CreatedAt time.Time `json:"created_at,omitempty" bun:"created_at,notnull,default:now()"`
}

type ExpiresAt struct {
	ExpiresAt time.Time `json:"expires_at,omitempty" validate:"omitempty,time-gt-now" bun:"expires_at,notnull,nullzero"`
}

type UpdatedAt struct {
	UpdatedAt time.Time `json:"updated_at,omitempty" bun:"updated_at,notnull,default:now()"`
}
