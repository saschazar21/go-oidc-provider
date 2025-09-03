package models

type ValidatabaleModelWithID interface {
	Validate() error
	GetID() string
}
