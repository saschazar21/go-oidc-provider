package utils

import (
	"time"

	"github.com/go-playground/validator/v10"
)

const (
	DATE         = "date"
	TIME_GT_NOW  = "time-gt-now"
	TIME_LT_NOW  = "time-lt-now"
	TIME_GTE_NOW = "time-gte-now"
	TIME_LTE_NOW = "time-lte-now"
)

var _customValidator *validator.Validate

func NewCustomValidator() *validator.Validate {
	if _customValidator == nil {
		_customValidator = validator.New()
		_customValidator.RegisterValidation(DATE, validateDate)
		_customValidator.RegisterValidation(TIME_GT_NOW, validateTimeGtNow)
		_customValidator.RegisterValidation(TIME_LT_NOW, validateTimeLtNow)
		_customValidator.RegisterValidation(TIME_GTE_NOW, validateTimeGteNow)
		_customValidator.RegisterValidation(TIME_LTE_NOW, validateTimeLteNow)
	}

	return _customValidator
}

func validateDate(fl validator.FieldLevel) bool {
	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return true
	case *time.Time:
		if t == nil {
			return false
		}
		return true
	case string:
		_, err := time.Parse(DEFAULT_DATE_FORMAT, t)
		if err != nil {
			return false
		}
		return true
	case *string:
		if t == nil {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, *t)
		if err != nil {
			return false
		}
		return true
	case EncryptedString:
		if t == "" {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, string(t))
		if err != nil {
			return false
		}
		return true
	case *EncryptedString:
		if t == nil {
			return false
		}
		if *t == "" {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, string(*t))
		if err != nil {
			return false
		}
		return true
	default:
		return false
	}
}

func validateTimeGtNow(fl validator.FieldLevel) bool {
	now := time.Now()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.After(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).After(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.After(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.After(now)
	case EncryptedDate:
		return t.Time.After(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.After(now)
	case Epoch:
		return t.Time.After(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return t.Time.After(now)
	case EpochMillis:
		return t.Time.After(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return t.Time.After(now)
	default:
		return false
	}
}

func validateTimeLtNow(fl validator.FieldLevel) bool {
	now := time.Now()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Before(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Before(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Before(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Before(now)
	case EncryptedDate:
		return t.Time.Before(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Before(now)
	case Epoch:
		return t.Time.Before(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return t.Time.Before(now)
	case EpochMillis:
		return t.Time.Before(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return t.Time.Before(now)
	default:
		return false
	}
}

func validateTimeGteNow(fl validator.FieldLevel) bool {
	now := time.Now()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Equal(now) || t.After(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Equal(now) || (*t).After(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.After(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.After(now)
	case EncryptedDate:
		return t.Time.Equal(now) || t.Time.After(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.After(now)
	case Epoch:
		return t.Time.Equal(now) || t.Time.After(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.After(now)
	case EpochMillis:
		return t.Time.Equal(now) || t.Time.After(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.After(now)
	default:
		return false
	}
}

func validateTimeLteNow(fl validator.FieldLevel) bool {
	now := time.Now()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Equal(now) || t.Before(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Equal(now) || (*t).Before(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.Before(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.Before(now)
	case EncryptedDate:
		return t.Time.Equal(now) || t.Time.Before(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.Before(now)
	case Epoch:
		return t.Time.Equal(now) || t.Time.Before(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.Before(now)
	case EpochMillis:
		return t.Time.Equal(now) || t.Time.Before(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.Before(now)
	default:
		return false
	}
}
