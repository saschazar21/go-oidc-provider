package utils

import (
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ACR string
type AMR string

type Marshalable interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
}

type Validatable interface {
	Validate() error
}

type AuthMethod string
type AuthStatus string

type EncryptedDate struct {
	time.Time
}

func (e EncryptedDate) MarshalJSON() ([]byte, error) {
	date := e.Time.Format(DEFAULT_DATE_FORMAT)
	return []byte(fmt.Sprintf("\"%s\"", date)), nil
}

func (e *EncryptedDate) UnmarshalJSON(data []byte) (err error) {
	var date time.Time
	if len(data) == 0 {
		return nil
	}

	stringified := string(data)
	date, err = time.Parse(fmt.Sprintf("\"%s\"", DEFAULT_DATE_FORMAT), stringified)
	if err != nil {
		return fmt.Errorf("failed to parse date: %w", err)
	}
	e.Time = date
	return
}

func (e EncryptedDate) Value() (driver.Value, error) {
	if e.IsZero() {
		return nil, nil
	}

	date := e.Time.Format(DEFAULT_DATE_FORMAT)
	encrypted, err := Encrypt([]byte(date))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt date: %w", err)
	}
	return encrypted, nil
}

func (e *EncryptedDate) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []byte:
		decrypted, err := Decrypt(v)
		if err != nil {
			return fmt.Errorf("failed to decrypt date: %w", err)
		}
		date, err := time.Parse(DEFAULT_DATE_FORMAT, string(decrypted))
		if err != nil {
			return fmt.Errorf("failed to parse decrypted date: %w", err)
		}
		e.Time = date
	case string:
		decrypted, err := Decrypt([]byte(v))
		if err != nil {
			return fmt.Errorf("failed to decrypt date: %w", err)
		}
		date, err := time.Parse(DEFAULT_DATE_FORMAT, string(decrypted))
		if err != nil {
			return fmt.Errorf("failed to parse decrypted date: %w", err)
		}
		e.Time = date
	default:
		return fmt.Errorf("unsupported type for EncryptedDate: %T", v)
	}
	return nil
}

type EncryptedString string

func (e EncryptedString) Value() (driver.Value, error) {
	if len(e) == 0 {
		return nil, nil
	}

	encrypted, err := Encrypt([]byte(e))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt string: %w", err)
	}
	return encrypted, nil
}

func (e *EncryptedString) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []byte:
		decrypted, err := Decrypt(v)
		if err != nil {
			return fmt.Errorf("failed to decrypt string: %w", err)
		}
		*e = EncryptedString(decrypted)
	case string:
		decrypted, err := Decrypt([]byte(v))
		if err != nil {
			return fmt.Errorf("failed to decrypt string: %w", err)
		}
		*e = EncryptedString(decrypted)
	default:
		return fmt.Errorf("unsupported type for EncryptedString: %T", v)
	}

	return nil
}

type Epoch struct {
	time.Time
}

func (e Epoch) MarshalJSON() ([]byte, error) {
	ts := e.Unix()
	return []byte(fmt.Sprintf("%d", ts)), nil
}

func (e *Epoch) UnmarshalJSON(data []byte) (err error) {
	var epoch int64
	stringified := string(data)

	if epoch, err = strconv.ParseInt(stringified, 10, 64); err != nil {
		return fmt.Errorf("failed to parse epoch: %w", err)
	}

	e.Time = time.Unix(epoch, 0)

	return
}

type EpochMillis struct {
	time.Time
}

func (e EpochMillis) MarshalJSON() ([]byte, error) {
	ms := e.UnixMilli()
	return []byte(fmt.Sprintf("%d", ms)), nil
}

func (e *EpochMillis) UnmarshalJSON(data []byte) (err error) {
	var epoch int64
	stringified := string(data)

	if epoch, err = strconv.ParseInt(stringified, 10, 64); err != nil {
		return fmt.Errorf("failed to parse epoch: %w", err)
	}

	e.Time = time.UnixMilli(epoch)

	return
}

type GrantType string

type HashedString string

func (h HashedString) Value() (driver.Value, error) {
	if len(h) == 0 {
		return nil, nil
	}

	hashed := Hash([]byte(h))

	return hashed, nil
}

func (h *HashedString) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []byte:
		s := base64.RawURLEncoding.EncodeToString(v)
		*h = HashedString(s)
	case string:
		*h = HashedString(v)
	default:
		return fmt.Errorf("unsupported type for HashedString: %T", v)
	}

	return nil
}

func (h *HashedString) Compare(plain []byte) bool {
	if len(*h) == 0 {
		return false
	}

	hashed := Hash(plain)
	str := base64.RawURLEncoding.EncodeToString(hashed[:])

	return string(*h) == str
}

func (h HashedString) String() string {
	if len(h) == 0 {
		return ""
	}
	return string(h)
}

type PKCEMethod string

type Prompt string

type ResponseType string

type Result string

type Scope string

type ScopeSlice []Scope

func (s ScopeSlice) MarshalJSON() ([]byte, error) {
	var joined string

	for i, scope := range s {
		joined += string(scope)
		if i < len(s)-1 {
			joined += " "
		}
	}

	return []byte(fmt.Sprintf("\"%s\"", joined)), nil
}

func (s *ScopeSlice) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*s = []Scope{}
		return nil
	}

	// Split space-separated string into scope slice
	parts := strings.Split(string(data), " ")
	var scopes []Scope
	for _, part := range parts {
		part = strings.Trim(part, " ")
		if part != "" {
			scopes = append(scopes, Scope(part))
		}
	}

	*s = scopes
	return nil
}

type TokenType string
