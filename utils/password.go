package utils

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// MaxPasswordBytes is a byte limit, not a character limit. Passwords are never
// trimmed, normalized, truncated, or passed through HashedString.
const MaxPasswordBytes = 1024

const (
	passwordMemory    = 19 * 1024 // KiB; OWASP Argon2id floor.
	passwordTime      = 2
	passwordKeyBytes  = 32
	passwordSaltBytes = 16
)

var (
	ErrInvalidPassword     = errors.New("password must contain between 1 and 1024 bytes")
	ErrInvalidPasswordHash = errors.New("invalid or unsupported password hash")
	// At most two KDFs run at once, including verification and dummy work.
	passwordSlots        = make(chan struct{}, 2)
	dummyPasswordOnce    sync.Once
	dummyPasswordEncoded string
	dummyPasswordError   error
)

type passwordHash struct {
	memory uint32
	time   uint32
	salt   []byte
	key    []byte
}

// HashPassword encodes a random-salted Argon2id hash in PHC format.
func HashPassword(password string) (string, error) {
	return HashPasswordContext(context.Background(), password)
}

// HashPasswordContext permits cancellation while waiting for a KDF slot.
// An already-running Argon2 computation cannot be interrupted.
func HashPasswordContext(ctx context.Context, password string) (string, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return "", ErrInvalidPassword
	}
	if err := acquirePasswordSlot(ctx); err != nil {
		return "", err
	}
	defer func() { <-passwordSlots }()
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("password salt generation failed")
	}
	key := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, 1, passwordKeyBytes)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", passwordMemory, passwordTime,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func acquirePasswordSlot(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case passwordSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-passwordSlots
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ValidatePasswordHash checks syntax and bounded KDF costs without doing KDF work.
func ValidatePasswordHash(encoded string) error {
	_, err := parsePasswordHash(encoded)
	return err
}

func parsePasswordHash(encoded string) (*passwordHash, error) {
	if len(encoded) > 256 {
		return nil, ErrInvalidPasswordHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, ErrInvalidPasswordHash
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 || !strings.HasPrefix(params[0], "m=") || !strings.HasPrefix(params[1], "t=") || params[2] != "p=1" {
		return nil, ErrInvalidPasswordHash
	}
	parse := func(s string, min, max uint64) (uint32, error) {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n < min || n > max || strconv.FormatUint(n, 10) != s {
			return 0, ErrInvalidPasswordHash
		}
		return uint32(n), nil
	}
	// Hard upper bounds prevent attacker-controlled PHC values exhausting memory
	// or CPU. Parallelism is deliberately fixed to one for this implementation.
	memory, err := parse(params[0][2:], passwordMemory, 64*1024)
	if err != nil {
		return nil, err
	}
	iterations, err := parse(params[1][2:], passwordTime, 4)
	if err != nil {
		return nil, err
	}
	decode := func(s string, min, max int) ([]byte, error) {
		b, err := base64.RawStdEncoding.Strict().DecodeString(s)
		if err != nil || len(b) < min || len(b) > max || base64.RawStdEncoding.EncodeToString(b) != s {
			return nil, ErrInvalidPasswordHash
		}
		return b, nil
	}
	salt, err := decode(parts[4], 16, 32)
	if err != nil {
		return nil, err
	}
	key, err := decode(parts[5], passwordKeyBytes, passwordKeyBytes)
	if err != nil {
		return nil, err
	}
	return &passwordHash{memory: memory, time: iterations, salt: salt, key: key}, nil
}

func VerifyPassword(encoded, password string) (bool, error) {
	return VerifyPasswordContext(context.Background(), encoded, password)
}

func VerifyPasswordContext(ctx context.Context, encoded, password string) (bool, error) {
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return false, ErrInvalidPassword
	}
	hash, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	if err := acquirePasswordSlot(ctx); err != nil {
		return false, err
	}
	defer func() { <-passwordSlots }()
	key := argon2.IDKey([]byte(password), hash.salt, hash.time, hash.memory, 1, uint32(len(hash.key)))
	defer clear(key)
	return subtle.ConstantTimeCompare(key, hash.key) == 1, nil
}

// DummyPasswordHash is initialized once on demand, never by a panicking init.
// Initialize at service startup and verify against it for unknown/passwordless
// users, discarding the comparison result. Never use it to authenticate a user.
func DummyPasswordHash() (string, error) {
	dummyPasswordOnce.Do(func() {
		secret := make([]byte, 32)
		defer clear(secret)
		if _, err := rand.Read(secret); err != nil {
			dummyPasswordError = errors.New("dummy password initialization failed")
			return
		}
		dummyPasswordEncoded, dummyPasswordError = HashPassword(string(secret))
	})
	return dummyPasswordEncoded, dummyPasswordError
}
