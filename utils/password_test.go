package utils

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordRoundTrip(t *testing.T) {
	for _, password := range []string{"password", "  päss\t密碼\n ", "\x00password\xff", strings.Repeat("a", MaxPasswordBytes)} {
		t.Run(base64.RawStdEncoding.EncodeToString([]byte(password[:1])), func(t *testing.T) {
			encoded, err := HashPassword(password)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePasswordHash(encoded); err != nil {
				t.Fatal(err)
			}
			hash, err := parsePasswordHash(encoded)
			if err != nil || len(hash.salt) < 16 || hash.memory < 19*1024 || hash.time < 2 {
				t.Fatal("unsafe hash parameters")
			}
			for _, candidate := range []struct {
				password string
				match    bool
			}{{password, true}, {"wrong", false}, {password[:len(password)-1] + "!", false}} {
				matched, err := VerifyPassword(encoded, candidate.password)
				if err != nil || matched != candidate.match {
					t.Fatalf("verification: matched=%v, err=%v", matched, err)
				}
			}
		})
	}
	first, err := HashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("same")
	if err != nil || first == second {
		t.Fatal("independent hashes must have different salts")
	}
}

func TestPasswordKnownPHC(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte("  secret  "), salt, 2, 19*1024, 1, 32)
	encoded := "$argon2id$v=19$m=19456,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
	matched, err := VerifyPassword(encoded, "  secret  ")
	if err != nil || !matched {
		t.Fatalf("PHC compatibility: %v", err)
	}
	matched, err = VerifyPassword(encoded, "secret")
	if err != nil || matched {
		t.Fatal("password whitespace must not be trimmed")
	}
}

func TestPasswordRejectsUnsafePHC(t *testing.T) {
	valid := "$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$" + strings.Repeat("A", 43)
	if err := ValidatePasswordHash(valid); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		"", strings.Repeat("a", 257), valid + "$extra", valid + "=",
		strings.Replace(valid, "argon2id", "argon2i", 1),
		strings.Replace(valid, "v=19", "v=16", 1),
		strings.Replace(valid, "m=19456", "m=19455", 1),
		strings.Replace(valid, "m=19456", "m=65537", 1),
		strings.Replace(valid, "m=19456", "m=4294967296", 1),
		strings.Replace(valid, "m=19456", "m=019456", 1),
		strings.Replace(valid, "m=19456", "m=+19456", 1),
		strings.Replace(valid, "t=2", "t=1", 1),
		strings.Replace(valid, "t=2", "t=5", 1),
		strings.Replace(valid, "p=1", "p=0", 1),
		strings.Replace(valid, "p=1", "p=2", 1),
		strings.Replace(valid, "p=1", "p=1,p=1", 1),
		strings.Replace(valid, "m=19456,t=2", "t=2,m=19456", 1),
		strings.Replace(valid, "MDEyMzQ1Njc4OWFiY2RlZg", "YWJjZA", 1),
		strings.Replace(valid, "MDEyMzQ1Njc4OWFiY2RlZg", "MDEyMzQ1Njc4OWFiY2RlZh", 1),
		strings.Replace(valid, "MDEy", "MDEy\n", 1),
		valid[:len(valid)-1],
	}
	for i, encoded := range invalid {
		if matched, err := VerifyPassword(encoded, "secret"); !errors.Is(err, ErrInvalidPasswordHash) || matched {
			t.Errorf("case %d: malformed hash accepted: %v", i, err)
		}
	}
}

func TestPasswordInputBounds(t *testing.T) {
	for _, password := range []string{"", strings.Repeat("a", MaxPasswordBytes+1), strings.Repeat("密", 342)} {
		if _, err := HashPassword(password); !errors.Is(err, ErrInvalidPassword) {
			t.Fatal("expected byte-length validation")
		}
		if matched, err := VerifyPassword("unused", password); !errors.Is(err, ErrInvalidPassword) || matched {
			t.Fatal("expected byte-length validation before KDF")
		}
	}
}

func TestPasswordBoundedConcurrencyAndCancellation(t *testing.T) {
	for i := 0; i < cap(passwordSlots); i++ {
		passwordSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(passwordSlots); i++ {
			<-passwordSlots
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := HashPasswordContext(ctx, "secret"); !errors.Is(err, context.Canceled) {
				t.Errorf("expected cancelled queued hash, got %v", err)
			}
		}()
	}
	cancel()
	wg.Wait()
	if len(passwordSlots) != cap(passwordSlots) {
		t.Fatal("cancelled waiters acquired or released someone else's slots")
	}
}

func TestDummyPasswordHash(t *testing.T) {
	encoded, err := DummyPasswordHash()
	if err != nil {
		t.Fatal(err)
	}
	again, err := DummyPasswordHash()
	if err != nil || again != encoded {
		t.Fatal("dummy hash must be stable and safely initialized")
	}
	if matched, err := VerifyPassword(encoded, "not-the-random-secret"); err != nil || matched {
		t.Fatal("dummy verification failed")
	}
}

func FuzzPasswordPHCParser(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$" + strings.Repeat("A", 43))
	f.Add("$argon2id$v=19$m=4294967295,t=999999,p=255$bad$bad")
	f.Fuzz(func(t *testing.T, encoded string) {
		_ = ValidatePasswordHash(encoded) // Parser only: fuzzing must not run a KDF.
	})
}

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		if _, err := HashPassword("benchmark password"); err != nil {
			b.Fatal(err)
		}
	}
}