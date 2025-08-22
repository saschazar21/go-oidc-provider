package utils

import (
	"crypto/rand"
	"fmt"
)

const (
	BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("desired random byte size must be greather than 0, received: %d", n)
	}
	if n > 1024 {
		return nil, fmt.Errorf("desired random byte size must be less than or equal to 1024, received: %d", n)
	}

	data := make([]byte, n)

	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	return data, nil
}

func RandomBase58String(n int, prefix ...string) (string, error) {
	data, err := RandomBytes(n)
	if err != nil {
		return "", err
	}

	result := make([]byte, n)

	for i, b := range data {
		result[i] = BASE58_ALPHABET[b%byte(len(BASE58_ALPHABET))]
	}

	p := ""

	if len(prefix) > 0 {
		p = prefix[0]

		if p[len(p)-1] != '_' && p[len(p)-1] != '-' {
			p += "_"
		}
	}

	return fmt.Sprintf("%s%s", p, string(result)), nil
}

func RandomDigitString(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("desired random digit size must be greater than 0, received: %d", n)
	}
	if n > 1024 {
		return "", fmt.Errorf("desired random digit size must be less than or equal to 1024, received: %d", n)
	}

	data, err := RandomBytes(n)
	if err != nil {
		return "", err
	}

	random := ""
	for _, b := range data {
		random = fmt.Sprintf("%s%d", random, b%10)
	}

	return random, nil
}
