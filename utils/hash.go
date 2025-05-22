package utils

import (
	"crypto/sha512"
	"fmt"
)

func Hash(data []byte) ([]byte, error) {
	// Create a new SHA512 hash
	h := sha512.New()

	// Write data to the hash
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hash: %w", err)
	}

	// Get the final hash result
	hash := h.Sum(nil)

	return hash, nil
}
