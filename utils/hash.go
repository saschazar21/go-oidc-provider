package utils

import (
	"crypto/sha256"

	"github.com/zeebo/blake3"
)

func Hash(data []byte) (hashed [32]byte) {
	hashed = blake3.Sum256(data)

	return
}

func HashS256(data []byte) (hashed [32]byte) {
	hashed = sha256.Sum256(data)

	return
}
