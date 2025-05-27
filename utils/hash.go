package utils

import (
	"github.com/zeebo/blake3"
)

func Hash(data []byte) (hashed [32]byte) {
	hashed = blake3.Sum256(data)

	return
}
