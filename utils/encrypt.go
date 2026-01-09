package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func createGCM() (cipher.AEAD, error) {
	if os.Getenv(MASTER_KEY_ENV) == "" {
		log.Fatalf("MASTER_KEY env must be set!")
	}

	decoded, err := base64.StdEncoding.DecodeString(os.Getenv(MASTER_KEY_ENV))

	if err != nil {
		log.Fatalf("failed to decode MASTER_KEY env, make sure it's a valid base64-encoding: %v", err)
	}

	if len(decoded) != 32 {
		log.Fatalf("MASTER_KEY env must be set and exactly 32 bytes long! Received %d bytes...", len(decoded))
	}

	aesBlock, err := aes.NewCipher(decoded)

	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)

	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm, nil
}

func Encrypt(data []byte) ([]byte, error) {
	gcm, err := createGCM()

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to feed random data into nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

func Decrypt(data []byte) ([]byte, error) {
	gcm, err := createGCM()

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
