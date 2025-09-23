package idtoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
)

func decodeDERFromBase64(encodedKey string) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		msg := "failed to decode DER from base64"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}

	// if the key is in PEM format, decode it
	if bytes := der; len(bytes) > 0 {
		if block, _ := pem.Decode(bytes); block != nil {
			der = block.Bytes
		}
	}

	return der, nil
}

func decodeECDSAPrivateKeyFromBase64(encodedKey string) (*ecdsa.PrivateKey, error) {
	der, err := decodeDERFromBase64(encodedKey)
	if err != nil {
		log.Printf("failed to decode ECDSA private key: %v", err)
		return nil, err
	}

	// Try SEC1 / PKCS#1 EC private key first
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	// Then try PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		msg := "failed to parse ECDSA private key"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}

	if ecdsaKey, ok := keyInterface.(*ecdsa.PrivateKey); ok {
		return ecdsaKey, nil
	}

	msg := "not an ECDSA private key"
	log.Printf("%s", msg)
	return nil, fmt.Errorf("%s", msg)
}

func decodeEd25519PrivateKeyFromBase64(encodedKey string) (ed25519.PrivateKey, error) {
	der, err := decodeDERFromBase64(encodedKey)
	if err != nil {
		log.Printf("failed to decode Ed25519 private key: %v", err)
		return nil, err
	}

	// Try raw 64-byte private key first
	if len(der) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(der), nil
	}

	// Then try PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		msg := "failed to parse Ed25519 private key"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}

	if ed25519Key, ok := keyInterface.(ed25519.PrivateKey); ok {
		return ed25519Key, nil
	}

	msg := "not an Ed25519 private key"
	log.Printf("%s", msg)
	return nil, fmt.Errorf("%s", msg)
}

func decodeHMACSecretFromBase64(encodedSecret string) ([]byte, error) {
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		msg := "failed to decode HMAC secret from base64"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}
	return secret, nil
}

func decodeRSAPrivateKeyFromBase64(encodedKey string) (*rsa.PrivateKey, error) {
	der, err := decodeDERFromBase64(encodedKey)
	if err != nil {
		log.Printf("failed to decode RSA private key: %v", err)
		return nil, err
	}

	// try PKCS#1 first
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// then try PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		msg := "failed to parse RSA private key"
		log.Printf("%s: %v", msg, err)
		return nil, fmt.Errorf("%s", msg)
	}

	if rsaKey, ok := keyInterface.(*rsa.PrivateKey); ok {
		return rsaKey, nil
	}

	msg := "not an RSA private key"
	log.Printf("%s", msg)
	return nil, fmt.Errorf("%s", msg)
}
