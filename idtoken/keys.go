package idtoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
)

var _keys map[string]interface{}

func loadKey(alg string) (interface{}, error) {
	key := os.Getenv("KEY_" + alg)

	if key == "" {
		return nil, nil
	}

	switch alg {
	case HS256, HS384, HS512:
		// HMAC uses a shared secret key
		// In a real implementation, you would retrieve this from a secure location
		return decodeHMACSecretFromBase64(key)
	case RS256, RS384, RS512:
		// RSA uses a private key for signing and a public key for verification
		return decodeRSAPrivateKeyFromBase64(key)
	case ES256, ES384, ES512:
		// ECDSA uses a private key for signing and a public key for verification
		return decodeECDSAPrivateKeyFromBase64(key)
	case EdDSA:
		// EdDSA uses an Ed25519 private key for signing and a public key for verification
		return decodeEd25519PrivateKeyFromBase64(key)
	default:
		return nil, nil
	}
}

func LoadKeys() (map[string]interface{}, error) {
	if len(_keys) > 0 {
		return _keys, nil
	}

	_keys = make(map[string]interface{})

	algorithms := []string{
		ES256, ES384, ES512,
		RS256, RS384, RS512,
		PS256, PS384, PS512,
		EdDSA,
		HS256, HS384, HS512,
	}

	for _, alg := range algorithms {
		key, err := loadKey(alg)
		if err != nil {
			log.Printf("Error loading key for algorithm %s: %v", alg, err)
			continue
		}
		if key == nil {
			log.Printf("No key found for algorithm %s", alg)
			continue
		}
		_keys[alg] = key
	}

	if len(_keys) == 0 {
		return nil, fmt.Errorf("no keys loaded, or loading of at least one key failed")
	}

	return _keys, nil
}

func GetKey(alg string) (interface{}, error) {
	if len(_keys) == 0 {
		if _, err := LoadKeys(); err != nil {
			return nil, err
		}
	}

	key, exists := _keys[alg]
	if !exists {
		return nil, fmt.Errorf("no key found for algorithm %s", alg)
	}

	return key, nil
}

func GetPublicKey(alg string) (interface{}, error) {
	key, err := GetKey(alg)
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return ed25519.PublicKey(k[32:]), nil
	default:
		return nil, fmt.Errorf("unsupported key type for algorithm %s", alg)
	}
}
