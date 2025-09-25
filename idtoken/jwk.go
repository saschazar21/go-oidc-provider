package idtoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func bigIntToBase64url(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func intToBase64url(i int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i)).Bytes())
}

func kidFromThumbprint(j *jwk) string {
	enc, _ := json.Marshal(j)
	hash := sha256.Sum256(enc)
	return base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2]) // use first half of the hash
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey, alg string) *jwk {
	key := jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: alg,
		N:   bigIntToBase64url(pub.N),
		E:   intToBase64url(pub.E),
	}
	key.Kid = kidFromThumbprint(&key)
	return &key
}

func ecdsaPublicKeyToJWK(pub *ecdsa.PublicKey, alg string) *jwk {
	var crv string
	switch pub.Curve.Params().Name {
	case "P-256":
		crv = "P-256"
	case "P-384":
		crv = "P-384"
	case "P-521":
		crv = "P-521"
	default:
		crv = pub.Curve.Params().Name
	}

	key := jwk{
		Kty: "EC",
		Use: "sig",
		Alg: alg,
		Crv: crv,
		X:   bigIntToBase64url(pub.X),
		Y:   bigIntToBase64url(pub.Y),
	}
	key.Kid = kidFromThumbprint(&key)
	return &key
}

func ed25519PublicKeyToJWK(pub ed25519.PublicKey, alg string) *jwk {
	key := jwk{
		Kty: "OKP",
		Use: "sig",
		Alg: alg,
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
	key.Kid = kidFromThumbprint(&key)
	return &key
}

func PublicKeyToJWK(key interface{}, alg string) (*jwk, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsaPublicKeyToJWK(&k.PublicKey, alg), nil
	case *rsa.PublicKey:
		return rsaPublicKeyToJWK(k, alg), nil
	case *ecdsa.PrivateKey:
		return ecdsaPublicKeyToJWK(&k.PublicKey, alg), nil
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyToJWK(k, alg), nil
	case ed25519.PrivateKey:
		return ed25519PublicKeyToJWK(k.Public().(ed25519.PublicKey), alg), nil
	case ed25519.PublicKey:
		return ed25519PublicKeyToJWK(k, alg), nil
	default:
		return nil, fmt.Errorf("unsupported key type for JWK conversion, got %T", key)
	}
}
