package utils

import "encoding/base64"

func GeneratePKCEChallenge(verifier string, isHashed ...bool) (challenge string) {
	if len(isHashed) > 0 && !isHashed[0] {
		challenge = verifier
		return
	}

	hashed := HashS256([]byte(verifier))

	challenge = base64.RawURLEncoding.EncodeToString(hashed[:])

	return
}
