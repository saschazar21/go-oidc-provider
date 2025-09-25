package test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

func LoadFixture(file string, model interface{}) error {
	data, err := os.ReadFile(filepath.Join("../test/testdata", file))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, model); err != nil {
		return err
	}
	return nil
}

func LoadTextFixture(file string, encodeToBase64 ...bool) (string, error) {
	data, err := os.ReadFile(filepath.Join("../test/testdata", file))
	if err != nil {
		return "", err
	}

	if len(encodeToBase64) > 0 && encodeToBase64[0] {
		return base64.StdEncoding.EncodeToString(data), nil
	}

	return string(data), nil
}
