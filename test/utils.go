package test

import (
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
