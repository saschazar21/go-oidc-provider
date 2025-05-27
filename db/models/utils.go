package models

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func loadFixture(file string, model interface{}) error {
	data, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, model); err != nil {
		return err
	}
	return nil
}
