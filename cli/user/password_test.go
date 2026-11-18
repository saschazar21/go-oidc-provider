package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func TestPasswordOptions(t *testing.T) {
	id := uuid.NewString()
	for _, tt := range []struct {
		args    []string
		wantErr bool
	}{
		{nil, false},
		{[]string{"--password-user", id}, false},
		{[]string{"--password-user", id, "--remove-password"}, false},
		{[]string{"--remove-password"}, true},
		{[]string{"--password-user", "bad"}, true},
		{[]string{"--password-user", uuid.Nil.String()}, true},
		{[]string{"--password-user", id, "plaintext-secret"}, true},
	} {
		var output bytes.Buffer
		options, err := parsePasswordOptions(tt.args, &output)
		if (err != nil) != tt.wantErr {
			t.Fatalf("parse options: %v", err)
		}
		if !tt.wantErr && len(tt.args) > 0 && options.userID.String() != id {
			t.Fatal("incorrect user ID")
		}
		if strings.Contains(output.String(), "plaintext-secret") || (err != nil && strings.Contains(err.Error(), "plaintext-secret")) {
			t.Fatal("argument error disclosed a secret")
		}
	}
}

func TestReadConfirmedPassword(t *testing.T) {
	for _, tt := range []struct {
		name    string
		first   string
		second  string
		failAt  int
		wantErr bool
	}{
		{"preserves bytes", "  密碼\t ", "  密碼\t ", -1, false},
		{"max bytes", strings.Repeat("a", utils.MaxPasswordBytes), strings.Repeat("a", utils.MaxPasswordBytes), -1, false},
		{"mismatch", "secret", "different", -1, true},
		{"empty", "", "", -1, true},
		{"oversized", strings.Repeat("a", utils.MaxPasswordBytes+1), "unused", -1, true},
		{"EOF", "", "", 0, true},
		{"confirmation EOF", "secret", "", 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inputs := [][]byte{[]byte(tt.first), []byte(tt.second)}
			calls := 0
			read := func() ([]byte, error) {
				i := calls
				calls++
				if i == tt.failAt {
					return nil, io.EOF
				}
				return inputs[i], nil
			}
			var output bytes.Buffer
			password, err := readConfirmedPassword(&output, read)
			if (err != nil) != tt.wantErr {
				t.Fatalf("read password: %v", err)
			}
			if !tt.wantErr && password != tt.first {
				t.Fatal("password was modified")
			}
			if tt.wantErr && password != "" {
				t.Fatal("failed input returned a password")
			}
			if tt.first != "" && strings.Contains(output.String(), tt.first) {
				t.Fatal("password was echoed")
			}
			for i := 0; i < calls; i++ {
				if i != tt.failAt && !bytes.Equal(inputs[i], make([]byte, len(inputs[i]))) {
					t.Fatal("temporary secret buffer was not cleared")
				}
			}
		})
	}
}