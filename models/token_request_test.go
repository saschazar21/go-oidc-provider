package models

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTokenRequest(t *testing.T) {
	type testStruct struct {
		Name    string
		Request http.Request
		WantErr bool
	}

	tests := []testStruct{
		{
			Name: "Valid Request with Basic Auth",
			Request: http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic dGVzdC1pZDpwYXNzd29yZA=="}, // base64 for "test-id:password"
					"Content-Type":  []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":   []string{"authorization_code"},
					"code":         []string{"valid-code"},
					"redirect_uri": []string{"https://client.example.com/callback"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with Client Credentials in Body",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"authorization_code"},
					"code":          []string{"valid-code"},
					"redirect_uri":  []string{"https://client.example.com/callback"},
					"client_id":     []string{"test-id"},
					"client_secret": []string{"password"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with PKCE",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"authorization_code"},
					"code":          []string{"valid-code"},
					"redirect_uri":  []string{"https://client.example.com/callback"},
					"client_id":     []string{"test-id"},
					"code_verifier": []string{"valid-code-verifier"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Valid Request with Refresh Token",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type":    []string{"refresh_token"},
					"refresh_token": []string{"valid-refresh-token"},
					"client_id":     []string{"test-id"},
					"client_secret": []string{"password"},
				},
				Method: http.MethodPost,
			},
			WantErr: false,
		},
		{
			Name: "Invalid Method",
			Request: http.Request{
				Method: http.MethodGet,
			},
			WantErr: true,
		},
		{
			Name: "Missing Required Fields",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Form: map[string][]string{
					"grant_type": []string{"authorization_code"},
					// Missing 'code' and 'redirect_uri'
				},
				Method: http.MethodPost,
			},
			WantErr: true,
		},
		{
			Name: "Invalid Content Type",
			Request: http.Request{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body:   io.NopCloser(strings.NewReader(`{"grant_type":"authorization_code","code":"valid-code","redirect_uri":"https://client.example.com/callback"}`)),
				Method: http.MethodPost,
			},
			WantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			req := &tt.Request

			// If the request body is set, read it into PostForm
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("Failed to read request body: %v", err)
				}
				req.PostForm, err = url.ParseQuery(string(bodyBytes))
				if err != nil {
					t.Fatalf("Failed to parse request body: %v", err)
				}
			} else {
				req.PostForm = req.Form
			}

			_, err := ParseTokenRequest(req)
			if (err != nil) != tt.WantErr {
				t.Errorf("ParseTokenRequest() error = %v, wantErr %v", err, tt.WantErr)
			}
		})
	}
}
