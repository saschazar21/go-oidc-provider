package main

import (
	"testing"

	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
)

func TestConfigureClientType(t *testing.T) {
	tests := []struct {
		name                string
		clientType          string
		wantConfidential    bool
		wantPKCERequired    bool
		wantTokenAuthMethod utils.AuthMethod
	}{
		{
			name:                "public",
			clientType:          "public",
			wantConfidential:    false,
			wantPKCERequired:    true,
			wantTokenAuthMethod: utils.AUTH_METHOD_NONE,
		},
		{
			name:                "confidential",
			clientType:          "confidential",
			wantConfidential:    true,
			wantPKCERequired:    false,
			wantTokenAuthMethod: utils.CLIENT_SECRET_BASIC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &models.Client{}
			require.NoError(t, configureClientType(client, tt.clientType))
			require.NotNil(t, client.IsConfidential)
			require.NotNil(t, client.IsPKCERequired)
			require.NotNil(t, client.AuthMethod)
			require.Equal(t, tt.wantConfidential, *client.IsConfidential)
			require.Equal(t, tt.wantPKCERequired, *client.IsPKCERequired)
			require.Equal(t, tt.wantTokenAuthMethod, *client.AuthMethod)
		})
	}
}
