package idtoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/stretchr/testify/require"
)

func TestClaimsTrustedAuthenticationMethods(t *testing.T) {
	t.Setenv(utils.ISSUER_URL_ENV, "https://issuer.example.com")
	for _, tt := range []struct {
		name     string
		evidence *[]utils.AMR
	}{
		{name: "legacy unknown"},
		{name: "empty", evidence: &[]utils.AMR{}},
		{name: "password", evidence: &[]utils.AMR{utils.AMR_PASSWORD}},
		{name: "combined", evidence: &[]utils.AMR{utils.AMR_PASSWORD, utils.AMR_EMAIL}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			untrusted := map[string]interface{}{"amr": []string{"mfa", "fido"}, "auth_time": time.Now().Unix()}
			authTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			auth := &models.Authorization{
				ClientID: "client", Client: &models.Client{},
				User:  &models.User{ID: uuid.New(), CustomClaims: &untrusted},
				Scope: []utils.Scope{utils.OPENID, utils.PROFILE},
				AMR:   tt.evidence, AuthTime: &authTime, ClaimsGranted: &untrusted, ClaimsRequested: &untrusted,
			}
			claims, err := NewClaimsFromAuthorization(auth)
			require.NoError(t, err)
			require.Equal(t, authTime.Unix(), claims.AuthTime.Unix())
			encoded, err := json.Marshal(claims)
			require.NoError(t, err)
			var decoded map[string]interface{}
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			if tt.evidence == nil || len(*tt.evidence) == 0 {
				require.NotContains(t, decoded, "amr", "untrusted claims cannot supply absent evidence")
			} else {
				require.Equal(t, *tt.evidence, claims.AMR)
				require.Len(t, decoded["amr"], len(*tt.evidence))
				(*tt.evidence)[0] = utils.AMR_FIDO
				require.Equal(t, utils.AMR_PASSWORD, claims.AMR[0], "claims must own a snapshot of the trusted evidence")
			}
		})
	}
}
