package endpoints

import (
	"bytes"
	"html/template"
	"testing"

	provider "github.com/saschazar21/go-oidc-provider/endpoints"
	"github.com/stretchr/testify/require"
)

func TestPaperTemplates(t *testing.T) {
	data := map[string]any{
		"Year": 2026, "Client": map[string]string{"Name": "Example <script>alert(1)</script>"},
		"Scope": []string{"openid", "profile", "email"}, "FormPostURI": "/submit",
		"Token": `token" autofocus="false`, "ID": "verification-id",
		"LoginURL":     "/authorize?scope=openid&state=demo",
		"OIDCRequest":  `{"client_id":"demo","scope":"openid profile"}`,
		"OIDCResponse": `{"message":"<script>alert(1)</script>"}`,
		"ClientID":     "demo-client", "ClientSecret": "demo-secret",
	}
	for _, test := range []struct {
		name   string
		source string
		want   []string
	}{
		{"index", DEFAULT_HTML_TEMPLATE_INDEX, []string{"This demo uses the following OIDC parameters:", "href=\"/authorize?"}},
		{"success", DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS, []string{"Here's the response data we received:", "demo-client", "demo-secret"}},
		{"error", DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR, []string{"Here's the error/response data we received:", "status--error"}},
		{"login", provider.DEFAULT_LOGIN_TEMPLATE, []string{`name="email"`, `label for="email"`, `autocomplete="email"`}},
		{"verification", provider.DEFAULT_MAGIC_LINK_TEMPLATE, []string{`name="token"`, `label for="token"`, `name="id" value="verification-id"`}},
		{"consent", provider.DEFAULT_AUTHORIZATION_TEMPLATE, []string{`value="approved"`, `value="denied"`, "<code>openid</code>"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tpl, err := template.New(test.name).Parse(test.source)
			require.NoError(t, err)
			var output bytes.Buffer
			require.NoError(t, tpl.Execute(&output, data))
			html := output.String()
			require.Contains(t, html, `aria-labelledby="page-title"`)
			require.Contains(t, html, provider.DEFAULT_PAPER_STYLES)
			require.NotContains(t, html, "<script")
			require.NotContains(t, html, "cdn.jsdelivr.net")
			require.NotContains(t, html, "ZgotmplZ")
			for _, want := range test.want {
				require.Contains(t, html, want)
			}
			if test.name == "consent" {
				require.Contains(t, html, "&lt;script&gt;")
			}
		})
	}
}

func TestConsentWithoutScopes(t *testing.T) {
	tpl, err := template.New("consent").Parse(provider.DEFAULT_AUTHORIZATION_TEMPLATE)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, tpl.Execute(&output, map[string]any{
		"Client": map[string]string{"Name": "Example"}, "Scope": []string{},
		"FormPostURI": "/authorize/decision", "Year": 2026,
	}))
	require.Contains(t, output.String(), "No specific scopes requested.")
	require.NotContains(t, output.String(), `<ul class="scope-list"`)
}

// Keep the redesign presentation-only: these headings, explanations, warnings,
// and dynamic values are part of the existing deployed demo's information.
func TestDeployedDemoInformationPreserved(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		want   []string
	}{
		{"index", DEFAULT_HTML_TEMPLATE_INDEX, []string{
			"go-oidc-provider Demo", "A simple demonstration of the OpenID Connect authentication flow",
			"Ready to test the flow?", "This demo uses the following OIDC parameters:",
			"{{ .OIDCRequest }}", "{{ .LoginURL }}", "Start OIDC Login",
			"This is a development / demonstration client only.", "Do not use in production without proper security review.",
		}},
		{"success", DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS, []string{
			"Authentication Successful ✓", "You're in!", "You have successfully authenticated with the OIDC provider.",
			"Here's the response data we received:", "{{ .OIDCResponse }}",
			"If you want to interact further with the OIDC provider, you can now use the obtained tokens or the following client credentials:",
			"Client ID:", "{{ .ClientID }}", "Client Secret:", "{{ .ClientSecret }}",
			"You can safely close this window now.", "Back to Home",
		}},
		{"error", DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR, []string{
			"Authentication Failed ✗", "Something went wrong...", "An error occurred during authentication with the OIDC provider.",
			"Here's the error/response data we received:", "{{ .OIDCResponse }}",
			"You can safely close this window, or try again.", "Back to Home",
		}},
		{"login", provider.DEFAULT_LOGIN_TEMPLATE, []string{
			"Sign In", "Enter <code>test@example.com</code> as e-mail address to proceed with the OIDC demo",
			"Email address", "This is a demo login — no password required.",
			"A magic link token is automatically created and provided in the next step.", "{{ .FormPostURI }}",
		}},
		{"verification", provider.DEFAULT_MAGIC_LINK_TEMPLATE, []string{
			"Verify Magic Link", "Verify Your Email",
			"Normally a magic link is sent to your (real) e-mail address—for demo purposes it is auto-filled here.",
			"Click it to sign in — or paste the token below if needed.", "Paste token here...",
			"{{ .Token }}", "{{ .ID }}", "{{ .FormPostURI }}", "Verify &amp; Sign In",
			"The magic link token sending mechanism is not implemented in this demo, nor is there a sample implementation available in the source code repository.",
			"Back to home", "if you need to start over.",
		}},
		{"consent", provider.DEFAULT_AUTHORIZATION_TEMPLATE, []string{
			"Authorization Request", "{{ .Client.Name }}", "wants to access your account",
			"to perform actions on your behalf according to the permissions below.", "Requested permissions (scopes):",
			"No specific scopes requested.", "{{ .FormPostURI }}", "Approve", "Deny",
			"Only approve if you trust this application.", "You can revoke access later in your account settings.",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, want := range test.want {
				require.Contains(t, test.source, want)
			}
			require.Contains(t, test.source, "{{ .Year }}")
			require.Contains(t, test.source, "Sascha Zarhuber")
			require.Contains(t, test.source, `href="https://sascha.work"`)
		})
	}
}
