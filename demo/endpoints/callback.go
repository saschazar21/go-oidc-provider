package endpoints

import (
	"html/template"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-demo/oidc"
)

const DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>OIDC Authentication Success</title>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gardevoir" />
</head>
<body>
		<header>
			<h1>OIDC Authentication successful!</h1>
		</header>
		<main>
			<p>You have successfully authenticated with the OIDC provider. It responded with the following data:</p>
			<br />
			<br />
			<pre><code>{{ .OIDCResponse }}</code></pre>
			<br />
			<br />
			<p>You can close this window now, or start over again on the <a href="/">home page</a>.</p>
		</main>
		<hr />
		<footer>
		<p>&copy; {{ .Year }} <a href="https://sascha.work" rel="noopener noreferrer" target="_blank">Sascha Zarhuber</a></p>
		</footer>
</body>
</html>
`

const DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>OIDC Authentication Error</title>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gardevoir" />
</head>
<body>
		<header>
			<h1>OIDC Authentication failed!</h1>
		</header>
		<main>
			<p>An error occurred during authentication with the OIDC provider. It responded with the following data:</p>
			<br />
			<br />
			<pre><code>{{ .OIDCResponse }}</code></pre>
			<br />
			<br />
			<p>You can close this window now, or start over again on the <a href="/">home page</a>.</p>
		</main>
		<hr />
		<footer>
		<p>&copy; {{ .Year }} <a href="https://sascha.work" rel="noopener noreferrer" target="_blank">Sascha Zarhuber</a></p>
		</footer>
</body>
</html>
`

type CallbackTemplateData struct {
	Year         int
	OIDCResponse string
}

func renderCallbackTemplate(w http.ResponseWriter, data interface{}) {
	var tpl *template.Template
	var err error

	switch data.(type) {
	case oidc.OIDCErrorResponse:
		w.WriteHeader(http.StatusBadRequest)
		tpl = template.New("callback_error").Funcs(template.FuncMap{})
		tpl, err = tpl.Parse(DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR)
	default:
		tpl = template.New("callback_success").Funcs(template.FuncMap{})
		tpl, err = tpl.Parse(DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS)
	}

	if err != nil {
		log.Printf("failed to parse callback template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tpl.Execute(w, data)
	if err != nil {
		log.Printf("failed to execute callback template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	if query.Get("error") != "" {
		var oidcErr oidc.OIDCErrorResponse
		err := oidc.ParseCallbackRequest(r, &oidcErr)
		if err != nil {
			log.Printf("failed to parse error callback request: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		log.Printf("received OIDC error response: %v", oidcErr)
		renderCallbackTemplate(w, err)
		return
	}

	var res oidc.OIDCAuthorizationResponse
	err := oidc.ParseCallbackRequest(r, &res)
	if err != nil {
		log.Printf("failed to parse callback request: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("received OIDC authorization response: %v", res)

	if res.State != "" {
		var state string
		cookies := r.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == oidc.COOKIE_STATE_NAME {
				state = cookie.Value
				break
			}
		}

		if state == "" || state != res.State {
			log.Printf("state mismatch: expected %v, got %v", state, res.State)
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}
	}

	oidc.DeleteStateCookie(w)

	tokenReq := oidc.NewOIDCTokenRequest(res.Code)
	tokenRes, err := tokenReq.ExchangeCode()
	if err != nil {
		log.Printf("failed to exchange code for token: %v", err)
		oidcErr, ok := err.(*oidc.OIDCErrorResponse)
		if ok && oidcErr != nil {
			renderCallbackTemplate(w, *oidcErr)
			return
		}
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	log.Printf("received OIDC token response: %v", tokenRes)
	renderCallbackTemplate(w, tokenRes)
}
