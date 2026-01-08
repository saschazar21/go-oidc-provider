package endpoints

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/saschazar21/go-oidc-demo/oidc"
)

const DEFAULT_HTML_TEMPLATE_INDEX = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>OIDC Client</title>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gardevoir" />
</head>
<body>
		<header>
			<h1>Welcome to the OIDC Provider/Client demo</h1>
		</header>
		<main>
			<p>Click the link below to initiate the OIDC login flow using the following parameters:</p>
			<br />
			<br />
			<pre><code>{{ .OIDCRequest }}</code></pre>
			<br />
			<br />
			<p><a href="{{ .LoginURL }}">Login with OIDC</a></p>
		</main>
		<hr />
		<footer>
		<p>&copy; {{ .Year }} <a href="https://sascha.work" rel="noopener noreferrer" target="_blank">Sascha Zarhuber</a></p>
		</footer>
</body>
</html>
`

type IndexTemplateData struct {
	Year        int
	LoginURL    string
	OIDCRequest string
}

func HandleIndex(w http.ResponseWriter, r *http.Request) {
	authReq := oidc.NewOIDCAuthorizationRequest()
	authURL := authReq.BuildURL()
	if authURL == "" {
		log.Println("failed to build authorization URL, check previous logs for details")
		http.Error(w, "Failed to build authorization URL", http.StatusInternalServerError)
		return
	}

	requestData, err := json.MarshalIndent(authReq, "", "    ")
	if err != nil {
		log.Printf("failed to marshal authorization request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := IndexTemplateData{
		Year:        time.Now().UTC().Year(),
		LoginURL:    authURL,
		OIDCRequest: string(requestData),
	}

	tpl := template.New("index").Funcs(template.FuncMap{})
	tpl, err = tpl.Parse(DEFAULT_HTML_TEMPLATE_INDEX)
	if err != nil {
		log.Printf("failed to parse template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	oidc.StoreStateCookie(w, authReq.State)

	err = tpl.Execute(w, data)
	if err != nil {
		log.Printf("failed to execute template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
