package endpoints

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/saschazar21/go-oidc-demo/oidc"
)

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
