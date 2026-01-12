package endpoints

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/saschazar21/go-oidc-demo/oidc"
	"github.com/saschazar21/go-oidc-provider/errors"
)

type CallbackTemplateData struct {
	Year         int
	OIDCResponse string
	ClientID     string
	ClientSecret string
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

	oidcResponse, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		log.Printf("failed to marshal callback data: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	callbackData := CallbackTemplateData{
		Year:         time.Now().UTC().Year(),
		OIDCResponse: string(oidcResponse),
	}

	if res, ok := data.(oidc.HasOIDCClientCredentials); ok {
		callbackData.ClientID = res.GetClientID()
		callbackData.ClientSecret = res.GetClientSecret()
	}

	err = tpl.Execute(w, callbackData)
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
			descr := "Malformatted error response"
			oidcErr = oidc.OIDCErrorResponse{
				ID:               string(errors.SERVER_ERROR),
				ErrorDescription: &descr,
			}
			renderCallbackTemplate(w, oidcErr)
			return
		}
		log.Printf("received OIDC error response: %v", oidcErr)
		renderCallbackTemplate(w, oidcErr)
		return
	}

	var res oidc.OIDCAuthorizationResponse
	err := oidc.ParseCallbackRequest(r, &res)
	if err != nil {
		log.Printf("failed to parse callback request: %v", err)
		descr := "Malformatted callback request"
		oidcErr := oidc.OIDCErrorResponse{
			ID:               string(errors.INVALID_REQUEST),
			ErrorDescription: &descr,
		}
		renderCallbackTemplate(w, oidcErr)
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
			descr := "State mismatch"
			oidcErr := oidc.OIDCErrorResponse{
				ID:               string(errors.INVALID_REQUEST),
				ErrorDescription: &descr,
			}
			renderCallbackTemplate(w, oidcErr)
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
