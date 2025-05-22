package errors

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

type HTTPError interface {
	Error() string
	Code() int
	Write(w http.ResponseWriter)
}

type HTTPErrorResponse struct {
	StatusCode  int    `validate:"required,min=100,max=599"`
	Message     string `validate:"required"`
	Description string
	RedirectURI string `validate:"omitempty,http_url"`
	Template    string
}

func (e HTTPErrorResponse) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Description)
	}
	return e.Message
}

func (e HTTPErrorResponse) Code() int {
	return e.StatusCode
}

func (e HTTPErrorResponse) Write(w http.ResponseWriter) {
	if e.Template == "" {
		e.Template = DEFAULT_HTML_ERROR_TEMPLATE
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(e.StatusCode)

	tmpl, err := template.New("error").Parse(e.Template)

	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	if err = tmpl.Execute(w, e); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}
}
