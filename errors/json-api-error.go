package errors

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/utils"
)

type JSONAPIError struct {
	StatusCode int    `json:"status" validate:"required,min=100,max=599"`
	Title      string `json:"title,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

func (e JSONAPIError) Error() (err string) {
	err = fmt.Sprintf("HTTP Status %d: %s", e.StatusCode, e.Title)

	if e.Detail != "" {
		err += fmt.Sprintf(" - %s", e.Detail)
	}

	return
}

func (e JSONAPIError) Code() int {
	return e.StatusCode
}

func (e JSONAPIError) Write(w http.ResponseWriter) {
	validate := utils.NewCustomValidator()
	if err := validate.Struct(e); err != nil {
		log.Printf("Error validating JSON API Error: %v", err)
		err := HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "An error occurred while processing the request.",
		}

		err.Write(w)
		return
	}

	response := map[string]interface{}{
		"errors": []JSONAPIError{e},
	}

	enc, err := json.Marshal(response)

	if err != nil {
		log.Printf("Error encoding JSON Error response: %v", err)
		err := HTTPErrorResponse{
			StatusCode:  e.StatusCode,
			Message:     e.Title,
			Description: e.Detail,
		}

		err.Write(w)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(e.StatusCode)
	w.Write(enc)
}
