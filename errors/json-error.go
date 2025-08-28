package errors

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/utils"
)

type JSONError struct {
	ErrorCode   OIDCErrorCode `json:"error" validate:"required"`
	Description *string       `json:"error_description,omitempty"`
	URI         *string       `json:"error_uri,omitempty" validate:"omitempty,uri"`

	StatusCode int `json:"-"`
}

func (e JSONError) Error() (err string) {
	err = string(e.ErrorCode)

	if e.Description != nil && *e.Description != "" {
		err += ": " + *e.Description
	}

	if e.URI != nil && *e.URI != "" {
		err += " (More info: " + *e.URI + ")"
	}

	return
}

func (e JSONError) Code() int {
	return e.StatusCode
}

func (e JSONError) Write(w http.ResponseWriter) {
	validate := utils.NewCustomValidator()
	if err := validate.Struct(e); err != nil {
		log.Printf("Error validating JSON Error: %v", err)
		err := HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "An error occurred while processing the request.",
		}

		err.Write(w)
		return
	}

	response := e

	enc, err := json.Marshal(response)

	if err != nil {
		log.Printf("Error encoding JSON Error response: %v", err)
		err := HTTPErrorResponse{
			StatusCode:  http.StatusInternalServerError,
			Message:     "Internal Server Error",
			Description: "An error occurred while processing the request.",
		}

		err.Write(w)
		return
	}

	if e.StatusCode < 100 {
		e.StatusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(e.StatusCode)
	w.Write(enc)
}
