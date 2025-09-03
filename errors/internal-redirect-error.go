package errors

import (
	"fmt"
	"net/http"
)

type InternalRedirectError struct {
	StatusCode int    `json:"-" schema:"-" validate:"required,eq=302|eq=303|eq=307|eq=308"`
	Location   string `json:"location" schema:"location" validate:"required,url"`
}

func (e InternalRedirectError) Error() string {
	return fmt.Sprintf("%d Redirect to: %s", e.StatusCode, e.Location)
}

func (e InternalRedirectError) Code() int {
	return e.StatusCode
}

func (e InternalRedirectError) Write(w http.ResponseWriter) {
	w.Header().Set("Location", e.Location)
	w.WriteHeader(e.StatusCode)
	w.Write([]byte(fmt.Sprintf("<html><body><script>window.location.href='%s';</script><a href='%s'>Back to %s</a></body></html>", e.Location, e.Location, e.Location)))
}
