package oidc

type OIDCErrorResponse struct {
	ID               string `json:"error" schema:"error"`
	ErrorDescription string `json:"error_description" schema:"error_description"`
}

func (e OIDCErrorResponse) Error() string {
	return "oidcErrorResponse{" +
		"Error: " + e.ID +
		", ErrorDescription: " + e.ErrorDescription +
		"}"
}

func NewOIDCErrorResponse(id, description string) *OIDCErrorResponse {
	return &OIDCErrorResponse{
		ID:               id,
		ErrorDescription: description,
	}
}
