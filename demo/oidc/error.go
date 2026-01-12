package oidc

type OIDCErrorResponse struct {
	ID               string  `json:"error" schema:"error"`
	ErrorDescription *string `json:"error_description" schema:"error_description,omitempty"`
	ErrorURI         *string `json:"error_uri,omitempty" schema:"error_uri,omitempty"`
	State            *string `json:"state,omitempty" schema:"state,omitempty"`
}

func (e OIDCErrorResponse) Error() string {
	err := "OIDCErrorResponse{" +
		"Error: " + e.ID

	if e.ErrorDescription != nil {
		err += ", ErrorDescription: " + *e.ErrorDescription
	}

	if e.ErrorURI != nil {
		err += ", ErrorURI: " + *e.ErrorURI
	}

	if e.State != nil {
		err += ", State: " + *e.State
	}

	err += "}"

	return err
}

func NewOIDCErrorResponse(id string, description ...string) *OIDCErrorResponse {
	var descPtr *string
	if len(description) > 0 {
		descPtr = &description[0]
	}
	return &OIDCErrorResponse{
		ID:               id,
		ErrorDescription: descPtr,
	}
}
