package errors

const (
	ACCESS_DENIED              OIDCErrorCode = "access_denied"
	ACCOUNT_SELECTION_REQUIRED OIDCErrorCode = "account_selection_required"
	CONSENT_REQUIRED           OIDCErrorCode = "consent_required"
	INTERACTION_REQUIRED       OIDCErrorCode = "interaction_required"
	INVALID_CLIENT             OIDCErrorCode = "invalid_client"
	INVALID_REQUEST            OIDCErrorCode = "invalid_request"
	INVALID_REQUEST_OBJECT     OIDCErrorCode = "invalid_request_object"
	INVALID_REQUEST_URI        OIDCErrorCode = "invalid_request_uri"
	INVALID_SCOPE              OIDCErrorCode = "invalid_scope"
	LOGIN_REQUIRED             OIDCErrorCode = "login_required"
	REGISTRATION_NOT_SUPPORTED OIDCErrorCode = "registration_not_supported"
	REQUEST_NOT_SUPPORTED      OIDCErrorCode = "request_not_supported"
	REQUEST_URI_NOT_SUPPORTED  OIDCErrorCode = "request_uri_not_supported"
	SERVER_ERROR               OIDCErrorCode = "server_error"
	TEMPORARILY_UNAVAILABLE    OIDCErrorCode = "temporarily_unavailable"
	UNSUPPORTED_RESPONSE_TYPE  OIDCErrorCode = "unsupported_response_type"
)

const (
	BAD_REQUEST           = "Bad Request"
	UNAUTHORIZED          = "Unauthorized"
	FORBIDDEN             = "Forbidden"
	NOT_FOUND             = "Not Found"
	METHOD_NOT_ALLOWED    = "Method Not Allowed"
	INTERNAL_SERVER_ERROR = "Internal Server Error"
)

const (
	DEFAULT_HTML_ERROR_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HTTP Status {{.StatusCode}}: {{.Message}}</title>
</head>
<body>
		<h1>HTTP Status {{.StatusCode}}: {{.Message}}</h1>
		{{if .Description}}
		<p>{{.Description}}</p>
		{{end}}
		{{if .RedirectURI}}
		<a href="{{.RedirectURI}}">Back to {{.RedirectURI}}</a>
		{{end}}
</body>
</html>`
)
