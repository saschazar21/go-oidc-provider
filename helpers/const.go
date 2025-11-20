package helpers

const (
	JWKS_ENDPOINT                   = "/.well-known/jwks.json"
	OPENID_CONFIGURATION_ENDPOINT   = "/.well-known/openid-configuration"
	AUTHORIZATION_DECISION_ENDPOINT = "/authorize/decision"
	AUTHORIZATION_GRANT_ENDPOINT    = "/authorize"
	TOKEN_ENDPOINT                  = "/token"
	TOKEN_INTROSPECTION_ENDPOINT    = "/introspect"
	USERINFO_ENDPOINT               = "/userinfo"

	CONSUME_MAGIC_LINK_ENDPOINT = "/login/magic"
	LOGIN_ENDPOINT              = "/login"
	LOGOUT_ENDPOINT             = "/logout"

	AUTHORIZATION_COOKIE_NAME = "authorization"
	AUTHORIZATION_COOKIE_ID   = "id"
	MAGIC_LINK_COOKIE_NAME    = "magic_link"
	MAGIC_LINK_ID             = "id"
	MAGIC_LINK_EMAIL          = "email"
	REDIRECT_COOKIE_NAME      = "redirect"
	REDIRECT_URI              = "uri"
	SESSION_COOKIE_NAME       = "session"
	SESSION_COOKIE_ID         = "id"

	LOGOUT_REASON_ID_TOKEN_HINT = "ID token hint"
	LOGOUT_REASON_END_SESSION   = "end session endpoint"
	LOGOUT_REASON_USER          = "manual logout"
)
