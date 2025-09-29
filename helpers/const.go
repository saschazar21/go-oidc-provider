package helpers

const (
	JWKS_ENDPOINT                 = "/.well-known/jwks.json"
	OPENID_CONFIGURATION_ENDPOINT = "/.well-known/openid-configuration"
	AUTHORIZATION_GRANT_ENDPOINT  = "/authorize"
	TOKEN_ENDPOINT                = "/token"
	USERINFO_ENDPOINT             = "/userinfo"

	LOGIN_ENDPOINT  = "/login"
	LOGOUT_ENDPOINT = "/logout"

	AUTHORIZATION_COOKIE_NAME = "authorization"
	AUTHORIZATION_COOKIE_ID   = "id"
	MAGIC_LINK_COOKIE_NAME    = "magic_link"
	MAGIC_LINK_ID             = "id"
	MAGIC_LINK_EMAIL          = "email"
	SESSION_COOKIE_NAME       = "session"
	SESSION_COOKIE_ID         = "id"
)
