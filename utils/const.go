package utils

const (
	COOKIE_AUTH_KEY_ENV = "COOKIE_AUTH_KEY"
	COOKIE_ENC_KEY_ENV  = "COOKIE_ENC_KEY"
	MASTER_KEY_ENV      = "MASTER_KEY"

	DEFAULT_DATE_FORMAT = "2006-01-02"
)

const (
	ACR_BRONZE ACR = "urn:mace:incommon:iap:bronze"
	ACR_SILVER ACR = "urn:mace:incommon:iap:silver"
	ACR_GOLD   ACR = "urn:mace:incommon:iap:gold"
)

const (
	AMR_PASSWORD    AMR = "pwd"
	AMR_OTP         AMR = "otp"
	AMR_MULTIFACTOR AMR = "mfa"
	AMR_SMS         AMR = "sms"
	AMR_EMAIL       AMR = "email"
	AMR_PUSH        AMR = "push"
	AMR_FIDO        AMR = "fido"
	AMR_BIOMETRIC   AMR = "biometric"
)

const (
	CLIENT_SECRET_BASIC         AuthMethod = "client_secret_basic"
	CLIENT_SECRET_POST          AuthMethod = "client_secret_post"
	CLIENT_SECRET_JWT           AuthMethod = "client_secret_jwt"
	PRIVATE_KEY_JWT             AuthMethod = "private_key_jwt"
	TLS_CLIENT_AUTH             AuthMethod = "tls_client_auth"
	SELF_SIGNED_TLS_CLIENT_AUTH AuthMethod = "self_signed_tls_client_auth"
	AUTH_METHOD_NONE            AuthMethod = "none"
)

const (
	APPROVED AuthStatus = "approved"
	PENDING  AuthStatus = "pending"
	DENIED   AuthStatus = "denied"
	REVOKED  AuthStatus = "revoked"
)

const (
	AUTHORIZATION_CODE GrantType = "authorization_code"
	IMPLICIT           GrantType = "implicit"
	CLIENT_CREDENTIALS GrantType = "client_credentials"
	REFRESH_TOKEN      GrantType = "refresh_token"
	DEVICE_CODE        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	JWT_BEARER         GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	CIBA               GrantType = "urn:openid:params:grant-type:ciba"
)

const (
	S256      PKCEMethod = "S256"
	PKCE_NONE PKCEMethod = "none"
)

const (
	CODE                ResponseType = "code"
	TOKEN               ResponseType = "token"
	ID_TOKEN            ResponseType = "id_token"
	CODE_TOKEN          ResponseType = "code token"
	CODE_ID_TOKEN       ResponseType = "code id_token"
	ID_TOKEN_TOKEN      ResponseType = "id_token token"
	CODE_ID_TOKEN_TOKEN ResponseType = "code id_token token"
	FORM_POST           ResponseType = "form_post"
)

const (
	SUCCESS Result = "success"
	FAILED  Result = "failed"
	EXPIRED Result = "expired"
)

const (
	OPENID         Scope = "openid"
	PROFILE        Scope = "profile"
	EMAIL          Scope = "email"
	PHONE          Scope = "phone"
	ADDRESS        Scope = "address"
	READ           Scope = "read"
	WRITE          Scope = "write"
	UPDATE         Scope = "update"
	DELETE         Scope = "delete"
	OFFLINE_ACCESS Scope = "offline_access"
)

const (
	AUTHORIZATION_CODE_TYPE TokenType = "authorization_code"
	ACCESS_TOKEN_TYPE       TokenType = "access_token"
	REFRESH_TOKEN_TYPE      TokenType = "refresh_token"
	CLIENT_CREDENTIALS_TYPE TokenType = "client_credentials"
	CUSTOM_TOKEN_TYPE       string    = "custom_token"
)
