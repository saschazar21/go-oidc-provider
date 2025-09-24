package utils

import (
	"time"

	"github.com/go-playground/validator/v10"
)

const (
	ACR_VALUE     = "acr"
	AMR_VALUE     = "amr"
	AUTH_METHOD   = "auth-method"
	AUTH_STATUS   = "auth-status"
	DATE          = "date"
	GRANT_TYPE    = "grant-type"
	PKCE_METHOD   = "pkce-method"
	PROMPT        = "prompt"
	RESPONSE_TYPE = "response-type"
	RESULT        = "result"
	SCOPE         = "scope"
	TIME_GT_NOW   = "time-gt-now"
	TIME_LT_NOW   = "time-lt-now"
	TIME_GTE_NOW  = "time-gte-now"
	TIME_LTE_NOW  = "time-lte-now"
	TOKEN_TYPE    = "token-type"
)

var _customValidator *validator.Validate

func NewCustomValidator() *validator.Validate {
	if _customValidator == nil {
		_customValidator = validator.New()
		_customValidator.RegisterValidation(ACR_VALUE, validateACR)
		_customValidator.RegisterValidation(AMR_VALUE, validateAMR)
		_customValidator.RegisterValidation(AUTH_METHOD, validateAuthMethod)
		_customValidator.RegisterValidation(AUTH_STATUS, validateAuthStatus)
		_customValidator.RegisterValidation(DATE, validateDate)
		_customValidator.RegisterValidation(GRANT_TYPE, validateGrantType)
		_customValidator.RegisterValidation(PKCE_METHOD, validatePKCEMethod)
		_customValidator.RegisterValidation(PROMPT, validatePrompt)
		_customValidator.RegisterValidation(RESPONSE_TYPE, validateResponseType)
		_customValidator.RegisterValidation(RESULT, validateResult)
		_customValidator.RegisterValidation(SCOPE, validateScope)
		_customValidator.RegisterValidation(TIME_GT_NOW, validateTimeGtNow)
		_customValidator.RegisterValidation(TIME_LT_NOW, validateTimeLtNow)
		_customValidator.RegisterValidation(TIME_GTE_NOW, validateTimeGteNow)
		_customValidator.RegisterValidation(TIME_LTE_NOW, validateTimeLteNow)
		_customValidator.RegisterValidation(TOKEN_TYPE, validateTokenType)
	}

	return _customValidator
}

func validateACR(fl validator.FieldLevel) bool {
	acr, ok := fl.Field().Interface().(ACR)
	if !ok {
		return false
	}

	validACRs := []ACR{
		ACR_BRONZE,
		ACR_SILVER,
		ACR_GOLD,
	}

	for _, validACR := range validACRs {
		if acr == validACR {
			return true
		}
	}
	return false
}

func validateAMR(fl validator.FieldLevel) bool {
	amr, ok := fl.Field().Interface().(AMR)
	if !ok {
		return false
	}

	validAMRs := []AMR{
		AMR_PASSWORD,
		AMR_OTP,
		AMR_MULTIFACTOR,
		AMR_SMS,
		AMR_EMAIL,
		AMR_PUSH,
		AMR_FIDO,
		AMR_BIOMETRIC,
	}

	for _, validAMR := range validAMRs {
		if amr == validAMR {
			return true
		}
	}
	return false
}

func validateAuthMethod(fl validator.FieldLevel) bool {
	authMethod, ok := fl.Field().Interface().(AuthMethod)
	if !ok {
		return false
	}

	validAuthMethods := []AuthMethod{
		CLIENT_SECRET_BASIC,
		CLIENT_SECRET_POST,
		CLIENT_SECRET_JWT,
		PRIVATE_KEY_JWT,
		TLS_CLIENT_AUTH,
		SELF_SIGNED_TLS_CLIENT_AUTH,
		AUTH_METHOD_NONE,
	}
	for _, validAuthMethod := range validAuthMethods {
		if authMethod == validAuthMethod {
			return true
		}
	}
	return false
}

func validateAuthStatus(fl validator.FieldLevel) bool {
	authStatus, ok := fl.Field().Interface().(AuthStatus)
	if !ok {
		return false
	}

	validAuthStatuses := []AuthStatus{
		APPROVED,
		PENDING,
		DENIED,
		REVOKED,
	}

	for _, validAuthStatus := range validAuthStatuses {
		if authStatus == validAuthStatus {
			return true
		}
	}
	return false
}

func validateDate(fl validator.FieldLevel) bool {
	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return true
	case *time.Time:
		if t == nil {
			return false
		}
		return true
	case string:
		_, err := time.Parse(DEFAULT_DATE_FORMAT, t)
		if err != nil {
			return false
		}
		return true
	case *string:
		if t == nil {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, *t)
		if err != nil {
			return false
		}
		return true
	case EncryptedString:
		if t == "" {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, string(t))
		if err != nil {
			return false
		}
		return true
	case *EncryptedString:
		if t == nil {
			return false
		}
		if *t == "" {
			return false
		}
		_, err := time.Parse(DEFAULT_DATE_FORMAT, string(*t))
		if err != nil {
			return false
		}
		return true
	default:
		return false
	}
}

func validateGrantType(fl validator.FieldLevel) bool {
	grantType, ok := fl.Field().Interface().(GrantType)
	if !ok {
		return false
	}

	validGrantTypes := []GrantType{
		AUTHORIZATION_CODE,
		IMPLICIT,
		CLIENT_CREDENTIALS,
		REFRESH_TOKEN,
		DEVICE_CODE,
		JWT_BEARER,
		CIBA,
	}

	for _, validGrantType := range validGrantTypes {
		if grantType == validGrantType {
			return true
		}
	}
	return false
}

func validateResponseType(fl validator.FieldLevel) bool {
	responseType, ok := fl.Field().Interface().(ResponseType)
	if !ok {
		return false
	}

	validResponseTypes := []ResponseType{
		CODE,
		TOKEN,
		ID_TOKEN,
		CODE_TOKEN,
		CODE_ID_TOKEN,
		ID_TOKEN_TOKEN,
		CODE_ID_TOKEN_TOKEN,
		FORM_POST,
	}

	for _, validResponseType := range validResponseTypes {
		if responseType == validResponseType {
			return true
		}
	}
	return false
}

func validateResult(fl validator.FieldLevel) bool {
	result, ok := fl.Field().Interface().(Result)
	if !ok {
		return false
	}

	validResults := []Result{
		SUCCESS,
		FAILED,
		EXPIRED,
	}

	for _, validResult := range validResults {
		if result == validResult {
			return true
		}
	}
	return false
}

func validateScope(fl validator.FieldLevel) bool {
	scope, ok := fl.Field().Interface().(Scope)
	if !ok {
		return false
	}

	validScopes := []Scope{
		OPENID,
		PROFILE,
		EMAIL,
		PHONE,
		ADDRESS,
		READ,
		WRITE,
		UPDATE,
		DELETE,
		OFFLINE_ACCESS,
	}

	for _, validScope := range validScopes {
		if scope == validScope {
			return true
		}
	}
	return false
}

func validatePKCEMethod(fl validator.FieldLevel) bool {
	pkceMethod, ok := fl.Field().Interface().(PKCEMethod)
	if !ok {
		return false
	}

	validPKCEMethods := []PKCEMethod{
		S256,
		PKCE_NONE,
	}

	for _, validPKCEMethod := range validPKCEMethods {
		if pkceMethod == validPKCEMethod {
			return true
		}
	}
	return false
}

func validatePrompt(fl validator.FieldLevel) bool {
	prompt, ok := fl.Field().Interface().(Prompt)
	if !ok {
		return false
	}

	validPrompts := []Prompt{
		NONE,
		LOGIN,
		CONSENT,
		SELECT_ACCOUNT,
	}

	for _, validPrompt := range validPrompts {
		if prompt == validPrompt {
			return true
		}
	}
	return false
}

func validateTimeGtNow(fl validator.FieldLevel) bool {
	now := time.Now().UTC()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.After(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).After(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.After(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.After(now)
	case EncryptedDate:
		return t.Time.After(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.After(now)
	case Epoch:
		return time.Time(t).After(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return time.Time(*t).After(now)
	case EpochMillis:
		return time.Time(t).After(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return time.Time(*t).After(now)
	default:
		return false
	}
}

func validateTimeLtNow(fl validator.FieldLevel) bool {
	now := time.Now().UTC()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Before(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Before(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Before(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Before(now)
	case EncryptedDate:
		return t.Time.Before(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Before(now)
	case Epoch:
		return time.Time(t).Before(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return time.Time(*t).Before(now)
	case EpochMillis:
		return time.Time(t).Before(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return time.Time(*t).Before(now)
	default:
		return false
	}
}

func validateTimeGteNow(fl validator.FieldLevel) bool {
	now := time.Now().UTC()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Equal(now) || t.After(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Equal(now) || (*t).After(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.After(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.After(now)
	case EncryptedDate:
		return t.Time.Equal(now) || t.Time.After(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.After(now)
	case Epoch:
		return time.Time(t).Equal(now) || time.Time(t).After(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return time.Time(*t).Equal(now) || time.Time(*t).After(now)
	case EpochMillis:
		return time.Time(t).Equal(now) || time.Time(t).After(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return time.Time(*t).Equal(now) || time.Time(*t).After(now)
	default:
		return false
	}
}

func validateTimeLteNow(fl validator.FieldLevel) bool {
	now := time.Now().UTC()

	switch t := fl.Field().Interface().(type) {
	case time.Time:
		return t.Equal(now) || t.Before(now)
	case *time.Time:
		if t == nil {
			return false
		}
		return (*t).Equal(now) || (*t).Before(now)
	case string:
		ti, err := time.Parse(time.RFC3339, t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.Before(now)
	case *string:
		if t == nil {
			return false
		}
		ti, err := time.Parse(time.RFC3339, *t)
		if err != nil {
			return false
		}
		return ti.Equal(now) || ti.Before(now)
	case EncryptedDate:
		return t.Time.Equal(now) || t.Time.Before(now)
	case *EncryptedDate:
		if t == nil {
			return false
		}
		return t.Time.Equal(now) || t.Time.Before(now)
	case Epoch:
		return time.Time(t).Equal(now) || time.Time(t).Before(now)
	case *Epoch:
		if t == nil {
			return false
		}
		return time.Time(*t).Equal(now) || time.Time(*t).Before(now)
	case EpochMillis:
		return time.Time(t).Equal(now) || time.Time(t).Before(now)
	case *EpochMillis:
		if t == nil {
			return false
		}
		return time.Time(*t).Equal(now) || time.Time(*t).Before(now)
	default:
		return false
	}
}

func validateTokenType(fl validator.FieldLevel) bool {
	tokenType, ok := fl.Field().Interface().(TokenType)
	if !ok {
		return false
	}

	validTokenTypes := []TokenType{
		AUTHORIZATION_CODE_TYPE,
		ACCESS_TOKEN_TYPE,
		REFRESH_TOKEN_TYPE,
		CLIENT_CREDENTIALS_TYPE,
	}

	for _, validTokenType := range validTokenTypes {
		if tokenType == validTokenType {
			return true
		}
	}
	return false
}
