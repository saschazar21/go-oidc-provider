package endpoints

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/utils"
)

const loginBrowserCookie = "login_browser"
const loginFormLimit = 16 << 10
const loginBrowserLifetime = 10 * time.Minute

// LoginHandlers adapts a fixed LoginService policy to browser login. Mount Login
// at /login and MagicLinkToken at /login/magic; do not also mount legacy login
// handlers. Passwords and codes are accepted only in bounded POST form bodies.
type LoginHandlers struct {
	service *helpers.LoginService
	store   sessions.Store
}

// NewLoginHandlers uses store for signed (optionally encrypted) browser cookies.
// Use the same keys/configuration as utils.NewCookieStore: the reference OIDC
// handlers still read cookies through that global store and connect to the DB
// configured in the environment. That DB MUST be the LoginService database.
// For applications with injected DB/store dependencies, wrap their own OIDC
// handlers with Protect instead of using the three reference-handler methods.
func NewLoginHandlers(service *helpers.LoginService, store sessions.Store) (*LoginHandlers, error) {
	if service == nil || len(service.RequiredMethods()) == 0 || store == nil {
		return nil, errors.New("login handlers require a configured service and cookie store")
	}
	v := reflect.ValueOf(store)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return nil, errors.New("login handlers require a cookie store")
	}
	return &LoginHandlers{service: service, store: store}, nil
}

// Protect attaches the configured authentication policy to a custom handler.
// The wrapped handler must enforce the policy using the helpers authorization,
// authorization-decision or token APIs; this is not standalone authentication
// middleware for arbitrary application handlers.
func (h *LoginHandlers) Protect(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, helpers.WithAuthenticationPolicy(r, h.service.RequiredMethods()))
	})
}

// Authorization invokes the environment/global-cookie-store reference endpoint.
func (h *LoginHandlers) Authorization(w http.ResponseWriter, r *http.Request) {
	h.Protect(http.HandlerFunc(HandleAuthorization)).ServeHTTP(w, r)
}

// AuthorizationDecision invokes the environment/global-store reference endpoint.
func (h *LoginHandlers) AuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	h.Protect(http.HandlerFunc(HandleAuthorizationDecision)).ServeHTTP(w, r)
}

// Token invokes the environment/global-cookie-store reference endpoint.
func (h *LoginHandlers) Token(w http.ResponseWriter, r *http.Request) {
	h.Protect(http.HandlerFunc(HandleToken)).ServeHTTP(w, r)
}

func loginHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func loginCookieOptions(maxAge int) *sessions.Options {
	return &sessions.Options{Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// The binding is 32 random bytes plus an authenticated absolute expiry. Keeping
// the expiry inside the opaque binding limits server-side validity even with a
// store whose securecookie codec permits longer-lived cookies. No user data,
// continuation, password, code or authentication evidence lives in this cookie.
func newLoginBinding() (string, error) {
	var data [40]byte
	if _, err := rand.Read(data[:32]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(data[32:], uint64(time.Now().Add(loginBrowserLifetime).Unix()))
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func validBrowserBinding(binding string) bool {
	data, err := base64.RawURLEncoding.DecodeString(binding)
	if err != nil || len(data) != 40 {
		return false
	}
	expiry := binary.BigEndian.Uint64(data[32:])
	now := time.Now().Unix()
	return expiry > uint64(now) && expiry <= uint64(now+int64(loginBrowserLifetime/time.Second))
}

func loginCSRF(binding string) string {
	sum := sha256.Sum256([]byte("oidc-login-csrf-v1:" + binding))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (h *LoginHandlers) browser(r *http.Request) (*sessions.Session, string, uuid.UUID, error) {
	// Reject duplicate cookies rather than relying on header ordering.
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == loginBrowserCookie {
			count++
		}
	}
	if count != 1 {
		return nil, "", uuid.Nil, helpers.ErrLoginRejected
	}
	cookie, err := h.store.Get(r, loginBrowserCookie)
	if err != nil || cookie == nil || cookie.IsNew {
		return nil, "", uuid.Nil, helpers.ErrLoginRejected
	}
	binding, ok := cookie.Values["binding"].(string)
	if !ok || !validBrowserBinding(binding) {
		return nil, "", uuid.Nil, helpers.ErrLoginRejected
	}
	var attempt uuid.UUID
	if value, exists := cookie.Values["attempt"]; exists {
		id, ok := value.(string)
		if !ok {
			return nil, "", uuid.Nil, helpers.ErrLoginRejected
		}
		attempt, err = uuid.Parse(id)
		if err != nil || attempt == uuid.Nil {
			return nil, "", uuid.Nil, helpers.ErrLoginRejected
		}
	}
	return cookie, binding, attempt, nil
}

func parseLoginForm(w http.ResponseWriter, r *http.Request, binding string) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return helpers.ErrLoginRejected
	}
	r.Body = http.MaxBytesReader(w, r.Body, loginFormLimit)
	if err := r.ParseForm(); err != nil {
		return helpers.ErrLoginRejected
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			return helpers.ErrLoginRejected
		}
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(loginCSRF(binding))) != 1 {
		return helpers.ErrLoginRejected
	}
	return nil
}

func loginRemoteIP(r *http.Request) string {
	// Forwarded headers are not trusted. Trusted proxy deployments should rewrite
	// RemoteAddr before invoking these handlers.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// Login renders the fixed policy's form or starts authentication. GET never
// authenticates, even when a session/attempt ID is supplied by the browser.
func (h *LoginHandlers) Login(w http.ResponseWriter, r *http.Request) {
	loginHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cookie, binding, _, err := h.browser(r)
	if r.Method == http.MethodGet {
		if err != nil {
			binding, err = newLoginBinding()
			if err != nil {
				h.render(w, false, "", http.StatusServiceUnavailable, true)
				return
			}
			cookie = sessions.NewSession(h.store, loginBrowserCookie)
			cookie.Values["binding"] = binding
			cookie.Options = loginCookieOptions(int(loginBrowserLifetime / time.Second))
			if err := h.store.Save(r, w, cookie); err != nil {
				h.render(w, false, "", http.StatusServiceUnavailable, true)
				return
			}
		}
		h.render(w, false, binding, http.StatusOK, false)
		return
	}
	if err != nil || parseLoginForm(w, r, binding) != nil || r.PostForm.Get("email") == "" ||
		(h.service.UsesPassword() && r.PostForm.Get("password") == "") {
		h.render(w, false, binding, http.StatusBadRequest, true)
		return
	}
	continuation, err := h.continuation(r)
	if err != nil {
		h.render(w, false, binding, http.StatusBadRequest, true)
		return
	}
	result, err := h.service.Start(r.Context(), helpers.LoginInput{
		Email: r.PostForm.Get("email"), Password: r.PostForm.Get("password"), Binding: binding,
		Continuation: continuation, RemoteIP: loginRemoteIP(r),
	})
	if err != nil {
		h.failure(w, false, binding, err)
		return
	}
	if result != nil && result.Session != nil {
		h.complete(w, r, result)
		return
	}
	if result == nil || result.AttemptID == uuid.Nil {
		h.failure(w, false, binding, errors.New("missing login result"))
		return
	}
	cookie.Values["attempt"] = result.AttemptID.String()
	cookie.Options = loginCookieOptions(int(loginBrowserLifetime / time.Second))
	if err := h.store.Save(r, w, cookie); err != nil {
		h.failure(w, false, binding, err)
		return
	}
	http.Redirect(w, r, helpers.CONSUME_MAGIC_LINK_ENDPOINT, http.StatusSeeOther)
}

// MagicLinkToken verifies/resends a code for the signed browser attempt only.
// Query-string codes/IDs and posted attempt IDs are never used.
func (h *LoginHandlers) MagicLinkToken(w http.ResponseWriter, r *http.Request) {
	loginHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	emailEnabled := false
	for _, method := range h.service.RequiredMethods() {
		emailEnabled = emailEnabled || method == utils.AMR_EMAIL
	}
	if !emailEnabled {
		h.render(w, true, "", http.StatusBadRequest, true)
		return
	}
	_, binding, attempt, err := h.browser(r)
	if err != nil || attempt == uuid.Nil {
		h.render(w, true, "", http.StatusBadRequest, true)
		return
	}
	if r.Method == http.MethodGet {
		h.render(w, true, binding, http.StatusOK, false)
		return
	}
	if parseLoginForm(w, r, binding) != nil {
		h.render(w, true, binding, http.StatusBadRequest, true)
		return
	}
	input := helpers.CodeInput{AttemptID: attempt, Binding: binding, Code: r.PostForm.Get("code"), RemoteIP: loginRemoteIP(r)}
	if r.PostForm.Get("action") == "resend" {
		_, err := h.service.Resend(r.Context(), input)
		if err != nil {
			h.failure(w, true, binding, err)
			return
		}
		h.render(w, true, binding, http.StatusOK, false)
		return
	}
	if action := r.PostForm.Get("action"); (action != "" && action != "verify") || input.Code == "" {
		h.render(w, true, binding, http.StatusBadRequest, true)
		return
	}
	result, err := h.service.VerifyCode(r.Context(), input)
	if err != nil {
		h.failure(w, true, binding, err)
		return
	}
	h.complete(w, r, result)
}

func safeHandlerContinuation(value string) bool {
	decoded := value
	for i := 0; i < 8; i++ {
		if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") ||
			strings.Contains(decoded, "\\") || strings.ContainsFunc(decoded, unicode.IsControl) {
			return false
		}
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return false
		}
		if next == decoded {
			u, err := url.Parse(value)
			return err == nil && !u.IsAbs() && u.Host == "" && u.Opaque == ""
		}
		decoded = next
	}
	return false
}

func (h *LoginHandlers) continuation(r *http.Request) (string, error) {
	if _, err := r.Cookie(helpers.AUTHORIZATION_COOKIE_NAME); err == nil {
		cookie, err := h.store.Get(r, helpers.AUTHORIZATION_COOKIE_NAME)
		if err != nil || cookie == nil || cookie.IsNew {
			return "", helpers.ErrLoginRejected
		}
		id, ok := cookie.Values[helpers.AUTHORIZATION_COOKIE_ID].(string)
		if ok && id != "" {
			if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
				return "", helpers.ErrLoginRejected
			}
			return helpers.AUTHORIZATION_GRANT_ENDPOINT, nil
		}
	}
	if cookie, err := r.Cookie(helpers.REDIRECT_COOKIE_NAME); err == nil {
		if !safeHandlerContinuation(cookie.Value) {
			return "", helpers.ErrLoginRejected
		}
		return cookie.Value, nil
	}
	return "/", nil
}

// Stage cookie writes so encoding/clearing failure cannot emit a partial login.
type loginCookieWriter struct{ header http.Header }

func (w *loginCookieWriter) Header() http.Header         { return w.header }
func (w *loginCookieWriter) WriteHeader(int)             {}
func (w *loginCookieWriter) Write(p []byte) (int, error) { return len(p), nil }

func (h *LoginHandlers) complete(w http.ResponseWriter, r *http.Request, result *helpers.LoginResult) {
	if result == nil || result.Session == nil || result.Session.ID == uuid.Nil ||
		result.Session.UserID == uuid.Nil || !safeHandlerContinuation(result.Continuation) {
		h.failure(w, false, "", errors.New("invalid completed login"))
		return
	}
	maxAge := int(time.Until(result.Session.ExpiresAt.ExpiresAt).Seconds())
	if maxAge <= 0 {
		h.failure(w, false, "", errors.New("expired completed login"))
		return
	}
	// Never load/merge the old session cookie: a tampered cookie is not evidence,
	// and a completed coordinator transaction is the sole source of this ID.
	cookie := sessions.NewSession(h.store, helpers.SESSION_COOKIE_NAME)
	cookie.Values[helpers.SESSION_COOKIE_ID] = result.Session.ID.String()
	cookie.Options = loginCookieOptions(maxAge)
	staged := &loginCookieWriter{header: make(http.Header)}
	if err := h.store.Save(r, staged, cookie); err != nil {
		h.failure(w, false, "", err)
		return
	}
	pending := sessions.NewSession(h.store, loginBrowserCookie)
	pending.Options = loginCookieOptions(-1)
	if err := h.store.Save(r, staged, pending); err != nil {
		h.failure(w, false, "", err)
		return
	}
	for _, value := range staged.Header().Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", value)
	}
	http.SetCookie(w, &http.Cookie{Name: helpers.REDIRECT_COOKIE_NAME, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, result.Continuation, http.StatusSeeOther)
}

func (h *LoginHandlers) failure(w http.ResponseWriter, magic bool, binding string, err error) {
	status := http.StatusServiceUnavailable
	if errors.Is(err, helpers.ErrLoginRejected) {
		status = http.StatusBadRequest
	}
	h.render(w, magic, binding, status, true)
}

var configuredLoginTemplate = template.Must(template.New("configured-login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in</title></head>
<body><main><h1>Sign in</h1>{{if .Error}}<p role="alert">Login could not be completed. Please try again.</p>{{end}}
<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Magic}}<label>Email code <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
<button type="submit" name="action" value="verify">Verify code</button><button type="submit" name="action" value="resend" formnovalidate>Resend code</button>
{{else}}<label>Email <input type="email" name="email" autocomplete="username" maxlength="320" required></label>
{{if .Password}}<label>Password <input type="password" name="password" autocomplete="current-password" required></label>{{end}}
<button type="submit">Continue</button>{{end}}</form></main></body></html>`))

func (h *LoginHandlers) render(w http.ResponseWriter, magic bool, binding string, status int, failed bool) {
	action := helpers.LOGIN_ENDPOINT
	if magic {
		action = helpers.CONSUME_MAGIC_LINK_ENDPOINT
	}
	w.WriteHeader(status)
	// The fixed template only writes strings/bools to an HTTP response. No
	// request-supplied password, code, email or error details are rendered.
	_ = configuredLoginTemplate.Execute(w, struct {
		Action, CSRF           string
		Magic, Password, Error bool
	}{action, loginCSRF(binding), magic, h.service.UsesPassword(), failed})
}
