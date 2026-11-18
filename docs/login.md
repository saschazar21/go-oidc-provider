# Configured browser login (0.2.0, unreleased)

The main APIs are in [helpers/login.go](../helpers/login.go), [helpers/login_strategy.go](../helpers/login_strategy.go), and [endpoints/login_handlers.go](../endpoints/login_handlers.go). Policy is immutable and selected **per provider instance**, not by a client, user, or browser request.

| Mode | `LoginConfig.Strategy` | `RequireEmail` | Completed AMR |
| --- | --- | --- | --- |
| Email code only | `helpers.EmailCodeStrategy()` | `false` (email is implicit) | `email` |
| Password only | `helpers.PasswordStrategy()` | `false` | `pwd` |
| Password then email code | `helpers.PasswordStrategy()` | `true` | `pwd`, `email` |

A nil strategy defaults to email-code-only. Email flows require an injected `EmailCodeSender` and a `ChallengeKey` containing at least **32 random bytes**. Every mode requires a non-nil `LoginLimiter`; errors fail closed. There is no built-in SMTP transport, production limiter, or environment switch that selects a login mode. These flows do not add an OAuth resource-owner password grant, assert an achieved ACR level, or provide phishing-resistant authentication.

## Rollout and compatibility

1. Back up the database and apply [.migrations/0.2.0.sql](../.migrations/0.2.0.sql) **before deploying the new code** on existing installations. There is no migration runner. Fresh installations use [schema.sql](../schema.sql) instead.
2. Existing users have no password credential after migration; provision one explicitly before requiring passwords. Email whitelist enrollment is available only through the built-in email-only flow, never as password enrollment or a replacement for the second factor.
3. Configure real delivery, limiter, challenge key, and shared cookie/database dependencies, then deploy the entire policy-protected handler set together.
4. Expect reauthentication: configured authorization and consent require every configured method. Configured code exchange and refresh reject insufficient or unknown AMR with `invalid_grant`, including pre-migration grants. No password is inferred merely because the user now has one. `client_credentials` remains unaffected.

Legacy exports, including `endpoints.HandleLogin` and `endpoints.HandleMagicLinkToken`, remain email-only and do not adopt a newly constructed service. **Never mount legacy login/magic handlers with a stronger configured flow.** Do not leave an unprotected authorization, decision, or token route as an alternate entry point. The [demo](../demo) remains unchanged and is not an example of configured password or combined login.

## Wire all three modes

The following reference wiring accepts real application dependencies rather than implementing a no-op limiter. Select one mode at startup. `challengeKey` is an explicit byte slice loaded from a secret manager: at least 32 cryptographically random bytes, not a password, a hardcoded example, or the bytes of an undecoded base64 string.

```go
package provider

import (
	"fmt"
	"net/http"

	"github.com/saschazar21/go-oidc-provider/endpoints"
	"github.com/saschazar21/go-oidc-provider/helpers"
	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

func NewLoginMux(
	conn *bun.DB,
	mode string,
	sender helpers.EmailCodeSender,
	limiter helpers.LoginLimiter,
	challengeKey []byte,
) (*http.ServeMux, error) {
	// This example supplies the same dependencies for all three choices.
	if sender == nil || limiter == nil || len(challengeKey) < 32 {
		return nil, fmt.Errorf("real sender, deployment-wide limiter, and >=32 key bytes required")
	}
	config := helpers.LoginConfig{
		DB: conn, Sender: sender, Limiter: limiter, ChallengeKey: challengeKey,
	}
	switch mode {
	case "email-code":
		config.Strategy = helpers.EmailCodeStrategy()
	case "password":
		config.Strategy = helpers.PasswordStrategy()
	case "password-then-email":
		config.Strategy = helpers.PasswordStrategy()
		config.RequireEmail = true
	default:
		return nil, fmt.Errorf("unknown login mode %q", mode)
	}
	service, err := helpers.NewLoginService(config)
	if err != nil {
		return nil, err
	}
	handlers, err := endpoints.NewLoginHandlers(service, utils.NewCookieStore())
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlers.Login)
	mux.HandleFunc("/login/magic", handlers.MagicLinkToken)
	mux.HandleFunc("/authorize", handlers.Authorization)
	mux.HandleFunc("/authorize/decision", handlers.AuthorizationDecision)
	mux.HandleFunc("/token", handlers.Token)
	return mux, nil
}
```

This mounts the login/OIDC subset, not a complete server; add discovery, JWKS, userinfo, logout, and application routes as appropriate. In password-only mode the code route rejects requests; it does not offer an email fallback. The reference forms accept passwords/codes only in bounded POST bodies, with CSRF and browser binding, and use secure cookies: serve over HTTPS.

### Database and cookie configuration must match

The service uses `LoginConfig.DB`, but `handlers.Authorization`, `handlers.AuthorizationDecision`, and `handlers.Token` call reference endpoints that connect using `DB_URL` and read cookies through `utils.NewCookieStore()`. **The injected database must be the same database selected by that environment, and the supplied store must have the same cookie keys/configuration as the global store.** A custom store passed to `NewLoginHandlers` does not replace dependencies in those three endpoints. Configure cookie keys before first use and keep them consistent across replicas; see [.env.sample](../.env.sample) and [utils/cookies.go](../utils/cookies.go).

For injected database/store OIDC handlers, use `handlers.Protect(customHandler)` rather than the three reference wrappers. `Protect` adds the required-method policy to the HTTP request context; it is **not standalone authentication middleware** for arbitrary application routes. The custom handler must pass that request/context through `helpers.HandleAuthorizationRequest` or `helpers.HandleAuthorizationDecision`, as appropriate. For tokens, call `helpers.ParseTokenRequest(r)` and the returned request's `HandleRequest(r.Context(), tx)`; see [endpoints/token.go](../endpoints/token.go). Do not discard the request context or create an unprotected alternate route. The lower-level policy API is `helpers.WithAuthenticationPolicy(r, service.RequiredMethods())`; an absent policy deliberately retains legacy behavior. See [helpers/authentication_policy.go](../helpers/authentication_policy.go).

### Delivery, key management, and throttling

- Implement `EmailCodeSender.SendLoginCode(ctx, email, code) error`, or adapt a delivery function with `helpers.EmailCodeSenderFunc`. Send to the provided address; never log codes, put them in URLs, or display them in HTML. Delivery runs after the attempt commits. A delivery error invalidates that code while retaining generic pending progress for a rate-limited resend. Delivery availability and observability are application responsibilities; no transactional outbox is provided.
- Implement `LoginLimiter.Allow(ctx, key) error`, or adapt with `helpers.LoginLimiterFunc`. Use an atomic, shared backend to enforce deployment-wide IP/account/attempt budgets across all workers and replicas, including a single-node production deployment. Namespaced keys contain SHA-256-hashed identifiers: `start` uses IP/email and `verify`/`resend` use IP/attempt ID. Configure meaningful limits for each operation and fail closed on backend errors. A callback returning nil unconditionally, or per-process-only counters behind multiple replicas, is not a production limiter. Add ingress/body/request-rate controls as well.
- The reference handlers use `RemoteAddr`, not forwarded headers. A trusted proxy integration must sanitize and rewrite it before invoking the handlers; never trust arbitrary client-supplied forwarding headers.
- Generate and store the challenge key separately from master, signing, and cookie keys. All replicas processing the same attempts need the same bytes. If your application stores the secret as base64, decode and validate the **decoded byte length** before constructing the service. No challenge-key environment variable is read automatically. Key replacement invalidates pending code verification; coordinate rotation/restarts and have users restart login.

## Challenge lifecycle and retention

The coordinator exposes `Start(ctx, LoginInput)`, `VerifyCode(ctx, CodeInput)`, and `Resend(ctx, CodeInput)`. It creates a session only after the fixed flow completes. The combined flow sends the code to the password-verified user's enrolled email, never a request-selected replacement address. Email-only unknown accounts use generic pending progress without authenticating an unknown user.

- Pending attempts expire after **10 minutes**; each six-digit code expires after **5 minutes**, capped by the attempt expiry.
- **Five failed code verifications** exhaust the attempt. The lifetime failure counter persists and is **not reset by resend**.
- Resend has a **30-second cooldown**, replaces the previous challenge, and invalidates the previous code. Neither resend nor a new code extends the attempt lifetime.
- Browser binding, fixed policy, account eligibility, and credential version are checked before completion. Session insertion and attempt completion commit together; the HTTP adapter writes the authenticated cookie only after success.
- AMR reflects verified methods and `AuthTime` is successful completion time. Configured session/consent reuse, code exchange, and refresh enforce method evidence; refresh preserves the original authentication time.

Rows live in `oidc_login_attempts`, including challenge metadata and keyed digests, not plaintext codes. Expiry is enforced during use, **not by deleting rows**. There is **no automatic retention cleanup trigger for this table**. Schedule manual/operator-managed cleanup of expired rows using `expires_at` and an appropriate audit/privacy retention window, including completed and anonymous attempts. Monitor table growth and delivery/limiter failures without collecting credentials or codes. Password mutation removes all of that user's attempt rows independently of retention cleanup.

## Password provisioning and administration

The [user CLI](../cli/user/main.go) preserves the existing no-argument create wizard and adds an optional initial password. Initial user creation plus credential persistence is atomic. For an existing user, invoke the user CLI with `--password-user UUID` to set or replace a password, or with `--password-user UUID --remove-password` to remove it. Removal asks for confirmation. See [cli/user/password.go](../cli/user/password.go).

Passwords are entered twice through **hidden interactive terminal input**. Never provide a password as a command argument, environment variable, profile field, or piped input. The password prompt refuses non-terminal input. Spaces and Unicode remain byte-exact; passwords are not trimmed, normalized, or silently truncated. There is no public enrollment, reset, recovery, or password-management endpoint; build any administrative recovery workflow separately with appropriate authorization and auditing.

Library operations in [helpers/password.go](../helpers/password.go):

- `helpers.SetPassword(ctx, db, userID, password)` hashes and atomically sets/replaces a credential.
- `helpers.RemovePassword(ctx, db, userID)` removes it; an existing passwordless user is handled idempotently.
- `helpers.SetPasswordInTx(ctx, tx, userID, password)` supports an existing transaction. Prefer hashing before opening a transaction using `utils.HashPasswordContext`, then call `helpers.SetEncodedPasswordInTx(ctx, tx, userID, encoded)` for atomic creation/provisioning. Roll back on **any** error; the encoded API accepts a validated PHC hash, never plaintext.

Set, replace, and remove invalidate pending attempts and revoke the user's sessions, authorizations, and database-backed tokens/refresh grants in the same transaction. Do not bypass these helpers with direct credential-table writes. Already-issued self-contained tokens cannot be recalled from offline consumers; enforce their existing expiry/revocation strategy. Removing a password does not create an email fallback under a password-required policy.

### Password hashing bounds

[utils/password.go](../utils/password.go) uses salted **Argon2id v19**, **19 MiB memory, two passes, parallelism one**, a random 16-byte salt, and a 32-byte derived key, encoded in PHC form. Passwords must contain **1–1024 bytes**, not characters. Hashes are separate from user profiles and are not ordinary `HashedString` values.

The verifier bounds PHC input to 256 bytes, memory to 19–64 MiB, passes to 2–4, parallelism to exactly one, salt to 16–32 bytes, and derived keys to 32 bytes. Malformed/out-of-bounds encodings are rejected before KDF work. Derived keys use constant-time comparison; missing users/credentials perform dummy verification. At most two default KDF operations run concurrently per process, including dummy work. Cancellation can stop waiting for a slot, not an Argon2 computation already running. Benchmark deployment capacity and enforce external limits; do not assume these process-local KDF bounds replace the deployment-wide limiter.

## Trusted custom strategies

`helpers.LoginStrategy` is a trusted server-side plugin, not a browser-selectable authentication option. Implement all three methods:

- `ID() string`: stable, nonempty identity of at most 128 bytes; change it when semantics change. It participates in the pending-flow fingerprint.
- `RequiredMethods() []utils.AMR`: immutable, nonempty, valid, duplicate-free methods that the primary strategy actually authenticates. Do not claim `pwd`, `email`, `mfa`, or another method merely because it is configured or a profile says it is available.
- `Authenticate(context.Context, bun.IDB, string, string) (*helpers.LoginIdentity, error)`: authenticate the supplied identity using trusted evidence; return the concrete user and exactly the declared primary methods only on success. Use generic `helpers.ErrLoginRejected` for expected authentication rejection. Honor cancellation and support concurrent calls; never issue a session or send the coordinator's email codes here.

`LoginIdentity.Methods` must come entirely from authenticated evidence, never unverified input. Password evidence requires the version read alongside the verified stored credential in `CredentialVersion`; custom external credentials need their own trusted revocation/version discipline. Only the built-in email-only strategy may initially return no user while awaiting email proof. The coordinator reloads/locks the user, checks account eligibility and applicable credential versions, and exclusively owns final session issuance.

Set `RequireEmail: true` to append the coordinator-managed email stage to a custom primary strategy, with sender/key/limiter requirements unchanged. The primary evidence must already satisfy everything returned by that strategy's `RequiredMethods()`; composition is not permission to fabricate primary evidence. The policy on OIDC requests checks required AMR membership, not custom-strategy provenance, so do not reuse method labels for weaker proofs and assume the strategy ID upgrades old sessions or grants. A custom plugin is inside the authentication trust boundary.

`PasswordStrategyWithVerifier` accepts `(ctx, encodedHash, byteExactPassword)` verification injection; overrides must preserve bounded costs and constant-time comparison. Neither custom strategies nor verifier injection should weaken password input bounds, evidence checks, account eligibility, or throttling. Additional plugin-specific UI is an application responsibility; the reference forms implement the built-in flows.