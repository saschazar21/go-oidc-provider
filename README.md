<div align="center">
  <img src="logo.jpg" alt="Logo depicting a shield composed of curly braces and a simple key from top to bottom in the center" width="220">
  <h1>go-oidc-provider</h1>
  <p><strong>A lightweight OpenID Connect (OIDC) & OAuth 2.0 identity provider library in Go.</strong></p>

  <p>
    <a href="https://go-oidc-demo.netlify.app" target="_blank" rel="noopener noreferrer">
      <img alt="Deployed demo URL" src="https://img.shields.io/badge/demo-go--oidc--demo.netlify.app-white?style=flat-square&logo=netlify&logoColor=00C7B7">
    </a>
    <a href="https://github.com/saschazar21/go-oidc-provider/releases" target="_blank" rel="noopener noreferrer">
      <img src="https://img.shields.io/github/v/release/saschazar21/go-oidc-provider?style=flat-square&logo=github&logoColor=white" alt="GitHub Release">
    </a>
    <a href="https://github.com/saschazar21/go-oidc-provider/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">
      <img alt="GitHub License" src="https://img.shields.io/github/license/saschazar21/go-oidc-provider?style=flat-square">
    </a>
    <a href="https://github.com/saschazar21/go-oidc-provider/actions/workflows/release.yml" target="_blank" rel="noopener noreferrer">
      <img src="https://img.shields.io/github/actions/workflow/status/saschazar21/go-oidc-provider/release.yml?branch=main&style=flat-square&logo=github&logoColor=white" alt="GitHub Actions CI">
    </a>
    <a href="https://pkg.go.dev/github.com/saschazar21/go-oidc-provider" target="_blank" rel="noopener noreferrer">
      <img src="https://pkg.go.dev/badge/github.com/saschazar21/go-oidc-provider.svg" alt="Go Reference">
    </a>
  </p>
</div>

## Features

- Complete support for **OpenID Connect Core 1.0** and **OAuth 2.0 Authorization Framework**
- Configurable **Authorization Flows** with support for **PKCE** for secure client-side usage
- Signed **ID tokens** (JWT), **access tokens** and **refresh tokens** with fully customizable claims
- Standard OIDC endpoints: discovery, authorization, token, userinfo
- Per-provider email-code, password-only, or password-then-email login, with injectable delivery and a required deployment-wide limiter
- Fully customizable, extensible, and easy to integrate into existing Go applications

## Prerequisites

- Go 1.24+
- Access to a PostgreSQL database

## Packages

- [`github.com/saschazar21/go-oidc-provider/cli`](cli): Command-line interface (CLI) helpers
  - `client`: Create OIDC clients using a guided CLI wizard
  - `magic-link-whitelist`: Add an e-mail address to the magic link whitelist for enabling new user registration, or
  - `user`: Create users and optionally provision, replace, or remove passwords using hidden terminal input
- [`github.com/saschazar21/go-oidc-provider/db`](db): Database client and connection management
- [`github.com/saschazar21/go-oidc-provider/endpoints`](endpoints): Generic implementations of standard OIDC endpoints, not for production use
- [`github.com/saschazar21/go-oidc-provider/errors`](errors): Custom error types for OIDC and HTTP status codes
- [`github.com/saschazar21/go-oidc-provider/helpers`](helpers): Helper packages for various endpoints. **This is the main package** for creating a custom OIDC provider based on this repository. See [endpoints](endpoints) package for reference implementations.
- [`github.com/saschazar21/go-oidc-provider/idtoken`](idtoken): Implementation of ID token (JWT) generation and signing, as well as claim management.
- [`github.com/saschazar21/go-oidc-provider/models`](models): Data models for users, clients, tokens, sessions, etc... Also includes low-level model functionalities such as database CRUD operations, validations, token manipulations, etc...
- [`github.com/saschazar21/go-oidc-provider/utils`](utils): Low-level utility functions and types used across the repository, ranging from cryptographic helpers to cookie utilities and more.

### Endpoints

The [`helpers`](helpers) and [`endpoints`](endpoints) packages provide reference implementations of standard OIDC process flows and endpoints. Below is a list of included endpoints:

| Endpoint                            | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `/.well-known/openid-configuration` | OIDC discovery document                           |
| `/.well-known/jwks.json`            | JSON Web Key Set (JWKS)                           |
| `/authorize`                        | Authorization endpoint (code flow)                |
| `/authorize/decision`               | User consent decision endpoint                    |
| `/introspect`                       | Token introspection endpoint                      |
| `/token`                            | Token endpoint (exchange code for tokens)         |
| `/userinfo`                         | User info endpoint                                |
| `/login`                            | Login endpoint                                    |
| `/login/magic`                      | Email-code verification/resend (configured flows) |
| `/logout`                           | Logout endpoint                                   |

> ⚠️ The HTTP handlers in the `endpoints` package are reference implementations meant to demonstrate how to use the library. They are not production-ready and should be customized and secured according to your application's needs. This first and foremost applies to the handling of **Magic Link Tokens**, which require a separate implementation to be securely transmitted to the end user.

### Login configuration and upgrade

See [docs/login.md](docs/login.md) for all three mode configurations, sender/limiter injection, handler wiring, password administration, and deployment requirements. `helpers.NewLoginService` fixes policy per provider instance; `PasswordStrategy()` with `RequireEmail: true` requires password verification followed by an email code. This is browser login, not an OAuth password grant or a claim of phishing-resistant authentication.

**Upgrade schema before deploying v0.2.0 code:** apply [.migrations/0.2.0.sql](.migrations/0.2.0.sql) to an existing database; use [schema.sql](schema.sql) for a fresh database. Existing users remain passwordless. Configured OIDC handlers reject sessions and grants whose authentication-method evidence is missing or insufficient, including old grants with unknown AMR. Password changes revoke user sessions and grants.

Legacy exported login/magic helpers and handlers remain email-only. **Never mount legacy login/magic handlers alongside a stronger configured flow.** Use the configured login, code, authorization, decision, and token handlers together; the reference OIDC handlers must use the same database and cookie-store configuration as the service. Custom handlers must preserve and enforce the configured request policy.

### Environment Variables

The following environment variables must be set for the library packages to function properly:

```bash
# OpenID Connect Issuer URL,
# will default to DEPLOY_PRIME_URL (or URL if CONTEXT=production)
# if not set
ISSUER_URL=

# PostgreSQL database connection string:
# postgres://user:password@host:5432/dbname
DB_URL=

# Base64-encoded master key for encrypting database values,
# must be exactly 32 bytes long
# `openssl rand -base64 32 | tr -d '\n'`
MASTER_KEY=

# Private keys encoded in base64 PEM format
# These can be generated with openssl, see below for examples.
# At least one of the keys must be set for the server to start
# (bare minimum is RS256, but ES256 is advised).
# RSA keys, must be at least 2048 bits long,
# e.g. RSA can be generated with `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048` and then `cat private_key.pem | base64 | tr -d '\n'`
KEY_RS256=
```

Additionally, there may be other optional environment variables defined for further customization. Please refer to the [`.env.sample`](.env.sample) file for a complete list.

## Demo

A demo application showcasing the usage of the library can be found in the [`demo`](demo) directory. It includes a simple implementation of an OIDC provider using the provided helper functions and reference endpoints, as well as a sample client application demonstrating how to authenticate against the provider.

A deployed version of the demo can be accessed at [https://go-oidc-demo.netlify.app](https://go-oidc-demo.netlify.app).

### Deploy the demo to Vercel

The demo supports both Netlify and Vercel. From the repository root, `make -C demo`
retains the Netlify build; `make -C demo vercel` cross-compiles all Go functions
for Vercel (Linux/amd64, CGO disabled). The `vercel` build tag selects Vercel's Go
bridge instead of Netlify's API Gateway adapter without changing the HTTP handlers.
The build requires the full checkout because the demo module imports the parent
provider module through a local replacement.

`make -C demo vercel` generates Build Output API v3 artifacts below the demo's
Vercel output directory: one function bundle per command, runtime descriptors,
route configuration, and static assets. Routing is maintained in
[demo/vercel/config.json](demo/vercel/config.json) and tested against
[demo/\_redirects](demo/_redirects). Run `make -C demo vercel-check` after compiling
to validate all bundles, metadata, routes, and executable formats.

To deploy manually, run `pnpm install --frozen-lockfile` inside the demo directory,
link the Vercel project with `pnpm exec vercel pull --yes --environment=production`,
then run `make vercel`, `make vercel-check`, and `pnpm deploy:vercel`. Run the
deployment from the demo directory, **not the functions subtree**: Vercel must
upload the complete prebuilt output, including routing and static assets. No
remote Go compilation is needed. A project created in the Vercel dashboard should
use the demo directory as its Root Directory and the Other framework preset.

The [deployment workflow](.github/workflows/deploy.yml) deploys both platforms on
pushes to `main`, after CI passes. For Vercel, create a GitHub Environment named
`vercel-production` and configure these environment or repository settings:

| Setting             | Kind     | Purpose                                       |
| ------------------- | -------- | --------------------------------------------- |
| `VERCEL_TOKEN`      | Secret   | Vercel token authorized to deploy the project |
| `VERCEL_ORG_ID`     | Variable | Vercel account/team identifier                |
| `VERCEL_PROJECT_ID` | Variable | Existing Vercel project identifier            |

The Vercel CLI displays the project and organization identifiers when linking the
project. Configure any required GitHub Environment approvals before deploying.
The workflow pulls production settings, compiles and validates the demo, then
deploys with `--prebuilt --prod`; its deployment URL is recorded separately from
Netlify's environment.

Configure the **production runtime environment in Vercel Project Settings** using
[demo/.env.sample](demo/.env.sample). In particular:

- Set an explicit, stable HTTPS `ISSUER_URL`, without a trailing slash. The
  automatic URL fallback supports Netlify, not Vercel.
- Provision a reachable PostgreSQL database with the current schema, an OIDC
  client with matching `OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET`, and the exact
  `ISSUER_URL` plus `/callback` redirect URI (and any logout redirect URIs).
- Configure `DB_URL`, `MASTER_KEY`, `COOKIE_AUTH_KEY`, at least one supported
  asymmetric signing key, and optionally `COOKIE_ENC_KEY`. Keep these values
  consistent across all functions and deployments; never put secrets in generated
  function descriptors. Enable `DEMO_MODE=true` for the demo behavior.
- Ensure deployment protection permits the demo's server-to-server discovery and
  token requests. Verify discovery, JWKS, login, callback/token exchange,
  userinfo/introspection, and logout after deployment.

Each Vercel build replaces only generated output, removing obsolete function
bundles. `make -C demo clean-vercel` removes that output while preserving linked
project settings and downloaded environment files; `make -C demo clean` also
removes the Netlify build outputs. Generated Vercel state is ignored by Git.

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

## License

Copyright &copy; 2026 Sascha Zarhuber.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
