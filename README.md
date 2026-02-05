<div align="center">
  <img src="logo.jpg" alt="Logo depicting a shield composed of curly braces and a simple key from top to bottom in the center" width="220">
  <h1>go-oidc-provider</h1>
  <p><strong>A lightweight OpenID Connect (OIDC) & OAuth 2.0 identity provider library in Go.</strong></p>

  <p>
    <a href="https://app.netlify.com/projects/go-oidc-demo/deploys">
      <img src="https://api.netlify.com/api/v1/badges/b795e10b-a47e-40a1-abd4-c2e7c1894598/deploy-status" alt="Netlify Deploy Status">
    </a>
    <a href="https://github.com/saschazar21/go-oidc-provider/actions/workflows/ci.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/your-username/your-repo/ci.yml?branch=main&style=flat-square&logo=github&logoColor=white" alt="GitHub Actions CI">
    </a>
    <a href="https://pkg.go.dev/github.com/saschazar21/go-oidc-provider">
      <img src="https://img.shields.io/github/go-mod/go-version/saschazar21/go-oidc-provider?style=flat-square&logo=go&logoColor=00ADD8" alt="Go Version">
    </a>
  </p>
</div>

## Features

- Complete support for **OpenID Connect Core 1.0** and **OAuth 2.0 Authorization Framework**
- Configurable **Authorization Flows** with support for **PKCE** for secure client-side usage
- Signed **ID tokens** (JWT), **access tokens** and **refresh tokens** with fully customizable claims
- Standard OIDC endpoints: discovery, authorization, token, userinfo
- Fully customizable, extensible, and easy to integrate into existing Go applications

## Prerequisites

- Go 1.24+
- Access to a PostgreSQL database

## Packages

- [`github.com/saschazar21/go-oidc-provider/cli`](cli): Command-line interface (CLI) helpers
  - `client`: Create OIDC clients using a guided CLI wizard
  - `magic-link-whitelist`: Add an e-mail address to the magic link whitelist for enabling new user registration, or
  - `user`: Manually create new user using a guided CLI wizard
- [`github.com/saschazar21/go-oidc-provider/db`](db): Database client and connection management
- [`github.com/saschazar21/go-oidc-provider/endpoints`](endpoints): Generic implementations of standard OIDC endpoints, not for production use
- [`github.com/saschazar21/go-oidc-provider/errors`](errors): Custom error types for OIDC and HTTP status codes
- [`github.com/saschazar21/go-oidc-provider/helpers`](helpers): Helper packages for various endpoints. **This is the main package** for creating a custom OIDC provider based on this repository. See [endpoints](endpoints) package for reference implementations.
- [`github.com/saschazar21/go-oidc-provider/idtoken`](idtoken): Implementation of ID token (JWT) generation and signing, as well as claim management.
- [`github.com/saschazar21/go-oidc-provider/models`](models): Data models for users, clients, tokens, sessions, etc... Also includes low-level model functionalities such as database CRUD operations, validations, token manipulations, etc...
- [`github.com/saschazar21/go-oidc-provider/utils`](utils): Low-level utility functions and types used across the repository, ranging from cryptographic helpers to cookie utilities and more.

### Endpoints

The [`helpers`](helpers) and [`endpoints`](endpoints) packages provide reference implementations of standard OIDC process flows and endpoints. Below is a list of included endpoints:

| Endpoint                            | Description                                    |
| ----------------------------------- | ---------------------------------------------- |
| `/.well-known/openid-configuration` | OIDC discovery document                        |
| `/.well-known/jwks.json`            | JSON Web Key Set (JWKS)                        |
| `/authorize`                        | Authorization endpoint (code flow)             |
| `/authorize/decision`               | User consent decision endpoint                 |
| `/introspect`                       | Token introspection endpoint                   |
| `/token`                            | Token endpoint (exchange code for tokens)      |
| `/userinfo`                         | User info endpoint                             |
| `/login`                            | Login endpoint                                 |
| `/login/magic`                      | Magic link login endpoint (passwordless login) |
| `/logout`                           | Logout endpoint                                |

> ⚠️ The HTTP handlers in the `endpoints` package are reference implementations meant to demonstrate how to use the library. They are not production-ready and should be customized and secured according to your application's needs. This first and foremost applies to the handling of **Magic Link Tokens**, which require a separate implementation to be securely transmitted to the end user.

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

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

## License

&copy; 2026 Sascha Zarhuber.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
