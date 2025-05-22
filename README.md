# [Work in Progress] Custom OIDC Provider

A lightweight, custom OpenID Connect (OIDC) provider written in Go, designed for easy deployment on Netlify. This project enables you to act as your own identity provider, supporting standard OIDC flows and token management.

## Features

- Implements OpenID Connect Core 1.0 and OAuth 2.0 Authorization Framework
- Supports Authorization Code flow, PKCE, and dynamic client registration
- Issues ID tokens and access tokens with customizable claims
- Exposes user info and discovery endpoints
- Deployable as a serverless function on Netlify

## Getting Started

### Prerequisites

- Go 1.22+ installed
- Netlify CLI for local development and deployment
- Netlify account

### Installation

1. **Clone the repository:**

2. **Install dependencies:**

   ```bash
   go mod tidy
   ```

3. **Configure environment variables:**

   Copy `env.sample` to `.env` in the project root:

   ```bash
   cp -v .env.sample .env
   ```

   Assign a value to each environment variable.

4. **Run locally with Netlify Dev:**

   ```bash
   netlify dev
   ```

5. **Set environment variables in Netlify dashboard** (Site settings → Environment variables).

6. **Deploy to production:**

   ```bash
   netlify deploy --prod
   ```

7. **Update your OIDC clients** to use the Netlify deployment URL as the issuer.

## Endpoints

| Endpoint                            | Description                               |
| ----------------------------------- | ----------------------------------------- |
| `/.well-known/openid-configuration` | OIDC discovery document                   |
| `/authorize`                        | Authorization endpoint (code flow)        |
| `/token`                            | Token endpoint (exchange code for tokens) |
| `/userinfo`                         | User info endpoint                        |
| `/register`                         | Dynamic client registration               |

## Example Usage

Configure your OIDC client with:

- **Issuer:** `https://your-site.netlify.app`
- **Client ID/Secret:** As set above
- **Redirect URI:** Your application's callback URL

## Customization

- Modify claims and user info logic in `internal/user.go`
- Extend supported grant types and flows in `internal/oidc.go`

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Netlify Functions Documentation](https://docs.netlify.com/functions/overview/)

---

**Note:** For production, ensure secure storage of secrets and use HTTPS for all endpoints.
