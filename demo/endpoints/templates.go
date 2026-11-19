package endpoints

import provider "github.com/saschazar21/go-oidc-provider/endpoints"

const demoMasthead = `<div class="masthead"><span class="brand-mark" aria-hidden="true">id</span> go-oidc-provider <span aria-hidden="true">/</span> demo</div>`
const demoFooter = `<footer class="footer">© {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a></footer>`

const DEFAULT_HTML_TEMPLATE_INDEX = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OIDC Demo</title>
` + provider.DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page">
    ` + demoMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <h1 id="page-title">go-oidc-provider Demo</h1>
        <p class="intro">A simple demonstration of the OpenID Connect authentication flow</p>
      </header>
      <div class="paper-body">
        <h2>Ready to test the flow?</h2>
        <p class="note" id="request-label">This demo uses the following OIDC parameters:</p>
        <pre class="data-box" aria-labelledby="request-label"><code>{{ .OIDCRequest }}</code></pre>
        <a href="{{ .LoginURL }}" class="button">Start OIDC Login <span aria-hidden="true">→</span></a>
        <div class="divider"><p class="note">This is a development / demonstration client only.<br>Do not use in production without proper security review.</p></div>
      </div>
    </article>
    ` + demoFooter + `
  </main>
</body>
</html>`

const DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Successful</title>
` + provider.DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page">
    ` + demoMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <div class="status">Authentication Successful ✓</div>
        <h1 id="page-title">You're in!</h1>
        <p class="intro" id="response-label">You have successfully authenticated with the OIDC provider.<br>Here's the response data we received:</p>
      </header>
      <div class="paper-body">
        <pre class="data-box" aria-labelledby="response-label"><code>{{ .OIDCResponse }}</code></pre>
        <p class="note">If you want to interact further with the OIDC provider, you can now use the obtained tokens or the following client credentials:</p>
        <dl class="credentials">
          <div><dt>Client ID:</dt><dd><code>{{ .ClientID }}</code></dd></div>
          <div><dt>Client Secret:</dt><dd><code>{{ .ClientSecret }}</code></dd></div>
        </dl>
        <div class="divider">
          <p class="note">You can safely close this window now.</p>
          <a href="/" class="button button--secondary">Back to Home</a>
        </div>
      </div>
    </article>
    ` + demoFooter + `
  </main>
</body>
</html>`

const DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Error</title>
` + provider.DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page">
    ` + demoMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <div class="status status--error">Authentication Failed ✗</div>
        <h1 id="page-title">Something went wrong...</h1>
        <p class="intro" id="error-label">An error occurred during authentication with the OIDC provider.<br>Here's the error/response data we received:</p>
      </header>
      <div class="paper-body">
        <pre class="data-box" aria-labelledby="error-label"><code>{{ .OIDCResponse }}</code></pre>
        <div class="divider">
          <p class="note">You can safely close this window, or try again.</p>
          <a href="/" class="button button--secondary">Back to Home</a>
        </div>
      </div>
    </article>
    ` + demoFooter + `
  </main>
</body>
</html>`
