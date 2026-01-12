package endpoints

const DEFAULT_AUTHORIZATION_TEMPLATE = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize {{ .Client.Name }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .consent-container {
      max-width: 580px;
    }
    .scope-list {
      max-height: 240px;
      overflow-y: auto;
      background-color: var(--bs-tertiary-bg);
      border: 1px solid var(--bs-border-color);
      border-radius: 0.375rem;
    }
    .scope-list .list-group-item {
      border-left: 0;
      border-right: 0;
      border-radius: 0;
    }
    .scope-list .list-group-item:first-child {
      border-top: 0;
    }
    .scope-list .list-group-item:last-child {
      border-bottom: 0;
    }
    .btn-approve {
      min-width: 140px;
    }
    .btn-deny {
      min-width: 140px;
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex flex-column">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container consent-container my-auto py-5">
    <div class="card shadow-sm border-0">
      <div class="card-header bg-primary text-white text-center fs-4 fw-semibold py-4">
        Authorization Request
      </div>
      
      <div class="card-body p-4 p-md-5">
        <div class="text-center mb-4">
					<svg xmlns="http://www.w3.org/2000/svg"
							width="64"
							height="64"
							class="bi bi-shield-check text-primary"
							viewBox="0 0 16 16"
							fill="none"
							stroke="currentColor"
							stroke-width="1"
							stroke-linecap="round"
							stroke-linejoin="round">
						<!-- Shield outline -->
						<path d="M8 1
										L12.5 2.5
										V6.5
										C12.5 9 10.7 11.3 8 12.5
										C5.3 11.3 3.5 9 3.5 6.5
										V2.5
										Z"/>
						<!-- Check mark -->
						<path d="M6.3 7.8
										L7.6 9.1
										L10 6.6"/>
					</svg>
        </div>

        <h2 class="card-title text-center mb-4 fw-bold">
          {{ .Client.Name }} wants to access your account
        </h2>

        <p class="text-center text-muted mb-5">
          This will allow <strong>{{ .Client.Name }}</strong> to perform actions on your behalf according to the permissions below.
        </p>

        {{ if gt (len .Scope) 0 }}
        <h5 class="text-center mb-3 fw-semibold">Requested permissions (scopes):</h5>
        <div class="scope-list mb-5">
          <ul class="list-group list-group-flush">
            {{ range .Scope }}
            <li class="list-group-item text-center py-2">{{ . }}</li>
            {{ end }}
          </ul>
        </div>
        {{ else }}
        <p class="text-center text-muted mb-5">
          No specific scopes requested.
        </p>
        {{ end }}

        <form method="POST" action="{{ .FormPostURI }}" class="d-flex justify-content-center gap-4 flex-wrap">
          <button type="submit" name="action" value="approved" class="btn btn-success btn-lg btn-approve">
            Approve
          </button>
          <button type="submit" name="action" value="denied" class="btn btn-outline-secondary btn-lg btn-deny">
            Deny
          </button>
        </form>

        <div class="mt-5 text-center">
          <p class="text-muted small">
            Only approve if you trust this application.<br>
            You can revoke access later in your account settings.
          </p>
        </div>
      </div>

      <div class="card-footer text-center text-muted small py-3">
        © {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>`

const DEFAULT_LOGIN_TEMPLATE = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .login-container {
      max-width: 420px;
    }
    .form-signin .form-floating:focus-within {
      z-index: 2;
    }
    .form-signin input[type="email"] {
      border-radius: 0.375rem;
      margin-bottom: -1px;
      border-bottom-right-radius: 0;
      border-bottom-left-radius: 0;
    }
    .btn-login {
      border-radius: 0.375rem;
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex align-items-center">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container login-container mx-auto px-4">
    <div class="card shadow-lg border-0 rounded-4 overflow-hidden">
      <div class="card-body p-5 p-md-5 text-center">
        <div class="mb-4">
          <svg xmlns="http://www.w3.org/2000/svg"
							width="64"
							height="64"
							fill="currentColor"
							class="bi bi-person-circle text-primary"
							viewBox="0 0 16 16">
						<path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z"/>
						<path fill-rule="evenodd"
									d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm8-7a7 7 0 0 0-5.468 11.594c.007-.243.065-.477.173-.684.28-.57.85-1.01 1.55-1.255C5.104 10.27 6.387 10 8 10c1.613 0 2.896.27 3.745.655.7.245 1.27.685 1.55 1.255.108.207.166.441.173.684A7 7 0 0 0 8 1z"/>
					</svg>
        </div>

        <h1 class="h3 fw-bold mb-4">Sign In</h1>

        <p class="text-muted mb-4">
          Enter <code>test@example.com</code> as e-mail address to proceed with the OIDC demo
        </p>

        <form method="POST" action="{{ .FormPostURI }}" class="form-signin">
          <div class="form-floating mb-3">
            <input type="email" class="form-control" id="email" name="email" placeholder="test@example.com" required autofocus>
            <label for="email">Email address</label>
          </div>

          <button class="btn btn-primary btn-lg w-100 btn-login fw-semibold" type="submit">
            Sign In →
          </button>

          <div class="mt-4">
            <p class="text-muted small mb-0">
              This is a demo login — no password required.<br>
              A magic link token is automatically created and provided in the next step.
            </p>
          </div>
        </form>
      </div>

      <div class="card-footer bg-transparent text-center text-muted small py-3 border-0">
        © {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>`

const DEFAULT_MAGIC_LINK_TEMPLATE = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Magic Link</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .verify-container {
      max-width: 460px;
    }
    .token-input {
      font-family: 'Consolas', 'Monaco', monospace;
      letter-spacing: 0.15em;
      font-size: 1.25rem;
    }
    .btn-verify {
      min-width: 160px;
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex align-items-center">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container verify-container mx-auto px-4">
    <div class="card shadow-lg border-0 rounded-4 overflow-hidden">
      <div class="card-body p-5 text-center">
        <div class="mb-4">
          <svg xmlns="http://www.w3.org/2000/svg"
							width="64"
							height="64"
							fill="currentColor"
							class="bi bi-envelope-check text-primary"
							viewBox="0 0 16 16">
						<path d="M2 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h8.5a.5.5 0 0 0 0-1H2a1 1 0 0 1-1-1V4.414l6.646 4.147a.5.5 0 0 0 .708 0L15 4.414V8a.5.5 0 0 0 1 0V4a2 2 0 0 0-2-2H2zm13 1.383L8 7.566 1 3.383V4l7 4.375L15 4v-.617z"/>
						<path d="M16 11.5a.5.5 0 0 1-.5.5H13v2.5a.5.5 0 0 1-1 0V12h-1.5a.5.5 0 0 1 0-1H12V8.5a.5.5 0 0 1 1 0V11h2.5a.5.5 0 0 1 .5.5z"/>
					</svg>
        </div>

        <h1 class="h3 fw-bold mb-3">Verify Your Email</h1>

        <p class="text-muted mb-4">
          Normally a magic link is sent to your (real) e-mail address—for demo purposes it is auto-filled here.<br>
          Click it to sign in — or paste the token below if needed.
        </p>

        <form method="POST" action="{{ .FormPostURI }}" class="mt-4">
          <div class="mb-4">
            <input 
              type="text" 
              class="form-control form-control-lg token-input text-center" 
              id="token" 
              name="token" 
              value="{{ .Token }}" 
              placeholder="Paste token here..." 
              required 
              autofocus
              autocomplete="one-time-code"
            >
          </div>

          <input type="hidden" name="id" value="{{ .ID }}">

          <button type="submit" class="btn btn-primary btn-lg w-100 btn-verify fw-semibold">
            Verify & Sign In →
          </button>

          <div class="mt-4">
            <p class="text-muted small mb-0">
              The magic link token sending mechanism is not implemented in this demo, nor is there a sample implementation available in the source code repository.<br>
              <a href="/" class="text-muted text-decoration-underline">Back to home</a> if you need to start over.
            </p>
          </div>
        </form>
      </div>

      <div class="card-footer bg-transparent text-center text-muted small py-3 border-0">
        © {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>`
