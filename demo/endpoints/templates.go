package endpoints

const DEFAULT_HTML_TEMPLATE_CALLBACK_SUCCESS = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Successful</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .success-container {
      max-width: 620px;
    }
    .response-box {
      background-color: var(--bs-tertiary-bg);
      border: 1px solid var(--bs-border-color);
      font-family: 'Consolas', 'Monaco', monospace;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .card-header-success {
      background-color: #0d6efd22;
      color: #0d6efd;
      border-bottom: 1px solid #0d6efd40;
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex flex-column">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container success-container my-auto py-5">
    <div class="card shadow-sm border-0">
      <div class="card-header card-header-success text-center fs-4 fw-semibold">
        Authentication Successful ✓
      </div>
      
      <div class="card-body p-4 p-md-5 text-center">
        <div class="mb-4">
          <svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" fill="currentColor" class="bi bi-check-circle-fill text-success" viewBox="0 0 16 16">
            <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
          </svg>
        </div>

        <h2 class="card-title mb-4 fw-bold">You're in!</h2>
        
        <p class="text-muted mb-4">
          You have successfully authenticated with the OIDC provider.<br>
          Here's the response data we received:
        </p>

        <pre class="response-box p-3 rounded text-start fs-6"><code>{{ .OIDCResponse }}</code></pre>

				<div class="mt-4 mb-2">
					<p class="text-muted">
						If you want to interact further with the OIDC provider, you can now use the obtained tokens or the following client credentials:<br>
					</p>
					<p class="text-center">
						<strong>Client ID:</strong> <code>{{ .ClientID }}</code><br>
						<strong>Client Secret:</strong> <code>{{ .ClientSecret }}</code>
					</p>
				</div>

        <div class="mt-5 pt-3">
          <p class="text-muted small mb-4">
            You can safely close this window now.
          </p>
          <a href="/" class="btn btn-primary px-5">
            Back to Home
          </a>
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

const DEFAULT_HTML_TEMPLATE_CALLBACK_ERROR = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Error</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .error-container {
      max-width: 620px;
    }
    .response-box {
      background-color: var(--bs-tertiary-bg);
      border: 1px solid var(--bs-border-color);
      font-family: 'Consolas', 'Monaco', monospace;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .card-header-error {
      background-color: #dc354522;
      color: #dc3545;
      border-bottom: 1px solid #dc354540;
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex flex-column">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container error-container my-auto py-5">
    <div class="card shadow-sm border-0">
      <div class="card-header card-header-error text-center fs-4 fw-semibold">
        Authentication Failed ✗
      </div>
      
      <div class="card-body p-4 p-md-5 text-center">
        <div class="mb-4">
          <svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" fill="currentColor" class="bi bi-x-circle-fill text-danger" viewBox="0 0 16 16">
            <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/>
          </svg>
        </div>

        <h2 class="card-title mb-4 fw-bold text-danger">Something went wrong...</h2>
        
        <p class="text-muted mb-4">
          An error occurred during authentication with the OIDC provider.<br>
          Here's the error/response data we received:
        </p>

        <pre class="response-box p-3 rounded text-start fs-6"><code>{{ .OIDCResponse }}</code></pre>

        <div class="mt-5 pt-3">
          <p class="text-muted small mb-4">
            You can safely close this window, or try again.
          </p>
          <a href="/" class="btn btn-outline-primary px-5 me-3">
            Back to Home
          </a>
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

const DEFAULT_HTML_TEMPLATE_INDEX = `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OIDC Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    .request-box {
      background-color: var(--bs-tertiary-bg);
      border: 1px solid var(--bs-border-color);
      font-family: 'Consolas', 'Monaco', monospace;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .hero-section {
      background: linear-gradient(135deg, #0d6efd10 0%, #6610f210 100%);
    }
  </style>
</head>
<body class="bg-body-tertiary min-vh-100 d-flex flex-column">
	<!-- Disclaimer: This HTML template was vibe-coded by AI as I did not want to spend too much time on front-end design for this demo project. -->
  <div class="container my-5 py-5">
    <div class="row justify-content-center">
      <div class="col-lg-8">

        <div class="card shadow-sm border-0 overflow-hidden">
          <div class="hero-section text-center py-5 px-4">
            <h1 class="display-5 fw-bold mb-3">
              go-oidc-provider Demo
            </h1>
            <p class="lead text-muted mb-0">
              A simple demonstration of the OpenID Connect authentication flow
            </p>
          </div>

          <div class="card-body p-5 text-center">
            <div class="mb-5">
							<svg xmlns="http://www.w3.org/2000/svg"
									width="80"
									height="80"
									class="bi bi-shield-lock text-primary"
									viewBox="0 0 16 16"
									fill="none"
									stroke="currentColor"
									stroke-width="1"
									stroke-linecap="round"
									stroke-linejoin="round">
								<!-- Shield outline -->
								<path d="M8 0
												L13 2.5
												V6.5
												C13 9 10.7 11.3 8 12.5
												C5.3 11.3 3 9 3 6.5
												V2.5
												Z"/>
								<!-- Lock body -->
								<rect x="6.25" y="6.5" width="3.5" height="2.5" rx="0.5"/>
								<!-- Lock shackle -->
								<path d="M7 6.5 V5.5a1 1 0 0 1 2 0v1"/>
							</svg>
            </div>

            <h2 class="h4 fw-semibold mb-4">Ready to test the flow?</h2>

            <p class="text-muted mb-4">
              This demo uses the following OIDC parameters:
            </p>

            <pre class="request-box p-4 rounded text-start fs-6 mb-5"><code>{{ .OIDCRequest }}</code></pre>

            <a href="{{ .LoginURL }}" class="btn btn-primary btn-lg px-5 py-3">
              Start OIDC Login →
            </a>

            <div class="mt-5 pt-4 border-top">
              <p class="text-muted small mb-0">
                This is a development / demonstration client only.<br>
                Do not use in production without proper security review.
              </p>
            </div>
          </div>

          <div class="card-footer text-center text-muted small py-3">
            © {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a>
          </div>
        </div>

      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>`
