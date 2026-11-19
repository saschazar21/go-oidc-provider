package endpoints

// DEFAULT_PAPER_STYLES is shared by the provider and demo templates. System
// fonts and self-contained CSS avoid third-party requests on sign-in pages.
const DEFAULT_PAPER_STYLES = `<style>
  :root {
    color-scheme: light;
    --canvas: #f5f4f0;
    --paper: #fffefa;
    --ink: #292d29;
    --muted: #666b63;
    --line: #dedfd6;
    --accent: #355d4b;
    --wash: #edf2eb;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    font-synthesis: none;
    -webkit-font-smoothing: antialiased;
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; min-height: 100svh; background: var(--canvas); color: var(--ink); font-size: 16px; line-height: 1.65; }
  .page { width: min(100% - 40px, 720px); margin: 0 auto; padding: 64px 0 32px; }
  .page--form { max-width: 480px; }
  .page--consent { max-width: 560px; }
  .masthead { display: flex; align-items: center; gap: 10px; margin-bottom: 24px; color: var(--muted); font-size: .8rem; font-weight: 500; letter-spacing: .03em; }
  .brand-mark { display: inline-grid; place-items: center; width: 28px; height: 28px; border: 1px solid var(--line); border-radius: 6px; background: var(--paper); color: var(--accent); font-family: ui-monospace, monospace; font-size: .72rem; }
  .paper { background: var(--paper); border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 2px 3px #292d2903, 0 12px 32px #292d2906; }
  .paper-header { padding: 32px 36px 28px; border-bottom: 1px solid var(--line); }
  .paper-body { padding: 32px 36px 36px; }
  .eyebrow { margin: 0 0 12px; color: var(--accent); font-size: .72rem; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; }
  h1 { margin: 0 0 12px; font-size: clamp(1.65rem, 5vw, 2rem); font-weight: 600; line-height: 1.25; letter-spacing: -.035em; overflow-wrap: anywhere; }
  h2 { margin: 0 0 12px; font-size: 1rem; font-weight: 600; letter-spacing: -.01em; }
  p { margin: 0 0 20px; }
  .intro { margin-bottom: 0; color: var(--muted); font-size: .94rem; }
  .muted, .note { color: var(--muted); }
  .note { font-size: .8rem; line-height: 1.65; }
  .divider { margin-top: 28px; padding-top: 22px; border-top: 1px solid var(--line); }
  .divider > :last-child { margin-bottom: 0; }
  a { color: var(--accent); text-underline-offset: 3px; }
  a:hover { color: #233e32; }
  label { display: block; margin-bottom: 8px; font-size: .85rem; font-weight: 600; }
  input:not([type="hidden"]) { display: block; width: 100%; min-height: 50px; border: 1px solid #b8bdb2; border-radius: 5px; background: #fff; padding: 12px 14px; color: var(--ink); font: inherit; line-height: 1.5; box-shadow: inset 0 1px 2px #292d2904; }
  input::placeholder { color: #7a7f75; opacity: 1; }
  input:focus { outline: 2px solid var(--accent); outline-offset: 3px; border-color: var(--accent); }
  :where(a, button):focus-visible { outline: 2px solid var(--accent); outline-offset: 4px; }
  .field { margin-bottom: 24px; }
  .token-input { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important; }
  .button { display: inline-flex; align-items: center; justify-content: center; gap: 12px; min-height: 46px; padding: 11px 20px; border: 1px solid var(--accent); border-radius: 5px; background: var(--accent); color: #fffefa; font: inherit; font-size: .88rem; font-weight: 500; line-height: 1.5; text-decoration: none; cursor: pointer; }
  .button:hover { background: #294b3b; border-color: #294b3b; color: #fff; }
  .button--secondary { background: transparent; color: var(--ink); border-color: #b8bdb2; }
  .button--secondary:hover { background: #f0f0ea; border-color: #91998b; color: var(--ink); }
  .button--full { width: 100%; }
  .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; }
  .actions .button { flex: 1; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .8rem; }
  code { padding: 2px 6px; border: 1px solid #dce3d6; border-radius: 4px; background: var(--wash); color: #36513d; overflow-wrap: anywhere; box-decoration-break: clone; -webkit-box-decoration-break: clone; }
  .entity { padding: 2px 6px; border-radius: 3px; background: var(--wash); color: var(--accent); font-weight: 600; overflow-wrap: anywhere; }
  .data-label { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 4px 16px; margin-bottom: 10px; font-size: .8rem; font-weight: 600; }
  .data-label span { color: var(--muted); font-size: .72rem; font-weight: 400; }
  .data-box { margin: 0 0 28px; padding: 20px; border: 1px solid var(--line); border-radius: 5px; background: #f8f9f4; color: #3d5142; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.85; tab-size: 2; }
  .data-box code { padding: 0; border: 0; background: none; color: inherit; font-size: inherit; }
  .scope-list { list-style: none; padding: 0; margin: 0; border: 1px solid var(--line); border-radius: 5px; max-height: 260px; overflow-y: auto; }
  .scope-list li { padding: 12px 16px; border-bottom: 1px solid var(--line); font-size: .88rem; }
  .scope-list li:last-child { border-bottom: 0; }
  .credentials { margin: 20px 0 0; }
  .credentials > div { padding: 14px 0; border-top: 1px solid var(--line); }
  .credentials dt { margin-bottom: 6px; color: var(--muted); font-size: .76rem; }
  .credentials dd { margin: 0; overflow-wrap: anywhere; }
  .status { display: inline-flex; align-items: center; gap: 7px; color: var(--accent); font-size: .76rem; font-weight: 500; margin-bottom: 18px; }
  .status::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
  .status--error { color: #994535; }
  .footer { margin-top: 24px; text-align: center; color: var(--muted); font-size: .72rem; }
  .footer a { color: inherit; }
  @media (max-width: 520px) {
    .page { width: calc(100% - 28px); padding-top: 28px; }
    .paper-header, .paper-body { padding: 24px; }
    .data-box { padding: 14px; font-size: .74rem; }
    .actions { flex-direction: column; }
  }
  @media print {
    body { background: #fff; }
    .page { width: 100%; padding: 0; }
    .paper { box-shadow: none; }
  }
</style>`

const paperMasthead = `<div class="masthead"><span class="brand-mark" aria-hidden="true">id</span> go-oidc-provider <span aria-hidden="true">/</span> demo</div>`
const paperFooter = `<footer class="footer">© {{ .Year }} · <a href="https://sascha.work" target="_blank" rel="noopener noreferrer">Sascha Zarhuber</a></footer>`

const DEFAULT_AUTHORIZATION_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize {{ .Client.Name }}</title>
` + DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page page--consent">
    ` + paperMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <p class="eyebrow">Authorization Request</p>
        <h1 id="page-title"><span class="entity">{{ .Client.Name }}</span> wants to access your account</h1>
        <p class="intro">This will allow <strong>{{ .Client.Name }}</strong> to perform actions on your behalf according to the permissions below.</p>
      </header>
      <div class="paper-body">
        {{ if gt (len .Scope) 0 }}
        <h2>Requested permissions (scopes):</h2>
        <ul class="scope-list" aria-label="Requested permissions">
          {{ range .Scope }}<li><code>{{ . }}</code></li>{{ end }}
        </ul>
        {{ else }}
        <p class="note">No specific scopes requested.</p>
        {{ end }}
        <form method="POST" action="{{ .FormPostURI }}" class="actions">
          <button type="submit" name="action" value="approved" class="button">Approve</button>
          <button type="submit" name="action" value="denied" class="button button--secondary">Deny</button>
        </form>
        <div class="divider"><p class="note">Only approve if you trust this application.<br>You can revoke access later in your account settings.</p></div>
      </div>
    </article>
    ` + paperFooter + `
  </main>
</body>
</html>`

const DEFAULT_LOGIN_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In</title>
` + DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page page--form">
    ` + paperMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <h1 id="page-title">Sign In</h1>
      </header>
      <div class="paper-body">
        <p class="note" id="email-hint">Enter <code>test@example.com</code> as e-mail address to proceed with the OIDC demo</p>
        <form method="POST" action="{{ .FormPostURI }}">
          <div class="field">
            <label for="email">Email address</label>
            <input type="email" id="email" name="email" placeholder="test@example.com" autocomplete="email" autocapitalize="none" spellcheck="false" aria-describedby="email-hint" required autofocus>
          </div>
          <button class="button button--full" type="submit">Sign In <span aria-hidden="true">→</span></button>
        </form>
        <div class="divider"><p class="note">This is a demo login — no password required.<br>A magic link token is automatically created and provided in the next step.</p></div>
      </div>
    </article>
    ` + paperFooter + `
  </main>
</body>
</html>`

const DEFAULT_MAGIC_LINK_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Magic Link</title>
` + DEFAULT_PAPER_STYLES + `
</head>
<body>
  <main class="page page--form">
    ` + paperMasthead + `
    <article class="paper" aria-labelledby="page-title">
      <header class="paper-header">
        <h1 id="page-title">Verify Your Email</h1>
      </header>
      <div class="paper-body">
        <p class="note" id="token-hint">Normally a magic link is sent to your (real) e-mail address—for demo purposes it is auto-filled here.<br>Click it to sign in — or paste the token below if needed.</p>
        <form method="POST" action="{{ .FormPostURI }}">
          <div class="field">
            <label for="token">Verification token</label>
            <input type="text" class="token-input" id="token" name="token" value="{{ .Token }}" placeholder="Paste token here..." aria-describedby="token-hint" required autofocus autocomplete="one-time-code" autocapitalize="none" spellcheck="false">
          </div>
          <input type="hidden" name="id" value="{{ .ID }}">
          <button type="submit" class="button button--full">Verify &amp; Sign In <span aria-hidden="true">→</span></button>
        </form>
        <div class="divider">
          <p class="note">The magic link token sending mechanism is not implemented in this demo, nor is there a sample implementation available in the source code repository.<br><a href="/">Back to home</a> if you need to start over.</p>
        </div>
      </div>
    </article>
    ` + paperFooter + `
  </main>
</body>
</html>`
