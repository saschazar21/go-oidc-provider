## [0.1.4] - 2026-02-12

### 🐛 Bug Fixes

- Fixed OpenID Configuration validator (#9)

### ⚙️ Miscellaneous Tasks

- Updated README.md [skip ci]
## [0.1.3] - 2026-02-10

### ⚙️ Miscellaneous Tasks

- Improve the matrix compile job for CLI applications (#8)
## [0.1.2] - 2026-02-10

### ⚙️ Miscellaneous Tasks

- Bump go version from 1.24.3 to 1.24.4 (#7)
## [0.1.1] - 2026-02-10

### ⚙️ Miscellaneous Tasks

- Fixed CLI build input path (#6)
## [0.1.0] - 2026-02-10

### 🚀 Features

- Initial commit
- Added Client model, extended User
- Added Authorization model
- Added Authorization model, excluded model validations into validations file
- Enhanced Authorization validator
- Added authorization_request for parsing auth requests
- Added Session model
- Added BeforeUpdate hooks
- Added Magic Link Whitelist model
- Added Magic Link Token model
- Added Token model
- Added JSONError, added token factory
- Added conditions to token retrieval
- Added token revocation functionality
- Added token revocation in authorization deactivation
- Added token rotation feature
- Extracted Token queries into query factory
- Added Token Request parser & unit test
- Moved models to top level, added helpers & internal-redirect-error
- Moved helper functions out of models
- Added magic link token helper
- Enhanced authorization helper
- Added prompt=none checks
- Added token response helpers
- Added HandleRequest facade in token helper
- Added idtoken package
- Added user claims to id token
- Added audience to id token, refactored Epoch & EpochMillis
- Added idtoken to token response
- Added alg=none for JWT, enhanced unit test coverage
- Added jwks endpoint handler
- Added OpenID configuration
- Added Authorization Response helper
- Added end_session helper
- Added Makefile, added end_session unit tests
- Added end_session endpoint
- Added login & magic_link_token endpoints
- Added authorization & authorization_decision endpoints
- Extended authorization helper to directly use authorizationResponse, added authorization endpoint unit test
- Added token endpoint
- Added client registration helper
- Added token introspection helper
- Added userinfo endpoint, added user hydration
- Added token introspection endpoint
- Added userinfo endpoint
- Added demo
- Added CLI applications
- Extended validators for client
- Added Netlify deployment files, fixed smaller issues
- Added new vibe-coded default layouts, fixed minor issues
- Upgraded to vibe-coded default layouts, fixed minor issues
- Added magic-link-whitelist CLI

### 🐛 Bug Fixes

- Fixed Authorization to pass unit test
- Fixed Authorization, User validation
- Fixed is_confidential client validation, adapted unit tests
- Fixed decoding scope string, removed unnecessary validation cases, added unit test
- Fixed smaller issues in user & session
- Fixed relation of authorization to replaced authorization
- Fixed Token AfterSelect hook
- Fixed authorization cookie validation, enhanced unit test coverage
- Changed user timestamps to pointer
- Fixed authorization destructuring from token
- Fixed typo, fixed nil pointer
- Temporarily deactivated client_secret check
- Removed replaced authorization, fixed client validator
- Swapped epoch to pointer for token introspection
- Fixed IP address parsing to not break at IPv6 addresses
- Fixed indentation, removed invalid working-directory
- Added hostname_port as fallback validator for IP addresses
- Fixed test workflow
- Fixed variable interpolation in test workflow
- Fixed permissions in test workflow
- Improve comment body in test workflow
- Fixed delimiter in test workflow
- Fixed comment body
- Rewrote the comment body section of the test workflow
- Fix percentage display of comment body in test workflow
- Next try for fixing percentage display of comment body in test workflow
- Final try for fixing the percentage display in test workflow
- Rewrote the awk statement in order to display valid percentages in test workflow
- New try to fix percentage display in comment body
- Next try in solving the percentage issue in test workflow
- Fixed release workflow
- Fixed deploy workflow
- Fixed changelog workflow
- Fixed git-cliff by appending --initial-tag flag

### 🧪 Testing

- Enhanced test coverage for authorizations
- Fixed and enhanced authorization unit tests
- Raised test coverage for magic link token helper
- Enhanced unit test coverage for authorization helper
- Enhanced test coverage for session helper
- Enhanced unit test coverage for end_session endpoint
- Added login endpoint unit test, fixed smaller issues
- Added authorization_decision helper unit test
- Added authorization decision endpoint unit test
- Enhanced test coverage for authorization endpoint

### ⚙️ Miscellaneous Tasks

- Rewrote README.md
- Add Copyright term
- Added Github workflows
- Added test workflow
- Added Github workflows (#1)
- Fixed changelog & deploy Github workflows
- Fixed changelog & deploy Github workflows (#2)
- Fixed Node & Go version definitions in deploy workflow
- Fixed tool version detection & added initial tag to git-cliff (#3)
- Removed invalid --initial-tag flags and add it to cliff.toml (#4)
- Fixed initial_tag addition to cliff.toml (#5)
