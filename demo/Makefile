# -----------------------
# Configuration
# -----------------------
CMD_DIR := cmd
OUT_DIR := functions
PUBLIC_DIR := public
VERCEL_OUT_DIR := .vercel/output
VERCEL_FUNCTIONS_DIR := $(VERCEL_OUT_DIR)/functions

GOOS := linux
GOARCH := amd64
CGO_ENABLED := 0
GOFLAGS := -ldflags="-s -w"

# -----------------------
# Discover functions
# -----------------------
# Finds: cmd/<name>/main.go → <name>
FUNCTIONS := $(notdir $(patsubst %/main.go,%,$(wildcard $(CMD_DIR)/*/main.go)))

# Output binaries
BINARIES := $(FUNCTIONS:%=$(OUT_DIR)/%)
VERCEL_BINARIES := $(FUNCTIONS:%=$(VERCEL_FUNCTIONS_DIR)/%.func/bootstrap)

# Keep the Netlify build as the default, regardless of helper target ordering.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

# -----------------------
# Targets
# -----------------------
.PHONY: all clean static vercel vercel-output vercel-static vercel-check clean-vercel FORCE

# 'all' depends on static and binaries
all: static $(BINARIES)

# -----------------------
# Build functions
# -----------------------
# Pattern rule: build each function
# Always ask Go to build: imported handlers and the platform adapter may change.
# Go's own build cache avoids recompiling unchanged packages.
$(OUT_DIR)/%: $(CMD_DIR)/%/main.go FORCE
	@mkdir -p $(OUT_DIR)
	@echo "Building $*"
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build $(GOFLAGS) -o $@ ./$(CMD_DIR)/$*

# -----------------------
# Vercel Build Output API v3
# -----------------------
# Cleanup must finish before the recursive build, including with make -j.
# Keep .vercel/project.json and downloaded project settings intact.
vercel: clean-vercel
	@$(MAKE) --no-print-directory vercel-output

vercel-output: $(VERCEL_BINARIES) vercel-static

# Pin the platform independently of Netlify overrides so metadata always agrees.
$(VERCEL_FUNCTIONS_DIR)/%.func/bootstrap: $(CMD_DIR)/%/main.go FORCE
	@mkdir -p $(@D)
	@echo "Building Vercel function $*"
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	go build $(GOFLAGS) -tags vercel -o $@ ./$(CMD_DIR)/$*
	@printf '%s\n' '{"runtime":"provided.al2023","handler":"bootstrap","architecture":"x86_64"}' > $(@D)/.vc-config.json

vercel-static:
	@mkdir -p $(VERCEL_OUT_DIR)/static
	cp vercel/config.json $(VERCEL_OUT_DIR)/config.json
	cp LICENSE $(VERCEL_OUT_DIR)/static/license.txt

# Run separately after `make vercel`; fail if any expected artifact is missing.
vercel-check:
	VERCEL_BUILD_OUTPUT="$(abspath $(VERCEL_OUT_DIR))" go test ./vercel -count=1

FORCE:

# -----------------------
# Copy static assets
# -----------------------
static:
	@mkdir -p $(PUBLIC_DIR)
	@echo "Copying static assets"
	cp -v _redirects $(PUBLIC_DIR)/_redirects
	cp -v LICENSE $(PUBLIC_DIR)/license.txt

# -----------------------
# Clean everything
# -----------------------
clean: clean-vercel
	rm -rf $(OUT_DIR) $(PUBLIC_DIR)

clean-vercel:
	rm -rf $(VERCEL_OUT_DIR)
