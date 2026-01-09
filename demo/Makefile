# -----------------------
# Configuration
# -----------------------
CMD_DIR := cmd
OUT_DIR := functions
PUBLIC_DIR := public

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

# -----------------------
# Targets
# -----------------------
.PHONY: all clean static

# 'all' depends on static and binaries
all: static $(BINARIES)

# -----------------------
# Build functions
# -----------------------
# Pattern rule: build each function
$(OUT_DIR)/%: $(CMD_DIR)/%/main.go
	@mkdir -p $(OUT_DIR)
	@echo "Building $*"
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build $(GOFLAGS) -o $@ ./$(CMD_DIR)/$*

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
clean:
	rm -rf $(OUT_DIR) $(PUBLIC_DIR)
