# fletch Makefile
# Build, test, and lint targets for the reference find/fetch library + CLI.
# Compatible with both GNU make and BSD make.

BINARY = fletch

# Scrub GNU make's jobserver from cargo's environment. Without this, build
# scripts that spawn their own `make` inherit a malformed MAKEFLAGS and fail
# with "No rule to make target '-j'".
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

.PHONY: all build release test lint fix fmt install-precommit clean help

all: build

help: ## Show this help
	@echo "fletch Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build              - Build in debug mode (default)"
	@echo "  release            - Build in release mode"
	@echo "  test               - Run all tests"
	@echo "  lint               - Run clippy with warnings denied"
	@echo "  fix                - Auto-fix clippy lints, then format with rustfmt"
	@echo "  fmt                - Format code with rustfmt"
	@echo "  install-precommit  - Install the git pre-commit hook (lint + test gate)"
	@echo "  clean              - Remove build artifacts"

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets -- -D warnings

# Auto-fix what clippy and rustfmt can fix on their own. Run fmt last so it
# tidies any code clippy rewrote. Mirrors what `lint` checks.
fix:
	$(CARGO) clippy --fix --all-targets --allow-dirty --allow-staged
	$(CARGO) fmt

fmt:
	$(CARGO) fmt

install-precommit:
	cp scripts/pre-commit "$$(git rev-parse --git-dir)/hooks/pre-commit"
	chmod +x "$$(git rev-parse --git-dir)/hooks/pre-commit"
	@echo "Pre-commit hook installed."

clean:
	$(CARGO) clean
