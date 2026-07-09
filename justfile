set shell := ["bash", "-euo", "pipefail", "-c"]

binary_name := "akvutil"
version := `grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'`

# List recipes
default:
    @just --list

# ──────────────────────────────── Build ─────────────────────────────────

# Build debug binary
build:
    cargo build

# Build release binary
release:
    cargo build --release

# ──────────────────────────────── Test ──────────────────────────────────

# Run all tests
test:
    cargo test

# Run tests with captured output visible
test-verbose:
    cargo test -- --nocapture

# ──────────────────────────────── Quality ───────────────────────────────

# Run clippy linter (fail on warnings, same flags as CI)
lint:
    cargo clippy --all-targets -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt --check

# Audit dependencies for RUSTSEC advisories (installs cargo-audit if missing)
audit:
    command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked
    cargo audit

# Run everything CI runs: fmt-check + lint + test + audit
check: fmt-check lint test audit

# Full CI pipeline (check + release build)
ci: check
    cargo build --release

# ──────────────────────────────── Install ───────────────────────────────

# Install binary locally
install:
    cargo install --path .

# Uninstall binary
uninstall:
    cargo uninstall {{binary_name}}

# ──────────────────────────────── Develop ───────────────────────────────

# Run the CLI with arguments (e.g. `just run search --help`)
run *args:
    cargo run -- {{args}}

# Setup development environment (install git hooks)
setup:
    git config core.hooksPath .githooks
    @echo "Git hooks installed. Pre-commit will run fmt and clippy."

# Clean build artifacts
clean:
    cargo clean

# Print version (from Cargo.toml)
version:
    @echo {{version}}
