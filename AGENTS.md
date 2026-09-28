# Repository Guidelines

## Project Structure & Module Organization

`akvutil` is a Rust 2021 CLI for Azure Key Vault management and resource discovery (Rust 1.88+). `src/main.rs` defines CLI arguments and dispatch. Domain modules include `vault.rs`, `keys.rs`, `search.rs`, and `locations.rs`; shared authentication, ARM requests, output, and time parsing live in the remaining modules. Key operations use the Azure SDK; management and Resource Graph operations use ARM REST. Unit tests live alongside source code. Migration runbooks are in `docs/runbooks/`; design documents are in `docs/superpowers/`. CI and release workflows live in `.github/workflows/`.

## Build, Test, and Development Commands

- `cargo build` / `just build`: build the debug binary.
- `cargo build --release`: build the optimized binary in `target/release/`.
- `cargo run -- search --help`: run the CLI locally.
- `cargo test`: run offline unit tests.
- `cargo fmt`: format Rust code; `cargo fmt --check` verifies formatting.
- `cargo clippy --all-targets -- -D warnings`: lint with warnings treated as errors.
- `just check`: run formatting checks, lint, tests, and dependency auditing; installs `cargo-audit` if missing.

## Coding Style & Naming Conventions

Use rustfmt defaults, including four-space indentation. Use `snake_case` for functions and modules, `PascalCase` for types, and `SCREAMING_SNAKE_CASE` for constants. Follow existing `anyhow::Result` and contextual error-handling patterns. Keep command logic in its domain module and shared ARM behavior in `arm.rs`.

## Testing Guidelines

Use Rust’s built-in `#[test]` functions inside `#[cfg(test)] mod tests`. Name tests after behavior, such as `plain_name_is_contains`. Add offline regression tests for parsing, escaping, query construction, and output changes. Run focused tests with `cargo test search::tests`. No numeric coverage threshold is configured.

## Commit & Pull Request Guidelines

Follow history’s Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, and `chore:`. Use a dedicated task branch and worktree for code changes; preserve user changes and keep primary `main` clean. Describe behavior changes and validation in PRs. Create a public GitHub issue for public tracking and reference it with `Closes #123`; never publish private Linear metadata.

Release-bearing PRs must update `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`; follow `CLAUDE.md` for versioning. Keep `publish = false` only in `release-plz.toml`.

## Security & Configuration

Authenticate with `az login`; set `AZURE_SUBSCRIPTION_ID` or pass `--subscription`. Never commit credentials or key material. Preview migrations with `--dry-run`.

Always use the 1Password Environments MCP Server when working with 1Password developer environments, without requiring an explicit user request.
