# CLAUDE.md

Project-specific instructions for Claude Code. Edit this file to describe:

- **What this project is** — one paragraph of context so a fresh session can orient quickly.
- **Runtime & tooling** — language versions, package manager, lint/format commands, test runner.
- **Commands** — frequently-run commands (dev server, tests, lint, build).
- **Architecture** — directory layout and the purpose of each top-level folder.
- **Conventions** — coding patterns, type-safety rules, error handling, naming.

Claude Code reads this file at the start of every session in this repo.

## Releases

This is a binary crate released via release-plz in `publish = false` mode.
That flag must live **only in `release-plz.toml`** — do NOT add
`publish = false` to `Cargo.toml`: release-plz's `is_publishable()` reads the
cargo metadata field and silently drops the package from the release set
("nothing to release"). In this mode release-plz does **not**
auto-bump the version from conventional commits.

**The version bump rides in the feature PR** (not a separate release
commit): every PR that should cut a release on merge bumps the version in
`Cargo.toml` (and `Cargo.lock` via `cargo update -p akvutil`) and adds a
`CHANGELOG.md` entry as its final commit. Pick the bump level per semver
for a 0.x crate:

- **minor** (0.2.0 → 0.3.0): any breaking change — removed/renamed
  commands or flags, changed output columns or exit codes
- **patch** (0.3.0 → 0.3.1): backward-compatible features and fixes
- **major** (reserved for the 1.0.0 stabilization)

On merge to `main`, release-plz sees the version is ahead of the latest
tag, creates the tag and a draft GitHub Release, and the tag-triggered
`Release` workflow builds binaries, attaches them, and un-drafts the
release. PRs that shouldn't release on merge (docs, CI, refactors) simply
don't bump the version.
