# CLAUDE.md

Project-specific instructions for Claude Code. Edit this file to describe:

- **What this project is** — one paragraph of context so a fresh session can orient quickly.
- **Runtime & tooling** — language versions, package manager, lint/format commands, test runner.
- **Commands** — frequently-run commands (dev server, tests, lint, build).
- **Architecture** — directory layout and the purpose of each top-level folder.
- **Conventions** — coding patterns, type-safety rules, error handling, naming.

Claude Code reads this file at the start of every session in this repo.

## Releases

This is a binary crate (`publish = false`), so release-plz does **not**
auto-bump the version from conventional commits. To cut a release: bump the
version in `Cargo.toml` (and `Cargo.lock` via `cargo update -p akvutil`),
update `CHANGELOG.md` if desired, and commit `chore: release vX.Y.Z` to
`main`. release-plz then creates the tag and a draft GitHub Release, and the
tag-triggered `Release` workflow builds binaries, attaches them, and
un-drafts the release.
