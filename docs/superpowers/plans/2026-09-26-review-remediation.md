# Code Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the five findings from the review of `be7b828..f39e5ae`, preventing destructive migration mistakes and correcting endpoint validation and discovery results.

**Architecture:** Keep fixes in the existing domain modules. Canonicalize endpoints centrally, guard migrations before writes, and separate destination lookup from creation so retries preserve configuration. Extract small pure query and decision helpers for offline regression coverage.

**Tech Stack:** Rust 2024, Rust 1.88+, anyhow, reqwest, serde_json, Azure SDK 1.0, built-in Rust tests.

**Spec:** The acceptance contract below records the five reviewed findings and is the specification for this plan. Baseline: `f39e5ae`, version `0.3.3`; all 45 unit tests, rustfmt, and Clippy passed during review.

## Global Constraints

- Follow `AGENTS.md` and `CLAUDE.md`; implement on a dedicated task branch/worktree and preserve the primary checkout and its untracked `AGENTS.md`.
- Create a public GitHub issue before publishing a PR, and link the PR with `Closes #<issue>`. No private Linear metadata in public content. Planning does not publish either artifact.
- Keep public CLI flags and output formats stable; no new override flag is needed for these fixes.
- Do not change documented recreate semantics: it generates new material and does not copy all source attributes, policies, or network settings.
- Do not claim a confirmed token leak: the endpoint validator is bypassable, but SDK challenge validation is an additional protection.
- Use existing dependencies where possible. Do not add a runtime regex dependency for these fixes.
- Final release-bearing change updates `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`; keep `publish = false` only in `release-plz.toml`.
- No live Azure writes are needed for the required validation. Do not provision resources as part of executing this plan without a separately scoped request.

## Acceptance Contract

| Finding | Required behavior | Introduction |
| --- | --- | --- |
| P1: existing target overwritten | Migration reuses a compatible existing destination without any vault PUT; permissions, firewall, service flags, tags, and RBAC mode remain intact. Only an explicit HTTP 404 permits creation. | `d553822`; firewall reset `c20f4e3` |
| P1: same-vault migration | Equivalent source and target endpoints fail before source enumeration, target provisioning, or key writes, including dry runs. | `d553822` |
| P2: URL validation bypass | Validate the parsed hostname and reject query, fragment, userinfo, explicit port, backslash, controls, and non-root path. Preserve supported Azure cloud suffixes and bare-name behavior. | `c66d1fe` |
| P2: region suffix mismatch | Wildcards match repeated suffixes correctly without overlapping literal segments or losing start/end anchoring. | `1765520` |
| P2: resource-ID prefix matches | Usage discovery matches a complete vault ID or a descendant path, never a different vault with the same prefix. | `d553822` |

## Review Focus

1. Bare names, uppercase hosts, and trailing slashes can identify the same vault: Task 1 and Task 2 tests.
2. Default HTTPS port normalization and URL delimiters must not bypass validation: Task 1 tests.
3. Failed destination lookup must never become permission to create; existing destinations must receive zero writes: Task 3 tests.
4. Repeated final segments and overlapping literals must retain glob semantics: Task 4 tests.
5. JSON serialization and KQL escaping must preserve complete ID boundaries: Task 5 tests.

## File Map and Delivery

| File | Responsibility |
| --- | --- |
| `src/auth.rs` | Endpoint normalization and migration identity guard |
| `src/keys.rs` | Invoke identity guard before building clients or enumerating keys |
| `src/vault.rs` | Early identity guard, safe destination selection, compatibility checks, accurate dry-run/report messages |
| `src/arm.rs` | Optional vault lookup with strict 404 handling, preserving existing retry/error behavior |
| `src/locations.rs` | Correct final anchored glob segment |
| `src/search.rs` | Pure usage-predicate construction with complete resource-ID boundaries |
| `README.md`, `docs/runbooks/constraints.md` | Document destination reuse and same-vault rejection |
| `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` | Patch release metadata |

Use one implementation branch and one PR with five focused fix commits and a final release commit. Tasks 1 → 2 → 3 share migration interfaces; Tasks 4 and 5 are independent. Keep this plan on its documentation branch until execution begins; implementation may start from current main with the plan carried over. Recheck HEAD/version first if main has moved.

---

Rust 2024 migration is a prerequisite added at the user’s request on 2026-09-28; keep the Rust 1.88 minimum and remove process-wide environment mutation from the help test.

### Task 1: Parse and canonicalize vault endpoints

**Files:** Modify/test `src/auth.rs`.

**Interfaces:** Keep `Context::vault_uri(vault: &str) -> Result<String>`. Return a normalized HTTPS endpoint with a lowercase hostname and no trailing slash. Use `reqwest::Url`, already available through the existing dependency.

- [ ] Add regression cases to the existing test module:

```rust
#[test]
fn rejects_url_structure_disguised_as_vault_host() {
    for bad in [
        "https://attacker.example?.vault.azure.net",
        "https://attacker.example#.vault.azure.net",
        "https://foo.vault.azure.net?x=1",
        "https://foo.vault.azure.net#x",
        "https://foo.vault.azure.net:443",
        "https://user@foo.vault.azure.net",
        r"https://attacker.example\.vault.azure.net",
        "https://foo.vault.azure.net/keys",
        "https://foo.vault.azure.net\n",
    ] {
        assert!(Context::vault_uri(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn canonicalizes_equivalent_endpoints() {
    for input in ["MyVault", "https://MYVAULT.vault.azure.net/"] {
        assert_eq!(Context::vault_uri(input).unwrap(),
                   "https://myvault.vault.azure.net");
    }
}
```

- [ ] Run `cargo test auth::tests`; confirm the query/fragment and normalization regressions fail before changing production code.
- [ ] Preserve the existing bare-name validation. For full URLs, reject controls, whitespace, backslashes, query/fragment delimiters, and explicit ports/userinfo before URL normalization. An explicit `:443` must remain rejected even though `Url::port()` normalizes it away. Preserve the current lowercase `https://` input convention; accepting other scheme spellings is outside this patch.
- [ ] Parse using `reqwest::Url::parse`; require scheme `https`, root path, no query/fragment/userinfo, and a nonempty host whose lowercase form ends with a supported `VAULT_SUFFIXES` entry. Validate the actual parsed `host_str()`, not the input suffix. Return `format!("https://{host}")`.
- [ ] Extend positive tests across the existing sovereign-cloud and Managed HSM suffixes, and preserve rejection of foreign suffix lookalikes, HTTP, paths, ports, and invalid bare names. Run `cargo test auth::tests` again.
- [ ] Commit: `fix: validate parsed vault endpoint hosts`.

### Task 2: Reject migrations into the source vault

**Files:** Modify/test `src/auth.rs`, `src/keys.rs`, `src/vault.rs`.

**Interfaces:** Add `pub fn ensure_distinct_vaults(source: &str, target: &str) -> Result<()>` in `auth.rs`; consumes the canonicalization from Task 1. Both migration entry points call it before any network request or mutation.

- [ ] Add tests covering identical bare names, bare name versus URI, uppercase host plus trailing slash, two distinct names, distinct supported cloud endpoints, and malformed inputs:

```rust
#[test]
fn migration_requires_distinct_endpoints() {
    assert!(ensure_distinct_vaults("myvault", "myvault").is_err());
    assert!(ensure_distinct_vaults(
        "myvault", "https://MYVAULT.vault.azure.net/").is_err());
    assert!(ensure_distinct_vaults("myvault", "othervault").is_ok());
    assert!(ensure_distinct_vaults(
        "https://myvault.vault.azure.cn", "myvault").is_ok());
    assert!(ensure_distinct_vaults("bad/name", "othervault").is_err());
}
```

- [ ] Run `cargo test auth::tests`; confirm failure before implementing the helper.
- [ ] Implement the guard:

```rust
pub fn ensure_distinct_vaults(source: &str, target: &str) -> Result<()> {
    if Context::vault_uri(source)? == Context::vault_uri(target)? {
        anyhow::bail!("source and target must identify different vaults");
    }
    Ok(())
}
```

- [ ] Add `crate::auth::ensure_distinct_vaults(source_vault, target_vault)?;` as the first statement of `keys::migrate_keys`; add the equivalent check using `args.source` and `args.target` as the first statement of `vault::migrate`. Apply the guard for both strategies and dry-run mode.
- [ ] Add async tests invoking both public migration functions with equal endpoints and assert the distinct-vault error is returned without credentials being acquired. Construct `Context::new(None)`; use CLI parsing for `VaultMigrateArgs` rather than duplicating defaults. For `migrate_keys`, test both strategies and both dry-run values. These tests must complete without Azure login or network connectivity.
- [ ] Run `cargo test`; commit: `fix: reject same-vault migrations before writes`.

### Task 3: Reuse existing migration destinations safely

**Files:** Modify/test `src/arm.rs`, `src/vault.rs`; document in `README.md` and `docs/runbooks/constraints.md`.

**Interfaces:** Add `arm::get_vault_if_exists(ctx: &Context, name: &str, resource_group: &str) -> Result<Option<Value>>`. Keep `get_vault`'s existing missing-vault error behavior. Add `validate_existing_target(target: &Value, location: &str, sku: &str, retention_days: u32, purge_protection: bool) -> Result<()>` in `vault.rs`.

**Compatibility policy:** Existing location and SKU must match the effective migration request (explicit flags, otherwise inherited source values), compared case-insensitively. Retention must be at least the inherited source retention; if the source has purge protection, the destination must too. Missing/malformed required fields are errors. Preserve existing RBAC mode, permissions, firewall, tags, and service flags, even when different from the source. Error messages name the mismatch and explain that migration will not reconfigure an existing destination.

- [ ] Add unit tests for lookup response classification: valid 200 JSON becomes `Some`, only HTTP 404 becomes `None`, 401/403/429/500 remain errors, and malformed successful bodies fail. Extract a pure response decoder accepting `(reqwest::StatusCode, &str)` as needed. Do not convert arbitrary `anyhow` errors into absence or inspect error strings for `404`.
- [ ] Run `cargo test arm::tests` to establish failing coverage.
- [ ] Refactor `send` just enough to expose the final response status to optional lookup while retaining authentication, retry counts, backoff, and existing error messages. Route only the new lookup through the optional decoder; do not turn 404 into success for unrelated operations.
- [ ] Add compatibility tests using complete JSON fixtures. Cover matching targets, mixed-case location/SKU, longer target retention, stricter purge protection, wrong location/SKU, shorter retention, missing required fields, and RBAC/network settings differing from the source but remaining valid.
- [ ] Add an injectable orchestration seam for destination selection. A small internal async helper can accept lookup and create closures so tests record whether creation was invoked without an HTTP server:

```rust
async fn select_target<L, LF, C, CF, V>(
    lookup: L, create: C, validate: V,
) -> anyhow::Result<(serde_json::Value, bool)>
where
    L: FnOnce() -> LF,
    LF: std::future::Future<Output = anyhow::Result<Option<serde_json::Value>>>,
    C: FnOnce() -> CF,
    CF: std::future::Future<Output = anyhow::Result<serde_json::Value>>,
    V: FnOnce(&serde_json::Value) -> anyhow::Result<()>,
{
    match lookup().await? {
        Some(target) => {
            validate(&target)?;
            Ok((target, false))
        }
        None => Ok((create().await?, true)),
    }
}
```

`bool` means “created”. Keep this helper private to `vault.rs`; its production callers use the real ARM lookup/create functions. Dry-run performs lookup and compatibility checks but never calls the write helper.

- [ ] Test the write boundary directly. An existing restricted/access-policy target must be returned unchanged, with a create closure that panics if called. A lookup error and an incompatible existing target must also leave create uncalled. A missing target invokes create exactly once. Exercise a two-run retry: first lookup returns None and creates; second lookup returns that configured target and performs no PUT.

```rust
let actual = select_target(
    || async { Ok(Some(expected.clone())) },
    || async { panic!("must not write an existing target") },
    |_| Ok(()),
).await.unwrap();
assert_eq!(actual.0, expected);
assert!(!actual.1);
```

- [ ] Wire destination lookup/selection after Task 2's guard and source lookup, before readiness polling and key migration. Report `reusing existing vault` versus `created vault` accurately. Dry-run reports which path would occur, including compatibility failures, and performs no writes. Keep readiness/authorization checks for both paths; a failed check must not trigger reconfiguration.
- [ ] Update README/runbook instructions: retrying preserves destination configuration; same-vault requests fail; existing incompatible targets fail rather than being modified; key-copy operations are not made idempotent by this change. Explain that backup/restore can still reject already restored keys and recreate retries can still create additional versions.
- [ ] Run `cargo test arm::tests`, `cargo test vault::tests`, then `cargo test`. Commit: `fix: preserve existing migration destination settings`.

**Limit:** A GET-before-PUT check does not provide atomic exclusion against another actor creating the same vault concurrently. Do not claim concurrency safety or invent an unsupported Azure conditional-create header. Cross-actor provisioning coordination is outside these five findings.

### Task 4: Correct region glob suffix matching

**Files:** Modify/test `src/locations.rs`.

**Interfaces:** Preserve `name_matches(pattern: &str, name: &str) -> bool` and current case-insensitive substring/glob semantics.

- [ ] Add the regression matrix:

```rust
#[test]
fn anchored_suffix_uses_final_occurrence_without_overlap() {
    for (pattern, name, expected) in [
        ("*south", "southafricasouth", true),
        ("*a", "eastasia", true),
        ("south*south", "southafricasouth", true),
        ("a*a", "a", false),
        ("ab*bc", "abc", false),
        ("a*a", "aba", true),
        ("east*a", "eastasia", true),
        ("west*a", "eastasia", false),
        ("**SOUTH", "southafricasouth", true),
        ("***", "eastasia", true),
        ("*south", "southafrica", false),
    ] {
        assert_eq!(name_matches(pattern, name), expected,
                   "{pattern:?} against {name:?}");
    }
}
```

- [ ] Run `cargo test locations::tests`; verify current suffix cases fail.
- [ ] Change the final anchored segment handling inside the segment loop. For that segment compute `name.len().checked_sub(seg.len())`; require `name.ends_with(seg)` and suffix start `>= pos`, plus suffix start `== 0` when it is also the first start-anchored segment. Return that result instead of greedily finding its first occurrence. Earlier segments retain their existing ordered search and start anchoring. Preserve the no-star substring branch and all-star behavior.
- [ ] Run `cargo test locations::tests`; commit: `fix: match repeated suffixes in location filters`.

### Task 5: Bound vault resource-ID matches in usage queries

**Files:** Modify/test `src/search.rs`.

**Interfaces:** Extract `fn usage_predicate(uri: &str, vault_id: Option<&str>) -> String` and use it from `find_usage`. Inputs are raw values; the helper owns JSON serialization and KQL escaping exactly once.

- [ ] Add query-construction regressions for a complete ID, descendant IDs, prefix lookalikes, case-insensitive operators, and quotes/backslashes. Test both lookup-present and lookup-absent branches. Keep existing URI behavior within this task's scope.
- [ ] Use complete serialized JSON string tokens for exact IDs and a quoted prefix ending in `/` for descendants. For ID `/subscriptions/s/resourceGroups/r/providers/Microsoft.KeyVault/vaults/prod`, predicates must search for `"/subscriptions/.../vaults/prod"` or `"/subscriptions/.../vaults/prod/`, never a bare `.../prod` substring. Build the tokens before applying `kql_escape`:

```rust
let exact = serde_json::to_string(id).expect("serializing a string cannot fail");
let child = serde_json::to_string(&format!("{id}/"))
    .expect("serializing a string cannot fail");
let child_prefix = &child[..child.len() - 1]; // remove the closing JSON quote
let id_predicate = format!(
    "tostring(properties) contains '{}' or tostring(properties) contains '{}'",
    kql_escape(&exact), kql_escape(child_prefix),
);
```

- [ ] Before implementing, run `cargo test search::tests` with the new expected-query tests and confirm failure. After implementing, check serialized fixtures for exact `prod`, `prod/keys/k`, `prod-old`, `production`, and another resource group; only the first two must match ID tokens. Include a fixture with casing differences by applying the same case-insensitive comparison as KQL `contains` in the local token test.
- [ ] Ensure the production query still excludes vault resources, retains its projection/order, and leaves URI discovery available when the vault ID cannot be found. Parenthesize the OR predicate where composed with other filters.
- [ ] Run `cargo test search::tests`; commit: `fix: bound vault IDs in usage search`.

**Validation limit:** Offline tests verify token semantics and escaping, not Azure's KQL execution. If an authorized read-only test subscription is available, run a usage query against similarly named vault references; otherwise record the live-query gap in the PR.

### Live acceptance routine

Execute [the live test runbook](2026-09-26-review-remediation-live-tests.md) against the patched binary when the user supplies an authorized sandbox subscription, region, and test principal. It covers create/show/list, rotation, both migration strategies, dry runs, pre-existing target preservation, identity rejection, and actual Resource Graph prefix matching. It provisions disposable Azure resources and is a separate execution stage from writing this plan. Offline checks remain the default CI gate; the full live suite is a manual acceptance gate, with any omitted phase reported explicitly.

### Task 6: Release and final verification

**Files:** Modify `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`; review all changed files.

- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`. Confirm regression tests exercise production helpers and mutation ordering, not duplicate unused implementations.
- [ ] Bump `0.3.3` to `0.3.4` if no intervening release has landed. These fixes reject unsafe/invalid inputs and restore intended behavior without redesigning supported commands. Update only the local package entry in the lockfile through Cargo; avoid unrelated dependency updates.
- [ ] Add a dated `0.3.4` changelog entry naming all five fixes. Document migration destination reuse and rejection behavior. Do not describe the URL finding as proven credential exfiltration.
- [ ] Run `cargo build --release --locked` and `cargo audit` (or the corresponding `just` tasks). If registry/advisory access is unavailable, report that check as unverified rather than passed.
- [ ] Review the final diff against all five acceptance rows, then commit `chore: release v0.3.4`. Perform a fresh code review before presenting the implementation as ready.
- [ ] If publishing is requested, create the public tracking issue first, then a PR referencing it with behavior changes, regression coverage, and validation limitations. Do not merge or publish a release as part of planning.

## Completion Criteria

All five findings have regression coverage; existing destination configuration receives no migration PUT; same-vault requests fail before writes; formatting, lint, tests, release build, and dependency audit are accounted for. Public release metadata stays synchronized. Required validation uses no live Azure mutations, and any unperformed live query verification is clearly reported.
