# akvutil Search + Create Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unified `search --type/--name` with glob matching over Resource Graph; help on bare invocation; network/service-access flags on `vault create`; key attributes + rotation policy on `key create`; new `key rotation show/set` and `key rotate` subcommands.

**Architecture:** CLI arg structs live in `src/main.rs` (existing pattern); pure query/parsing helpers live next to their consumers (`src/search.rs`, new `src/timespec.rs`) and are unit-tested; Azure calls go through the existing `src/arm.rs` REST client (control plane) and `azure_security_keyvault_keys` `KeyClient` (data plane).

**Tech Stack:** Rust 1.88, clap 4 (derive), tokio, azure_security_keyvault_keys 1.0, azure_core 1.0 (`azure_core::time` re-exports `OffsetDateTime`, `Duration`, `parse_rfc3339` — no new dependencies).

**Spec:** `docs/superpowers/specs/2026-07-09-search-and-create-expansion-design.md`

## Global Constraints

- No new crate dependencies; use `azure_core::time` for date/duration types.
- All user input embedded in KQL must pass through `kql_escape` (and `regex_escape` first when inside a regex literal).
- Conventional commits (`feat:`, `test:`, `docs:`); run `cargo fmt` before each commit; `cargo clippy -- -D warnings` and `cargo test` must pass at each commit.
- No live-Azure integration tests; unit-test pure functions only, in `#[cfg(test)] mod tests` at the bottom of the file, matching existing style.
- Breaking change accepted: `search vaults [query]` positional form is removed, replaced by `search --type keyvault --name <pattern>`.

**Verified SDK facts (do not re-derive):**
- `KeyClient` has `get_key_rotation_policy(&str, Option<..>) -> Result<Response<KeyRotationPolicy>>`, `update_key_rotation_policy(&str, RequestContent<KeyRotationPolicy>, Option<..>)`, `rotate_key(&str, Option<..>) -> Result<Response<Key>>`.
- `KeyRotationPolicy { attributes: Option<KeyRotationPolicyAttributes>, id: Option<String> /* skip_serializing */, lifetime_actions: Option<Vec<LifetimeAction>> }`.
- `KeyRotationPolicyAttributes { expiry_time: Option<String>, .. }` (created/updated are read-only, `Default` available).
- `LifetimeAction { action: Option<LifetimeActionType>, trigger: Option<LifetimeActionTrigger> }`; `LifetimeActionType { type_prop: Option<KeyRotationPolicyAction> }`; `LifetimeActionTrigger { time_after_create: Option<String>, time_before_expiry: Option<String> }`. All derive `Default`, `Serialize`, `Clone`.
- `KeyRotationPolicyAction::{Notify, Rotate}` derives `PartialEq, Eq, Copy`.
- `KeyAttributes { enabled: Option<bool>, expires: Option<OffsetDateTime>, not_before: Option<OffsetDateTime>, exportable: Option<bool>, .. }` derives `Default`; `CreateKeyParameters` has `key_attributes: Option<KeyAttributes>` and `tags: Option<HashMap<String, String>>`.
- All models convert to request bodies via `.try_into()?` (`RequestContent`), same as the existing `create_key` call.

---

### Task 1: Help on bare invocation

**Files:**
- Modify: `src/main.rs:11-28` (Cli struct attributes) and tests module at bottom

**Interfaces:**
- Produces: no API surface; behavioral change only.

- [ ] **Step 1: Write the failing test**

Append to the existing `mod tests` in `src/main.rs`:

```rust
use clap::Parser as _;

#[test]
fn bare_invocation_shows_help() {
    let err = super::Cli::try_parse_from(["akvutil"]).unwrap_err();
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test bare_invocation_shows_help`
Expected: FAIL — kind is `MissingSubcommand`, not `DisplayHelpOnMissingArgumentOrSubcommand`.

- [ ] **Step 3: Implement**

Add `arg_required_else_help = true` to the `#[command(...)]` attribute on `Cli`:

```rust
#[command(
    name = "akvutil",
    version,
    about = "Azure Key Vault utility: create/migrate vaults and keys, and find resources that use them",
    arg_required_else_help = true
)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test bare_invocation_shows_help`
Expected: PASS. Also sanity-check by eye: `cargo run --quiet 2>&1 | head -5` prints the full help (About + Usage + Commands), exit code 2.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs && git commit -m "feat: print full help when invoked without arguments"
```

---

### Task 2: Wildcard → KQL name predicate

**Files:**
- Modify: `src/search.rs` (add functions below `kql_escape`, extend tests module)

**Interfaces:**
- Consumes: existing `kql_escape(&str) -> String` in `src/search.rs`.
- Produces: `pub fn name_predicate(pattern: &str) -> String` — returns a KQL boolean expression over the `name` column. Task 3 embeds it in queries.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/search.rs`:

```rust
use super::name_predicate;

#[test]
fn plain_name_is_contains() {
    assert_eq!(name_predicate("testfoo"), "name contains 'testfoo'");
}

#[test]
fn trailing_star_is_startswith() {
    assert_eq!(name_predicate("testfoo*"), "name startswith 'testfoo'");
}

#[test]
fn leading_star_is_endswith() {
    assert_eq!(name_predicate("*foo"), "name endswith 'foo'");
}

#[test]
fn internal_star_is_case_insensitive_anchored_regex() {
    assert_eq!(
        name_predicate("te*foo"),
        r"name matches regex '(?i)^te.*foo$'"
    );
}

#[test]
fn multiple_stars_use_regex() {
    assert_eq!(
        name_predicate("*crypto*"),
        r"name matches regex '(?i)^.*crypto.*$'"
    );
}

#[test]
fn kql_injection_is_escaped_in_all_branches() {
    assert_eq!(name_predicate("o'brien"), r"name contains 'o\'brien'");
    assert_eq!(name_predicate(r"\'*"), r"name startswith '\\\''");
    assert_eq!(name_predicate("*'"), r"name endswith '\''");
    // Regex branch: quote must still be KQL-escaped inside the regex literal.
    assert_eq!(
        name_predicate("a'*b*c"),
        r"name matches regex '(?i)^a\'.*b.*c$'"
    );
}

#[test]
fn regex_metacharacters_in_literals_are_escaped() {
    // '.' and '+' must match literally, and the regex backslashes must be
    // doubled by kql_escape so KQL hands the regex engine a single backslash.
    assert_eq!(
        name_predicate("te.st*a+b"),
        r"name matches regex '(?i)^te\\.st.*a\\+b$'"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib search`
Expected: FAIL to compile — `name_predicate` not defined.

- [ ] **Step 3: Implement**

Add below `kql_escape` in `src/search.rs`:

```rust
/// Escape regex metacharacters so a literal chunk of a wildcard pattern
/// cannot alter the regex built around it.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Translate a glob-style pattern into a KQL predicate over `name`.
/// No '*' means substring match; a single leading/trailing '*' anchors the
/// match; anything else compiles to an anchored case-insensitive regex.
/// KQL contains/startswith/endswith are already case-insensitive.
pub fn name_predicate(pattern: &str) -> String {
    let stars = pattern.matches('*').count();
    match stars {
        0 => format!("name contains '{}'", kql_escape(pattern)),
        1 if pattern.ends_with('*') => format!(
            "name startswith '{}'",
            kql_escape(&pattern[..pattern.len() - 1])
        ),
        1 if pattern.starts_with('*') => {
            format!("name endswith '{}'", kql_escape(&pattern[1..]))
        }
        _ => {
            let body = pattern
                .split('*')
                .map(|part| kql_escape(&regex_escape(part)))
                .collect::<Vec<_>>()
                .join(".*");
            format!("name matches regex '(?i)^{body}$'")
        }
    }
}
```

Note the escaping order in the regex branch: regex-escape first (adds `\` before metacharacters), then `kql_escape` (doubles those backslashes for the KQL string literal). Reversing the order would leave single backslashes that KQL consumes before the regex engine sees them.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib search`
Expected: all new tests PASS (plus existing `kql_escape` tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/search.rs && git commit -m "feat: glob-style name predicate for resource graph queries"
```

---

### Task 3: Resource type enum + union query builder

**Files:**
- Modify: `src/main.rs` (add `ResourceType` enum near the other ValueEnums)
- Modify: `src/search.rs` (add `build_search_query`, extend tests)

**Interfaces:**
- Consumes: `name_predicate` from Task 2.
- Produces:
  - In `src/main.rs`: `#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)] pub enum ResourceType { Keyvault, Storage, Des, Rg }` and `impl ResourceType { pub const ALL: [ResourceType; 4] = [ResourceType::Keyvault, ResourceType::Storage, ResourceType::Des, ResourceType::Rg]; }`
  - In `src/search.rs`: `pub fn build_search_query(types: &[ResourceType], name: Option<&str>) -> String` — full KQL for one Resource Graph call. Task 4 executes it.

- [ ] **Step 1: Add the enum to `src/main.rs`** (no test yet; it is exercised by Step 2's tests)

Place after the `MigrateStrategy` enum:

```rust
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ResourceType {
    /// Key vaults (microsoft.keyvault/vaults)
    Keyvault,
    /// Storage accounts (microsoft.storage/storageaccounts)
    Storage,
    /// Disk encryption sets (microsoft.compute/diskencryptionsets)
    Des,
    /// Resource groups
    Rg,
}

impl ResourceType {
    pub const ALL: [ResourceType; 4] = [
        ResourceType::Keyvault,
        ResourceType::Storage,
        ResourceType::Des,
        ResourceType::Rg,
    ];
}
```

- [ ] **Step 2: Write the failing tests**

Add to `mod tests` in `src/search.rs`:

```rust
use super::build_search_query;
use crate::ResourceType;

#[test]
fn single_type_query_has_no_union() {
    assert_eq!(
        build_search_query(&[ResourceType::Keyvault], Some("foo*")),
        "(Resources | where type =~ 'microsoft.keyvault/vaults' \
         | where name startswith 'foo' \
         | project name, type, resourceGroup, location, subscriptionId, id) \
         | order by type asc, name asc"
    );
}

#[test]
fn multi_type_query_unions_branches_and_repeats_filter() {
    let q = build_search_query(&[ResourceType::Storage, ResourceType::Des], Some("prod"));
    assert!(q.starts_with("union ("));
    assert_eq!(q.matches("| where name contains 'prod'").count(), 2);
    assert!(q.contains("'microsoft.storage/storageaccounts'"));
    assert!(q.contains("'microsoft.compute/diskencryptionsets'"));
    assert!(q.ends_with("| order by type asc, name asc"));
}

#[test]
fn rg_branch_uses_resourcecontainers_and_projects_own_name() {
    let q = build_search_query(&[ResourceType::Rg], None);
    assert!(q.contains(
        "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
    ));
    assert!(q.contains("resourceGroup = name"));
    // No name filter when no pattern given.
    assert!(!q.contains("| where name"));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --lib search`
Expected: FAIL to compile — `build_search_query` not defined.

- [ ] **Step 4: Implement**

Add to `src/search.rs` (add `use crate::ResourceType;` to the imports):

```rust
impl ResourceType {
    /// Source table + type filter for this resource type.
    fn branch(self) -> &'static str {
        match self {
            ResourceType::Keyvault => {
                "Resources | where type =~ 'microsoft.keyvault/vaults'"
            }
            ResourceType::Storage => {
                "Resources | where type =~ 'microsoft.storage/storageaccounts'"
            }
            ResourceType::Des => {
                "Resources | where type =~ 'microsoft.compute/diskencryptionsets'"
            }
            ResourceType::Rg => {
                "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
            }
        }
    }

    /// Common projection. Resource groups have no parent group, so they
    /// project their own name into the resourceGroup column.
    fn projection(self) -> &'static str {
        match self {
            ResourceType::Rg => {
                "project name, type, resourceGroup = name, location, subscriptionId, id"
            }
            _ => "project name, type, resourceGroup, location, subscriptionId, id",
        }
    }
}

/// One KQL query covering all requested types — a single Resource Graph
/// call regardless of how many types are searched.
pub fn build_search_query(types: &[ResourceType], name: Option<&str>) -> String {
    let filter = name
        .map(|n| format!(" | where {}", name_predicate(n)))
        .unwrap_or_default();
    let mut branches: Vec<String> = types
        .iter()
        .map(|t| format!("({}{filter} | {})", t.branch(), t.projection()))
        .collect();
    let body = if branches.len() == 1 {
        branches.pop().unwrap()
    } else {
        format!("union {}", branches.join(", "))
    };
    format!("{body} | order by type asc, name asc")
}
```

If the single-type expected string in the test mismatches on whitespace, fix the *test* to match the exact generated string — the KQL is whitespace-insensitive; the test just pins the format.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib search`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs src/search.rs && git commit -m "feat: union query builder for multi-type resource search"
```

---

### Task 4: Wire the unified search CLI

**Files:**
- Modify: `src/main.rs` (replace `SearchCommand`, dispatch)
- Modify: `src/search.rs` (add `resources` runner, delete old `vaults` fn)

**Interfaces:**
- Consumes: `build_search_query` (Task 3), `arm::graph_query`, `output::print_table`/`print_json`.
- Produces: `pub async fn resources(ctx: &Context, types: &[ResourceType], name: Option<&str>, fmt: OutputFormat) -> Result<()>` in `src/search.rs`. CLI shape: `akvutil search [--type t1,t2] [--name pattern]` and `akvutil search usage --vault V`.

- [ ] **Step 1: Restructure the CLI in `src/main.rs`**

Replace the `Search` variant of `Command`:

```rust
    /// Find resources by type and name, or find what uses a vault
    Search(SearchArgs),
```

Replace the existing `SearchCommand` enum with:

```rust
#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SearchArgs {
    #[command(subcommand)]
    pub command: Option<SearchCommand>,

    /// Resource types to search (comma-separated or repeated; default: all)
    #[arg(long = "type", value_enum, value_delimiter = ',')]
    pub types: Vec<ResourceType>,

    /// Name pattern: substring match, or use '*' wildcards (foo*, *foo, f*o)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Subcommand)]
pub enum SearchCommand {
    /// Find resources that use a vault (storage accounts, disk encryption
    /// sets, SQL servers, VMs, etc.)
    Usage {
        /// Vault name
        #[arg(long)]
        vault: String,
    },
}
```

Replace the `Command::Search` dispatch arm in `main()`:

```rust
        Command::Search(args) => match args.command {
            Some(SearchCommand::Usage { vault }) => {
                search::usage(&ctx, &vault, cli.output).await
            }
            None => {
                let mut types = if args.types.is_empty() {
                    ResourceType::ALL.to_vec()
                } else {
                    args.types
                };
                types.sort();
                types.dedup();
                search::resources(&ctx, &types, args.name.as_deref(), cli.output).await
            }
        },
```

- [ ] **Step 2: Replace `vaults` with `resources` in `src/search.rs`**

Delete the `pub async fn vaults(...)` function (lines 22-47 in the current file; `find_vault_id`, `find_usage`, and `usage` stay). Add:

```rust
pub async fn resources(
    ctx: &Context,
    types: &[ResourceType],
    name: Option<&str>,
    fmt: OutputFormat,
) -> Result<()> {
    let kql = build_search_query(types, name);
    let rows = arm::graph_query(ctx, &kql).await?;

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No matching resources found.");
            } else {
                output::print_table(
                    &["NAME", "TYPE", "RESOURCE GROUP", "LOCATION", "SUBSCRIPTION"],
                    &rows,
                    &["name", "type", "resourceGroup", "location", "subscriptionId"],
                );
                println!("\n{} resource(s) found.", rows.len());
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 3: Add a CLI-parsing test**

Append to `mod tests` in `src/main.rs`:

```rust
#[test]
fn search_flags_parse() {
    let cli = super::Cli::try_parse_from([
        "akvutil", "search", "--type", "keyvault,storage", "--name", "testfoo*",
    ])
    .unwrap();
    let super::Command::Search(args) = cli.command else {
        panic!("expected search command");
    };
    assert!(args.command.is_none());
    assert_eq!(
        args.types,
        vec![super::ResourceType::Keyvault, super::ResourceType::Storage]
    );
    assert_eq!(args.name.as_deref(), Some("testfoo*"));
}

#[test]
fn search_usage_subcommand_still_parses() {
    let cli =
        super::Cli::try_parse_from(["akvutil", "search", "usage", "--vault", "myvault"]).unwrap();
    let super::Command::Search(args) = cli.command else {
        panic!("expected search command");
    };
    assert!(matches!(
        args.command,
        Some(super::SearchCommand::Usage { vault }) if vault == "myvault"
    ));
}
```

- [ ] **Step 4: Build and test**

Run: `cargo clippy -- -D warnings && cargo test`
Expected: compiles clean, all tests PASS. Sanity-check help by eye: `cargo run --quiet -- search --help` shows `--type`, `--name`, and the `usage` subcommand.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs src/search.rs && git commit -m "feat: unified search command with --type/--name filters

BREAKING CHANGE: 'search vaults [query]' is replaced by
'search --type keyvault --name <pattern>'"
```

---

### Task 5: Duration and timestamp parsing (`src/timespec.rs`)

**Files:**
- Create: `src/timespec.rs`
- Modify: `src/main.rs:1-6` (add `mod timespec;`)

**Interfaces:**
- Consumes: `azure_core::time::{parse_rfc3339, Duration, OffsetDateTime}`.
- Produces:
  - `pub fn policy_duration(s: &str) -> Result<String>` — `"90d"`/`"3m"`/`"2y"` → `"P90D"`/`"P3M"`/`"P2Y"`; raw ISO-8601 (`P...`) passes through uppercased.
  - `pub fn timestamp(s: &str, now: OffsetDateTime) -> Result<OffsetDateTime>` — RFC-3339 datetime, bare `YYYY-MM-DD` (midnight UTC), or `+<n>d|m|y` relative to `now`.
  Tasks 7-8 consume both.

- [ ] **Step 1: Write the failing tests**

Create `src/timespec.rs`:

```rust
//! Parsing of user-supplied durations (Key Vault rotation policies use
//! ISO-8601 durations) and timestamps (key expiry / not-before).

use anyhow::{bail, Context as _, Result};
use azure_core::time::{parse_rfc3339, Duration, OffsetDateTime};

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        // 2023-11-14T22:13:20Z
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn shorthand_durations() {
        assert_eq!(policy_duration("90d").unwrap(), "P90D");
        assert_eq!(policy_duration("3m").unwrap(), "P3M");
        assert_eq!(policy_duration("2y").unwrap(), "P2Y");
    }

    #[test]
    fn iso8601_passes_through_uppercased() {
        assert_eq!(policy_duration("P90D").unwrap(), "P90D");
        assert_eq!(policy_duration("p1y10d").unwrap(), "P1Y10D");
    }

    #[test]
    fn rejects_bad_durations() {
        for bad in ["", "d", "90", "90x", "-90d", "0d", "P"] {
            assert!(policy_duration(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bare_date_is_midnight_utc() {
        let t = timestamp("2027-01-01", now()).unwrap();
        assert_eq!(t.unix_timestamp(), 1_798_761_600); // 2027-01-01T00:00:00Z
    }

    #[test]
    fn full_rfc3339_passes_through() {
        let t = timestamp("2027-01-01T12:30:00Z", now()).unwrap();
        assert_eq!(t.unix_timestamp(), 1_798_806_600);
    }

    #[test]
    fn relative_days_from_now() {
        let t = timestamp("+90d", now()).unwrap();
        assert_eq!(t - now(), Duration::days(90));
        // months = 30 days, years = 365 days (documented approximation)
        assert_eq!(timestamp("+3m", now()).unwrap() - now(), Duration::days(90));
        assert_eq!(timestamp("+1y", now()).unwrap() - now(), Duration::days(365));
    }

    #[test]
    fn rejects_bad_timestamps() {
        for bad in ["", "tomorrow", "+90", "+x", "2027-13-40"] {
            assert!(timestamp(bad, now()).is_err(), "accepted {bad:?}");
        }
    }
}
```

Add `mod timespec;` to the module list at the top of `src/main.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib timespec`
Expected: FAIL to compile — functions not defined.

- [ ] **Step 3: Implement**

Add above the tests module in `src/timespec.rs`:

```rust
/// Split "<digits><unit-char>" shorthand; returns (n, lowercase unit).
fn split_shorthand(s: &str) -> Option<(u32, char)> {
    let unit = s.chars().last()?;
    if !unit.is_ascii_alphabetic() {
        return None;
    }
    let n: u32 = s[..s.len() - 1].parse().ok()?;
    Some((n, unit.to_ascii_lowercase()))
}

/// Parse a policy duration: "<n>d" (days), "<n>m" (months), "<n>y" (years),
/// or a raw ISO-8601 duration like "P90D" (passed through uppercased).
/// Key Vault policies have no sub-day granularity.
pub fn policy_duration(s: &str) -> Result<String> {
    let t = s.trim();
    if t.len() > 1 && t.to_ascii_uppercase().starts_with('P') {
        return Ok(t.to_ascii_uppercase());
    }
    match split_shorthand(t) {
        Some((n, 'd')) if n > 0 => Ok(format!("P{n}D")),
        Some((n, 'm')) if n > 0 => Ok(format!("P{n}M")),
        Some((n, 'y')) if n > 0 => Ok(format!("P{n}Y")),
        _ => bail!(
            "invalid duration '{s}': expected <n>d, <n>m (months), <n>y, \
             or an ISO-8601 duration like P90D"
        ),
    }
}

/// Parse a timestamp: RFC-3339 datetime, bare date (midnight UTC), or
/// "+<n>d|m|y" relative to `now` (months ≈ 30 days, years ≈ 365 days).
pub fn timestamp(s: &str, now: OffsetDateTime) -> Result<OffsetDateTime> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('+') {
        let days = match split_shorthand(rest) {
            Some((n, 'd')) if n > 0 => i64::from(n),
            Some((n, 'm')) if n > 0 => i64::from(n) * 30,
            Some((n, 'y')) if n > 0 => i64::from(n) * 365,
            _ => bail!("invalid relative time '{s}': expected +<n>d, +<n>m, or +<n>y"),
        };
        return Ok(now + Duration::days(days));
    }
    let full = if t.contains('T') {
        t.to_string()
    } else {
        format!("{t}T00:00:00Z")
    };
    parse_rfc3339(&full).with_context(|| {
        format!("invalid timestamp '{s}': expected RFC-3339 (2027-01-01[T12:30:00Z]) or +<duration>")
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib timespec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/timespec.rs src/main.rs && git commit -m "feat: duration and timestamp parsing for policy and attribute flags"
```

---

### Task 6: Vault create — network access + service toggles

**Files:**
- Modify: `src/main.rs` (VaultCreateArgs, new enums, `parse_ip_rule`, tests)
- Modify: `src/arm.rs` (VaultSpec, create_vault body)
- Modify: `src/vault.rs` (spec construction, warning, summarize/print, migrate defaults)

**Interfaces:**
- Consumes: nothing new.
- Produces: extended `VaultSpec` (all call sites must fill the new fields):
  ```rust
  pub public_network_access: &'a str, // "enabled" | "disabled"
  pub default_action: &'a str,        // "Allow" | "Deny"
  pub bypass: &'a str,                // "AzureServices" | "None"
  pub ip_rules: &'a [String],
  pub enabled_for_deployment: bool,
  pub enabled_for_disk_encryption: bool,
  pub enabled_for_template_deployment: bool,
  ```

- [ ] **Step 1: Write the failing tests for IP-rule validation**

Append to `mod tests` in `src/main.rs`:

```rust
use super::parse_ip_rule;

#[test]
fn accepts_ipv4_and_cidr() {
    assert_eq!(parse_ip_rule("1.2.3.4").unwrap(), "1.2.3.4");
    assert_eq!(parse_ip_rule("10.0.0.0/24").unwrap(), "10.0.0.0/24");
    assert_eq!(parse_ip_rule("0.0.0.0/0").unwrap(), "0.0.0.0/0");
}

#[test]
fn rejects_bad_ip_rules() {
    for bad in ["", "notanip", "1.2.3", "1.2.3.4.5", "1.2.3.4/33", "1.2.3.4/x", "::1"] {
        assert!(parse_ip_rule(bad).is_err(), "accepted {bad:?}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib rejects_bad_ip_rules`
Expected: FAIL to compile — `parse_ip_rule` not defined.

- [ ] **Step 3: Implement CLI surface in `src/main.rs`**

Add next to `parse_tag`:

```rust
fn parse_ip_rule(s: &str) -> Result<String, String> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (s, None),
    };
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("invalid IPv4 address '{s}'"));
    }
    if let Some(p) = prefix {
        if !p.parse::<u8>().is_ok_and(|n| n <= 32) {
            return Err(format!("invalid CIDR prefix in '{s}' (expected /0-/32)"));
        }
    }
    Ok(s.to_string())
}
```

Add enums next to `VaultSku`:

```rust
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum PublicNetworkAccess {
    Enabled,
    Disabled,
}

impl PublicNetworkAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            PublicNetworkAccess::Enabled => "enabled",
            PublicNetworkAccess::Disabled => "disabled",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum NetworkAction {
    Allow,
    Deny,
}

impl NetworkAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkAction::Allow => "Allow",
            NetworkAction::Deny => "Deny",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum NetworkBypass {
    /// Trusted Azure services may bypass the network ACLs
    AzureServices,
    /// No traffic bypasses the network ACLs
    None,
}

impl NetworkBypass {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkBypass::AzureServices => "AzureServices",
            NetworkBypass::None => "None",
        }
    }
}
```

Append to `VaultCreateArgs`:

```rust
    /// Public network access to the vault
    #[arg(long, value_enum, default_value_t = PublicNetworkAccess::Enabled)]
    pub public_network_access: PublicNetworkAccess,
    /// Default network ACL action for traffic not matching an IP rule
    #[arg(long, value_enum, default_value_t = NetworkAction::Allow)]
    pub default_action: NetworkAction,
    /// Allow this IPv4 address or CIDR range (repeatable)
    #[arg(long = "allow-ip", value_parser = parse_ip_rule)]
    pub allow_ip: Vec<String>,
    /// Traffic allowed to bypass the network ACLs
    #[arg(long, value_enum, default_value_t = NetworkBypass::AzureServices)]
    pub bypass: NetworkBypass,
    /// Allow Azure VMs to retrieve certificates stored as secrets
    #[arg(long)]
    pub enabled_for_deployment: bool,
    /// Allow Azure Disk Encryption to retrieve secrets and unwrap keys
    #[arg(long)]
    pub enabled_for_disk_encryption: bool,
    /// Allow ARM template deployments to retrieve secrets
    #[arg(long)]
    pub enabled_for_template_deployment: bool,
```

- [ ] **Step 4: Extend `VaultSpec` and `create_vault` in `src/arm.rs`**

Add the seven fields from the Interfaces block to `VaultSpec`. In `create_vault`, extend the initial `properties` json:

```rust
    let mut properties = json!({
        "tenantId": tenant,
        "sku": { "family": "A", "name": spec.sku },
        "enableRbacAuthorization": spec.rbac,
        "softDeleteRetentionInDays": spec.retention_days,
        "accessPolicies": [],
        "publicNetworkAccess": spec.public_network_access,
        "enabledForDeployment": spec.enabled_for_deployment,
        "enabledForDiskEncryption": spec.enabled_for_disk_encryption,
        "enabledForTemplateDeployment": spec.enabled_for_template_deployment,
        // Defaults ("Allow"/"AzureServices"/no rules) match the service
        // defaults, so always sending networkAcls is behavior-preserving.
        "networkAcls": {
            "defaultAction": spec.default_action,
            "bypass": spec.bypass,
            "ipRules": spec.ip_rules.iter()
                .map(|ip| json!({ "value": ip }))
                .collect::<Vec<_>>(),
        },
    });
```

- [ ] **Step 5: Update `src/vault.rs`**

In `create`, warn on the pointless combination and fill the spec:

```rust
pub async fn create(ctx: &Context, args: &VaultCreateArgs, fmt: OutputFormat) -> Result<()> {
    if !args.allow_ip.is_empty() && args.default_action == crate::NetworkAction::Allow {
        eprintln!(
            "warning: --allow-ip has no effect while --default-action is 'allow'; \
             use --default-action deny to enforce the IP rules"
        );
    }
    let spec = VaultSpec {
        name: &args.name,
        resource_group: &args.resource_group,
        location: &args.location,
        sku: args.sku.as_str(),
        rbac: args.rbac,
        retention_days: args.retention_days,
        purge_protection: args.purge_protection,
        tags: &args.tag,
        public_network_access: args.public_network_access.as_str(),
        default_action: args.default_action.as_str(),
        bypass: args.bypass.as_str(),
        ip_rules: &args.allow_ip,
        enabled_for_deployment: args.enabled_for_deployment,
        enabled_for_disk_encryption: args.enabled_for_disk_encryption,
        enabled_for_template_deployment: args.enabled_for_template_deployment,
    };
    let vault = arm::create_vault(ctx, &spec).await?;
    print_vault(&vault, fmt);
    Ok(())
}
```

In `migrate`'s `VaultSpec` construction, fill the new fields with the behavior-preserving defaults (migrate does not copy network settings this round — spec §3):

```rust
            public_network_access: "enabled",
            default_action: "Allow",
            bypass: "AzureServices",
            ip_rules: &[],
            enabled_for_deployment: false,
            enabled_for_disk_encryption: false,
            enabled_for_template_deployment: false,
```

Extend `summarize` with:

```rust
        "publicNetworkAccess": vault.pointer("/properties/publicNetworkAccess"),
        "networkDefaultAction": vault.pointer("/properties/networkAcls/defaultAction"),
        "networkBypass": vault.pointer("/properties/networkAcls/bypass"),
        "ipRules": vault.pointer("/properties/networkAcls/ipRules")
            .and_then(Value::as_array).map(Vec::len),
        "enabledForDeployment": vault.pointer("/properties/enabledForDeployment"),
        "enabledForDiskEncryption": vault.pointer("/properties/enabledForDiskEncryption"),
        "enabledForTemplateDeployment": vault.pointer("/properties/enabledForTemplateDeployment"),
```

and extend the label list in `print_vault`:

```rust
                ("Public network", "publicNetworkAccess"),
                ("Net default", "networkDefaultAction"),
                ("Net bypass", "networkBypass"),
                ("IP rules", "ipRules"),
                ("For deployment", "enabledForDeployment"),
                ("For disk encrypt", "enabledForDiskEncryption"),
                ("For templates", "enabledForTemplateDeployment"),
```

- [ ] **Step 6: Build and test**

Run: `cargo clippy -- -D warnings && cargo test`
Expected: compiles clean, all tests PASS (including the ip-rule tests from Step 1). Sanity-check: `cargo run --quiet -- vault create --help` lists the seven new flags with defaults.

- [ ] **Step 7: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs src/arm.rs src/vault.rs
git commit -m "feat: network access and service-access options for vault create"
```

---

### Task 7: Key create — attributes + rotation policy

**Files:**
- Modify: `src/main.rs` (KeyCreateArgs)
- Modify: `src/keys.rs` (merge_rotation_policy, create; tests)

**Interfaces:**
- Consumes: `timespec::{policy_duration, timestamp}` (Task 5); SDK models per Global Constraints.
- Produces: `pub fn merge_rotation_policy(policy: KeyRotationPolicy, rotate_after: Option<&str>, notify_before: Option<&str>, policy_expiry: Option<&str>) -> Result<KeyRotationPolicy>` in `src/keys.rs` — overlays the given values onto an existing policy (pass `KeyRotationPolicy::default()` to build from scratch). Task 8 reuses it for `key rotation set`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `src/keys.rs`:

```rust
use azure_security_keyvault_keys::models::KeyRotationPolicy;
use serde_json::json;

#[test]
fn builds_policy_from_scratch() {
    let p = merge_rotation_policy(
        KeyRotationPolicy::default(),
        Some("90d"),
        Some("30d"),
        Some("2y"),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&p).unwrap(),
        json!({
            "attributes": { "expiryTime": "P2Y" },
            "lifetimeActions": [
                { "action": { "type": "Rotate" }, "trigger": { "timeAfterCreate": "P90D" } },
                { "action": { "type": "Notify" }, "trigger": { "timeBeforeExpiry": "P30D" } },
            ],
        })
    );
}

#[test]
fn overlay_replaces_only_given_actions() {
    let existing: KeyRotationPolicy = serde_json::from_value(json!({
        "attributes": { "expiryTime": "P1Y" },
        "lifetimeActions": [
            { "action": { "type": "Rotate" }, "trigger": { "timeAfterCreate": "P30D" } },
        ],
    }))
    .unwrap();
    let p = merge_rotation_policy(existing, Some("90d"), None, None).unwrap();
    let v = serde_json::to_value(&p).unwrap();
    // Rotate trigger updated, expiry preserved, no Notify action invented.
    assert_eq!(v["attributes"]["expiryTime"], "P1Y");
    assert_eq!(v["lifetimeActions"][0]["trigger"]["timeAfterCreate"], "P90D");
    assert_eq!(v["lifetimeActions"].as_array().unwrap().len(), 1);
}

#[test]
fn notify_without_expiry_is_rejected() {
    let err = merge_rotation_policy(KeyRotationPolicy::default(), None, Some("30d"), None)
        .unwrap_err();
    assert!(err.to_string().contains("--policy-expiry"));
}

#[test]
fn bad_duration_propagates() {
    assert!(
        merge_rotation_policy(KeyRotationPolicy::default(), Some("90x"), None, None).is_err()
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib keys`
Expected: FAIL to compile — `merge_rotation_policy` not defined.

- [ ] **Step 3: Implement `merge_rotation_policy` in `src/keys.rs`**

Extend the models import:

```rust
use azure_security_keyvault_keys::{
    models::{
        CreateKeyParameters, CurveName, KeyAttributes, KeyRotationPolicy,
        KeyRotationPolicyAction, KeyType, LifetimeAction, LifetimeActionTrigger,
        LifetimeActionType, RestoreKeyParameters,
    },
    KeyClient, ResourceExt as _,
};
use crate::timespec;
```

Add:

```rust
/// Overlay rotation-policy values onto `policy`. Pass
/// `KeyRotationPolicy::default()` to build a policy from scratch. The
/// service requires an expiry time whenever a Notify action exists, so that
/// combination is rejected here with a actionable message instead of a 400.
pub fn merge_rotation_policy(
    mut policy: KeyRotationPolicy,
    rotate_after: Option<&str>,
    notify_before: Option<&str>,
    policy_expiry: Option<&str>,
) -> Result<KeyRotationPolicy> {
    fn upsert(
        actions: &mut Vec<LifetimeAction>,
        kind: KeyRotationPolicyAction,
        trigger: LifetimeActionTrigger,
    ) {
        let action = LifetimeAction {
            action: Some(LifetimeActionType {
                type_prop: Some(kind),
            }),
            trigger: Some(trigger),
        };
        let existing = actions.iter_mut().find(|a| {
            a.action.as_ref().and_then(|t| t.type_prop) == Some(kind)
        });
        match existing {
            Some(slot) => *slot = action,
            None => actions.push(action),
        }
    }

    let mut actions = policy.lifetime_actions.take().unwrap_or_default();
    if let Some(d) = rotate_after {
        upsert(
            &mut actions,
            KeyRotationPolicyAction::Rotate,
            LifetimeActionTrigger {
                time_after_create: Some(timespec::policy_duration(d)?),
                time_before_expiry: None,
            },
        );
    }
    if let Some(d) = notify_before {
        upsert(
            &mut actions,
            KeyRotationPolicyAction::Notify,
            LifetimeActionTrigger {
                time_after_create: None,
                time_before_expiry: Some(timespec::policy_duration(d)?),
            },
        );
    }
    if let Some(d) = policy_expiry {
        policy
            .attributes
            .get_or_insert_with(Default::default)
            .expiry_time = Some(timespec::policy_duration(d)?);
    }

    let has_expiry = policy
        .attributes
        .as_ref()
        .and_then(|a| a.expiry_time.as_ref())
        .is_some();
    let has_notify = actions.iter().any(|a| {
        a.action.as_ref().and_then(|t| t.type_prop) == Some(KeyRotationPolicyAction::Notify)
    });
    if has_notify && !has_expiry {
        bail!("a notify action requires an expiry time: set --policy-expiry");
    }

    policy.lifetime_actions = Some(actions);
    Ok(policy)
}
```

Add `bail` to the anyhow import: `use anyhow::{bail, Context as _, Result};`

If the first test fails on JSON key ordering or an extra empty field, adjust the *expected JSON* to the actual serialization (the models skip `None` fields, so it should match as written).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib keys`
Expected: PASS.

- [ ] **Step 5: Extend `KeyCreateArgs` in `src/main.rs`**

Append:

```rust
    /// Enable or disable the key (default: service default, enabled)
    #[arg(long, action = clap::ArgAction::Set)]
    pub enabled: Option<bool>,
    /// Expiry: RFC-3339 date/datetime, or +<n>d|m|y from now (e.g. 2027-01-01, +2y)
    #[arg(long)]
    pub expires: Option<String>,
    /// Not-before: RFC-3339 date/datetime, or +<n>d|m|y from now
    #[arg(long = "not-before")]
    pub not_before: Option<String>,
    /// Mark the key exportable (requires a release policy and premium/HSM)
    #[arg(long)]
    pub exportable: bool,
    /// Tags as key=value pairs
    #[arg(long, value_parser = parse_tag)]
    pub tag: Vec<(String, String)>,
    /// Auto-rotate this long after creation (e.g. 90d, P90D)
    #[arg(long = "rotate-after")]
    pub rotate_after: Option<String>,
    /// Notify via Event Grid this long before expiry (requires --policy-expiry)
    #[arg(long = "notify-before")]
    pub notify_before: Option<String>,
    /// Expiry applied to each newly rotated key version (e.g. 2y, P2Y)
    #[arg(long = "policy-expiry")]
    pub policy_expiry: Option<String>,
```

- [ ] **Step 6: Use the new args in `keys::create`**

Replace the body of `pub async fn create` in `src/keys.rs`:

```rust
pub async fn create(ctx: &Context, args: &KeyCreateArgs, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, &args.vault)?;

    // Fail on bad policy flags before creating anything.
    let policy = if args.rotate_after.is_some()
        || args.notify_before.is_some()
        || args.policy_expiry.is_some()
    {
        Some(merge_rotation_policy(
            KeyRotationPolicy::default(),
            args.rotate_after.as_deref(),
            args.notify_before.as_deref(),
            args.policy_expiry.as_deref(),
        )?)
    } else {
        None
    };

    let now = azure_core::time::OffsetDateTime::now_utc();
    let attributes = KeyAttributes {
        enabled: args.enabled,
        expires: args
            .expires
            .as_deref()
            .map(|s| timespec::timestamp(s, now))
            .transpose()?,
        not_before: args
            .not_before
            .as_deref()
            .map(|s| timespec::timestamp(s, now))
            .transpose()?,
        exportable: args.exportable.then_some(true),
        ..Default::default()
    };
    let has_attributes = args.enabled.is_some()
        || args.expires.is_some()
        || args.not_before.is_some()
        || args.exportable;

    let params = CreateKeyParameters {
        kty: Some(args.kty.to_key_type()),
        key_size: args.size,
        curve: args.curve.map(Curve::to_curve_name),
        key_ops: if args.ops.is_empty() {
            None
        } else {
            // KeyOperation is an extensible enum; round-trip through JSON to
            // convert the user's strings.
            Some(serde_json::from_value(json!(args.ops))?)
        },
        key_attributes: has_attributes.then_some(attributes),
        tags: if args.tag.is_empty() {
            None
        } else {
            Some(args.tag.iter().cloned().collect())
        },
        ..Default::default()
    };

    let key = client
        .create_key(&args.name, params.try_into()?, None)
        .await
        .with_context(|| format!("failed to create key '{}'", args.name))?
        .into_model()?;

    if let Some(policy) = policy {
        client
            .update_key_rotation_policy(&args.name, policy.try_into()?, None)
            .await
            .with_context(|| {
                format!("key '{}' was created, but setting its rotation policy failed", args.name)
            })?;
    }

    let kid = key
        .key
        .as_ref()
        .and_then(|k| k.kid.clone())
        .unwrap_or_default();
    match fmt {
        OutputFormat::Json => output::print_json(&json!({ "name": args.name, "kid": kid })),
        OutputFormat::Table => println!("Created key '{}'\n  kid: {kid}", args.name),
    }
    Ok(())
}
```

- [ ] **Step 7: Build and test**

Run: `cargo clippy -- -D warnings && cargo test`
Expected: compiles clean, all tests PASS. Sanity-check: `cargo run --quiet -- key create --help` lists the new flags.

- [ ] **Step 8: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs src/keys.rs
git commit -m "feat: key attributes and rotation policy on key create"
```

---

### Task 8: `key rotation show/set` and `key rotate`

**Files:**
- Modify: `src/main.rs` (KeyCommand variants, dispatch, CLI test)
- Modify: `src/keys.rs` (rotation_show, rotation_set, rotate)

**Interfaces:**
- Consumes: `merge_rotation_policy` (Task 7), `get_key_rotation_policy` / `update_key_rotation_policy` / `rotate_key` (SDK).
- Produces: CLI: `key rotation show|set`, `key rotate`. Functions: `keys::{rotation_show, rotation_set, rotate}` (async, same `(ctx, .., fmt)` shape as siblings).

- [ ] **Step 1: Extend the CLI in `src/main.rs`**

Add variants to `KeyCommand`:

```rust
    /// Show or set a key's rotation policy
    #[command(subcommand)]
    Rotation(RotationCommand),
    /// Rotate a key now (creates a new version per the rotation policy)
    Rotate {
        /// Vault name or full https URI
        #[arg(long)]
        vault: String,
        /// Key name
        #[arg(long)]
        name: String,
    },
```

Add:

```rust
#[derive(Subcommand)]
pub enum RotationCommand {
    /// Show the current rotation policy
    Show {
        /// Vault name or full https URI
        #[arg(long)]
        vault: String,
        /// Key name
        #[arg(long)]
        name: String,
    },
    /// Update the rotation policy (unspecified parts are preserved)
    Set(RotationSetArgs),
}

#[derive(Args)]
pub struct RotationSetArgs {
    /// Vault name or full https URI
    #[arg(long)]
    pub vault: String,
    /// Key name
    #[arg(long)]
    pub name: String,
    /// Auto-rotate this long after creation (e.g. 90d, P90D)
    #[arg(long = "rotate-after")]
    pub rotate_after: Option<String>,
    /// Notify via Event Grid this long before expiry (requires an expiry time)
    #[arg(long = "notify-before")]
    pub notify_before: Option<String>,
    /// Expiry applied to each newly rotated key version (e.g. 2y, P2Y)
    #[arg(long = "policy-expiry")]
    pub policy_expiry: Option<String>,
}
```

Extend the `Command::Key` dispatch:

```rust
            KeyCommand::Rotation(cmd) => match cmd {
                RotationCommand::Show { vault, name } => {
                    keys::rotation_show(&ctx, &vault, &name, cli.output).await
                }
                RotationCommand::Set(args) => keys::rotation_set(&ctx, &args, cli.output).await,
            },
            KeyCommand::Rotate { vault, name } => {
                keys::rotate(&ctx, &vault, &name, cli.output).await
            }
```

Add a parsing test to `mod tests` in `src/main.rs`:

```rust
#[test]
fn key_rotation_set_parses() {
    let cli = super::Cli::try_parse_from([
        "akvutil", "key", "rotation", "set", "--vault", "v", "--name", "k",
        "--rotate-after", "90d",
    ])
    .unwrap();
    let super::Command::Key(super::KeyCommand::Rotation(super::RotationCommand::Set(args))) =
        cli.command
    else {
        panic!("expected key rotation set");
    };
    assert_eq!(args.rotate_after.as_deref(), Some("90d"));
    assert!(args.notify_before.is_none());
}
```

- [ ] **Step 2: Implement the three functions in `src/keys.rs`**

```rust
/// Render a rotation policy as table lines or JSON.
fn print_rotation_policy(policy: &KeyRotationPolicy, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => output::print_json(&serde_json::to_value(policy)?),
        OutputFormat::Table => {
            let expiry = policy
                .attributes
                .as_ref()
                .and_then(|a| a.expiry_time.as_deref())
                .unwrap_or("-");
            println!("{:<22} {expiry}", "Version expiry");
            for action in policy.lifetime_actions.iter().flatten() {
                let kind = action
                    .action
                    .as_ref()
                    .and_then(|t| t.type_prop)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| "?".into());
                let trigger = action.trigger.as_ref();
                let when = match (
                    trigger.and_then(|t| t.time_after_create.as_deref()),
                    trigger.and_then(|t| t.time_before_expiry.as_deref()),
                ) {
                    (Some(d), _) => format!("{d} after creation"),
                    (_, Some(d)) => format!("{d} before expiry"),
                    _ => "-".into(),
                };
                println!("{kind:<22} {when}");
            }
        }
    }
    Ok(())
}

pub async fn rotation_show(
    ctx: &Context,
    vault: &str,
    name: &str,
    fmt: OutputFormat,
) -> Result<()> {
    let client = client(ctx, vault)?;
    let policy = client
        .get_key_rotation_policy(name, None)
        .await
        .with_context(|| format!("failed to read rotation policy for key '{name}'"))?
        .into_model()?;
    print_rotation_policy(&policy, fmt)
}

pub async fn rotation_set(ctx: &Context, args: &RotationSetArgs, fmt: OutputFormat) -> Result<()> {
    if args.rotate_after.is_none() && args.notify_before.is_none() && args.policy_expiry.is_none()
    {
        bail!("nothing to set: pass at least one of --rotate-after, --notify-before, --policy-expiry");
    }
    let client = client(ctx, &args.vault)?;
    // Read-modify-write: the PUT replaces the whole policy, so start from the
    // current one to preserve whatever the caller didn't specify.
    let current = client
        .get_key_rotation_policy(&args.name, None)
        .await
        .with_context(|| format!("failed to read rotation policy for key '{}'", args.name))?
        .into_model()?;
    let merged = merge_rotation_policy(
        current,
        args.rotate_after.as_deref(),
        args.notify_before.as_deref(),
        args.policy_expiry.as_deref(),
    )?;
    let updated = client
        .update_key_rotation_policy(&args.name, merged.try_into()?, None)
        .await
        .with_context(|| format!("failed to update rotation policy for key '{}'", args.name))?
        .into_model()?;
    print_rotation_policy(&updated, fmt)
}

pub async fn rotate(ctx: &Context, vault: &str, name: &str, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, vault)?;
    let key = client
        .rotate_key(name, None)
        .await
        .with_context(|| format!("failed to rotate key '{name}'"))?
        .into_model()?;
    let kid = key
        .key
        .as_ref()
        .and_then(|k| k.kid.clone())
        .unwrap_or_default();
    match fmt {
        OutputFormat::Json => output::print_json(&json!({ "name": name, "kid": kid })),
        OutputFormat::Table => println!("Rotated key '{name}'\n  new version kid: {kid}"),
    }
    Ok(())
}
```

Add `RotationSetArgs` to the `crate::` import list in `src/keys.rs`.

- [ ] **Step 3: Build and test**

Run: `cargo clippy -- -D warnings && cargo test`
Expected: compiles clean, all tests PASS. Sanity-check: `cargo run --quiet -- key rotation set --help` and `-- key rotate --help` render.

- [ ] **Step 4: Commit**

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
git add src/main.rs src/keys.rs
git commit -m "feat: key rotation show/set and manual key rotate commands"
```

---

### Task 9: Documentation + final verification

**Files:**
- Modify: `README.md` (usage examples, if the file exists — check with `ls README.md`; skip the README edits if absent)
- Modify: `CLAUDE.md` (only if it documents commands — it currently doesn't; skip unless changed by earlier tasks)

**Interfaces:** none.

- [ ] **Step 1: Update README usage examples**

If `README.md` exists, update any `search vaults` example to the new form and add a short section (adjust to the README's existing style):

```markdown
## Search

    akvutil search --type keyvault --name 'testfoo*'   # prefix match
    akvutil search --type storage,des,rg --name prod   # substring match
    akvutil search --name '*crypto*'                   # all types
    akvutil search usage --vault myvault               # who uses this vault

`--name` matches substrings by default; `*` wildcards anchor the match
(`foo*` prefix, `*foo` suffix, `f*o` regex).

## Key rotation

    akvutil key create --vault v --name k --rotate-after 90d --policy-expiry 2y
    akvutil key rotation show --vault v --name k
    akvutil key rotation set --vault v --name k --notify-before 30d
    akvutil key rotate --vault v --name k
```

- [ ] **Step 2: Full verification**

Run: `cargo fmt --check && cargo clippy -- -D warnings && cargo test && cargo build --release`
Expected: all clean/PASS.

Smoke-check the CLI surface (no Azure calls):

```bash
cargo run --quiet 2>&1 | head -3                     # full help, not an error line
cargo run --quiet -- search --help
cargo run --quiet -- vault create --help
cargo run --quiet -- key create --help
cargo run --quiet -- key rotation --help
```

Expected: each renders help including the new flags/subcommands.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: usage examples for unified search and key rotation"
```
