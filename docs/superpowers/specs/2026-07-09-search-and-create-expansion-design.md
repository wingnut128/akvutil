# akvutil: search + create expansion — design

Date: 2026-07-09
Status: approved

## Goal

Expand akvutil in four areas:

1. A unified `search` command over Azure Resource Graph covering key vaults,
   storage accounts, disk encryption sets, and resource groups, with
   glob-style name matching.
2. Print full help when the binary is invoked with no arguments.
3. Richer `vault create`: network access controls and Azure service access
   toggles.
4. Richer `key create`: key attributes and rotation policy, plus new
   `key rotation show/set` and `key rotate` subcommands.

## 1. CLI surface

```
akvutil                                  → prints full help (arg_required_else_help)
akvutil search --type keyvault --name 'testfoo*'
akvutil search --type storage,des,rg    # comma-separated or repeated flag
akvutil search --name '*crypto*'        # no --type = all four types
akvutil search usage --vault myvault    # unchanged
akvutil vault create ... --public-network-access disabled --default-action deny \
    --allow-ip 1.2.3.4/32 --bypass azure-services \
    --enabled-for-deployment --enabled-for-disk-encryption \
    --enabled-for-template-deployment
akvutil key create ... --rotate-after 90d --notify-before 30d --policy-expiry 2y \
    --expires 2027-01-01 --not-before 1d --enabled true --exportable --tag env=prod
akvutil key rotation show --vault V --name K
akvutil key rotation set  --vault V --name K --rotate-after 90d \
    [--notify-before ...] [--policy-expiry ...]
akvutil key rotate        --vault V --name K     # manual rotation, new version now
```

- `Search` becomes an `Args` struct with `--type`/`--name` flags plus an
  optional `usage` subcommand, using `args_conflicts_with_subcommands = true`.
- **Breaking change (accepted):** the old `search vaults [query]` positional
  form is replaced by `search --type keyvault --name <pattern>`.
- `--type` is a clap `ValueEnum` with variants `keyvault | storage | des | rg`,
  accepted comma-separated (`value_delimiter = ','`) or repeated.
- Both flags are optional: omitting `--type` searches all four types; omitting
  `--name` applies no name filter. A bare `akvutil search` therefore lists all
  resources of the four types across the subscription.
- No-args help: `arg_required_else_help = true` on the top-level `Cli`
  (subcommand-level invocations like bare `akvutil vault` keep clap's default
  behavior).

## 2. Search implementation (`src/search.rs`)

### Wildcard → KQL predicate

A pure function `name_predicate(pattern: &str) -> String` translating a
glob-style pattern into a KQL boolean expression over `name`:

| Pattern    | KQL                                        |
|------------|--------------------------------------------|
| `testfoo`  | `name contains 'testfoo'`                  |
| `testfoo*` | `name startswith 'testfoo'`                |
| `*foo`     | `name endswith 'foo'`                      |
| `te*foo` (internal or multiple `*`) | `name matches regex '(?i)^te.*foo$'` |

All matching is case-insensitive (`contains`/`startswith`/`endswith` are
already case-insensitive in KQL; the regex form gets a `(?i)` prefix).
Literal parts are passed through the existing `kql_escape`, and in the regex
form additionally regex-escaped, so injection safety is preserved. Unit-tested
in the same style as `kql_escape`.

### Type → query mapping

| `--type`   | Resource Graph source |
|------------|-----------------------|
| `keyvault` | `Resources \| where type =~ 'microsoft.keyvault/vaults'` |
| `storage`  | `Resources \| where type =~ 'microsoft.storage/storageaccounts'` |
| `des`      | `Resources \| where type =~ 'microsoft.compute/diskencryptionsets'` |
| `rg`       | `ResourceContainers \| where type =~ 'microsoft.resources/subscriptions/resourcegroups'` |

### Query shape

One KQL `union` across the selected sources — a single Resource Graph API
call regardless of how many types are requested. Each branch projects a
common column set: `name, type, resourceGroup, location, subscriptionId, id`
(resource groups project their own name as `resourceGroup`). Results ordered
by `type asc, name asc`. Table output shows NAME / TYPE / RESOURCE GROUP /
LOCATION / SUBSCRIPTION; `--output json` prints the raw rows as today.

`search usage` and `find_vault_id` are unchanged.

## 3. Vault create (`src/arm.rs`, `src/vault.rs`, `src/main.rs`)

New `VaultCreateArgs` flags and their ARM mapping:

| Flag | ARM property | Default |
|------|--------------|---------|
| `--public-network-access enabled\|disabled` | `properties.publicNetworkAccess` | `enabled` |
| `--default-action allow\|deny` | `properties.networkAcls.defaultAction` | `allow` |
| `--allow-ip <CIDR or IP>` (repeatable) | `properties.networkAcls.ipRules[]` | none |
| `--bypass azure-services\|none` | `properties.networkAcls.bypass` (`AzureServices`/`None`) | `azure-services` |
| `--enabled-for-deployment` | `properties.enabledForDeployment` | false |
| `--enabled-for-disk-encryption` | `properties.enabledForDiskEncryption` | false |
| `--enabled-for-template-deployment` | `properties.enabledForTemplateDeployment` | false |

- `VaultSpec` grows matching fields; defaults preserve current behavior
  exactly, so `vault migrate`'s spec construction keeps working (migrate does
  not copy network settings this round).
- Validation: `--allow-ip` values are syntactically checked (IPv4 or IPv4/CIDR)
  client-side. `--allow-ip` combined with `--default-action allow` is legal but
  pointless → print a warning to stderr, don't error.
- `vault show` / `print_vault` output gains the new fields (public network
  access, default action, ip rule count, bypass, the three toggles).

## 4. Key create + rotation (`src/keys.rs`, `src/main.rs`)

### Duration/date parsing

One pure parser module:

- **Durations** (`--rotate-after`, `--notify-before`, `--policy-expiry`):
  accept shorthands `<n>d`/`<n>m`/`<n>y` (days/months/years — `m` is months,
  matching Key Vault policy granularity; there are no sub-day durations) and
  raw ISO-8601 (`P90D`, `P2Y`). Normalized to ISO-8601 strings for the API.
- **Timestamps** (`--expires`, `--not-before`): accept RFC-3339
  (`2027-01-01` or full datetime) or `+<duration>` relative to now.

Unit-tested.

### Key attributes on create

`--enabled true|false`, `--expires`, `--not-before`, `--exportable`,
`--tag key=value` (repeatable, reusing `parse_tag`) map onto
`CreateKeyParameters` attributes and tags.

### Rotation policy

- On `key create`, when any of `--rotate-after`/`--notify-before`/
  `--policy-expiry` is given, call `update_key_rotation_policy` after
  `create_key` with:
  - lifetime action `Rotate` triggered by `timeAfterCreate = rotate-after`
  - lifetime action `Notify` triggered by `timeBeforeExpiry = notify-before`
  - `attributes.expiryTime = policy-expiry`
- Client-side validation mirrors Azure's rules: `--notify-before` requires an
  expiry time (`--policy-expiry`), with a clear error message.
- `key rotation show` prints the current policy (table or JSON);
  `key rotation set` writes it with the same three flags (at least one
  required).
- `key rotate` calls the data-plane `rotate_key` and prints the new
  version's kid.
- SDK note: verify exact method names/models in
  `azure_security_keyvault_keys` 1.0 during planning; if rotation-policy
  endpoints are missing from the crate, fall back to a raw data-plane REST
  call via the existing `reqwest` client pattern.

### Scoped out

- `vault migrate` / `key migrate --strategy recreate` does **not** copy
  rotation policies or key attributes to the target (follow-up candidate;
  migrate output will not mention policies).

## 5. Testing

Unit tests for the pure parts, matching existing repo style (no live-Azure
integration tests):

- `name_predicate`: all four pattern shapes, injection attempts
  (`*'` / `\'` payloads), regex metacharacters in literals.
- Duration/timestamp parsing: shorthands, ISO-8601 passthrough, rejects.
- `--allow-ip` syntax validation.
- KQL union assembly for type combinations (string-level assertions).
