# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-07-09

### Added

- `justfile` with recipes for building, testing, linting, auditing,
  installing, and running the CLI (`just --list` to enumerate); `just check`
  runs the same fmt/clippy/test/audit pipeline as CI

## [0.3.0] - 2026-07-09

### Changed (BREAKING)

- `search vaults [query]` is replaced by the unified
  `search --type keyvault --name <pattern>`; the search table now shows
  NAME/TYPE/RESOURCE GROUP/LOCATION/SUBSCRIPTION instead of the
  vault-specific SKU/RBAC/URI columns

### Added

- `search --type keyvault|storage|des|rg --name <pattern>` — one Resource
  Graph query across key vaults, storage accounts, disk encryption sets,
  and resource groups; substring match by default, `*` wildcards anchor
  (`foo*` prefix, `*foo` suffix, `f*o` regex), injection-safe escaping
- Full help when invoked without arguments (exit 2, on stderr)
- `vault create`: `--public-network-access`, `--default-action`,
  `--allow-ip` (validated IPv4/CIDR, repeatable), `--bypass`, and
  `--enabled-for-deployment` / `--enabled-for-disk-encryption` /
  `--enabled-for-template-deployment`; `vault show` displays the new fields
- `key create`: attributes (`--enabled`, `--expires`, `--not-before`,
  `--exportable`, `--tag`) and rotation policy (`--rotate-after`,
  `--notify-before`, `--policy-expiry`, accepting `90d`/`3m`/`2y` or
  ISO-8601 like `P90D`), validated client-side before the key is created
- `key rotation show` / `key rotation set` — inspect or update a key's
  rotation policy (read-modify-write; unspecified parts are preserved)
- `key rotate` — manually rotate a key to a new version

### Fixed

- `vault migrate` now notes that network settings are not copied from the
  source vault

## [0.2.0] - 2026-07-08

### Security

- Reject a `--vault` URI whose host is not a known Key Vault / Managed HSM
  domain, so the data-plane token (and, during `key migrate`, exported key
  backups) can no longer be sent to an arbitrary host
- Fix KQL escaping in `search` (escape backslashes, not just quotes) so a
  crafted vault name or query cannot break out of the query string
- Percent-encode subscription, resource group, and vault name in ARM
  request URLs

### Fixed

- `vault migrate` now waits for a newly-created vault's data plane (DNS and
  RBAC role propagation) before migrating keys, instead of racing it into a
  spurious 403
- `search usage` no longer matches unrelated vaults whose name is a suffix
  (e.g. `foo` matched `barfoo.vault.azure.net`)
- ARM responses with non-JSON error bodies (gateway 502/503, empty) surface
  the real response instead of "no error detail"; ARM and Resource Graph
  requests retry on 429/5xx honoring `Retry-After`

## [0.1.0] - 2026-07-08

### Added

- `vault create` / `vault show` — create and inspect key vaults (SKU,
  purge protection, retention, tags) via the ARM REST API
- `vault migrate` — create a target vault inheriting source settings,
  move keys, and report resources still pointing at the source vault
- `key create` / `key list` — RSA, EC, and octet keys (standard or HSM)
  through the GA `azure_security_keyvault_keys` 1.0 data-plane SDK
- `key migrate` — `backup-restore` (preserves material and versions,
  same-geography only) or `recreate` (same-shape keys, new material)
- `search vaults` / `search usage` — Azure Resource Graph queries for
  vaults and for resources that reference a given vault
- `--output table|json` on every command; subscription via
  `--subscription` or `AZURE_SUBSCRIPTION_ID`
