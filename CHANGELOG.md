# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
