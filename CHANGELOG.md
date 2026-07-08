# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
