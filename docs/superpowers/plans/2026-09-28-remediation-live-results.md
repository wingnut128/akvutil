# Remediation live validation — 2026-09-28

Tested `akvutil 0.3.4` at commit `d4c222547f9445f470c1687d82802d1761500cd0`, built with the pinned Rust 1.98.1 toolchain using `cargo build --release --locked --offline`. Azure CLI 2.90.0 supplied independent ARM and key-data checks. No application code changes were needed.

The user authorized execution and cleanup in a sandbox subscription in `centralus`, explicitly excluding Managed HSM. The run created five Standard Key Vaults with seven-day retention, software RSA-2048/EC-P256 keys, and two disk encryption sets without attached disks. No Managed HSMs, Premium vaults, VMs, disks, or storage accounts were created. All resources and test role assignments were scoped to one uniquely tagged disposable resource group.

| Phase | Result | Evidence |
| --- | --- | --- |
| Preflight and fixtures | PASS | Live subscription state enabled; caller permissions, registered Key Vault/Compute providers, region support and policy assignments checked. All five vaults verified Standard with seven-day retention. |
| Create/show/list and rotation | PASS | RSA fixture has two versions; EC has one. Explicit rotation produced a second rotation-key version. Updating rotation from P90D to P120D preserved P2Y expiry and P30D notification. |
| Dry runs | PASS | Absent target remained absent with ARM ResourceNotFound; source inventory unchanged. Existing-target vault dry run and both key migration strategies left target configuration and versions unchanged. |
| Recreate migration | PASS | Only selected RSA and EC names copied, one version each; matching type, size/curve and operations, different public key material. |
| Backup/restore migration | PASS | Selected keys retained all source versions, version identifiers and public JWK material; unrelated rotation key excluded. Source inventory unchanged. |
| Restricted target reuse | PASS | Two migrations reported reuse and preserved identical configuration snapshots, including restricted network settings. Only the selected retry key gained two versions. |
| Access-policy target reuse | PASS | Non-RBAC mode and access policy remained unchanged. Restore preserved key versions; repeating restore failed as expected and preserved both keys and configuration. |
| Negative cases | PASS | Both migration commands rejected equivalent endpoints, including uppercase hosts and trailing slashes, across both strategies and dry-run modes. SKU mismatch failed in dry-run and write modes without changing the target. Malformed endpoints failed local validation; valid URI succeeded. |
| Locations and general discovery | PASS | Suffix-filter results matched an independent endswith comparison over all 63 reported locations. Single-type search returned all five vaults; multi-type search also returned the group. |
| Resource Graph usage boundaries | PASS | Independent ARM Resource Graph query confirmed both DES fixtures and source vault IDs were indexed. Each vault usage query included its exact DES ID and excluded the prefix-lookalike fixture. |

## Evidence limits and execution notes

- Before/after configuration snapshots matched exactly. Activity Log queries for the repeat-migration interval returned no events, so they do not independently prove zero vault writes. Offline orchestration tests cover the no-PUT boundary.
- The local harness initially expected REST-shaped rotation-policy JSON; Azure CLI returns `expiresIn` and flattened lifetime actions. The assertion was corrected and execution resumed after completed mutations; key creation and rotation were not repeated.
- Public JWK fingerprints, inventories, configuration snapshots, command exit codes/timings, resource IDs and cleanup evidence are stored privately outside the repository. No access tokens or backup blobs were logged.
- This run validates public Azure in one region from macOS. Other release platforms, sovereign clouds and the documented concurrent GET/PUT provisioning race remain outside this run.

## Cleanup — PASS

The exact group ID and run tag were checked before deletion. Azure confirmed the disposable resource group no longer exists, and all three recorded test role assignments are absent. No active test resources remain. All five vaults are soft-deleted with scheduled retention expiry on 2026-10-05 at 14:35:37 UTC; no vaults were purged.
