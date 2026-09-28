# Review Remediation Live Test Routine

**Purpose:** Exercise the patched CLI end to end against disposable Azure resources, including every finding in [the implementation plan](2026-09-26-review-remediation.md).

**Status:** Executed successfully on 2026-09-28; scoped cleanup completed. See [the live validation report](2026-09-28-remediation-live-results.md) for results and evidence limits. For future runs, build the patched branch before running this routine; do not use the installed `akvutil` accidentally.

## Execution Contract

- Use one explicitly selected nonproduction Azure subscription, one supported public-Azure region, and a new uniquely named resource group. All writes and role assignments stay inside that group.
- Required inputs: subscription ID, region, caller principal object ID/type, and the runner's stable public IPv4 address/CIDR for the firewall test. Obtain these at execution time; do not infer permission from the CLI's currently selected subscription.
- The runner needs resource creation/deletion permissions, scoped role-assignment permission, and access-policy management for the disposable group. Preflight `Microsoft.KeyVault` and `Microsoft.Compute` provider registration and relevant Azure Policy constraints. Report policy restrictions rather than weakening subscription policy.
- Standard software keys suffice. Do not provision Managed HSM, VMs, disks, or storage accounts. The Resource Graph fixture uses two disk encryption sets without attached disks.
- Use 7-day soft-delete retention for new test vaults when policy permits. The final Resource Graph phase enables purge protection on its two source fixtures; those names will remain reserved through retention after deletion. Purge protection cannot be switched off. No purge is part of this routine.
- Store private evidence outside the repository, with `umask 077`. Record commands, exit codes, resource IDs, versions, public JWK fingerprints, before/after configuration, and timings. Never log access tokens or backup blobs.
- Use bounded readiness retries: up to 10 minutes for RBAC/DNS/Resource Graph propagation, polling every 10 seconds. Stop/report on timeout. Do not blindly retry mutating commands: recreate legitimately adds versions.
- Planning does not authorize running these commands. Execution should encompass creation, test writes, and scoped cleanup as one explicit live-test task.

Azure reference constraints: [backup/restore geography and subscription boundaries](https://learn.microsoft.com/en-us/azure/key-vault/general/overview-security-worlds), [soft-delete and recovery](https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery), and [disk encryption set setup](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-enable-customer-managed-keys-cli).

## 1. Build, select inputs, and create an isolated fixture group

Use Bash for the command examples. Supply the four required environment values before execution. `AKV_TEST_PRINCIPAL_TYPE` is `User` or `ServicePrincipal` for the actual authenticated runner; a managed identity also uses `ServicePrincipal`.

```bash
set -euo pipefail
umask 077
: "${AKV_TEST_SUBSCRIPTION:?supply an authorized sandbox subscription}"
: "${AKV_TEST_LOCATION:?supply the test region}"
: "${AKV_TEST_PRINCIPAL_ID:?supply the authenticated caller object ID}"
: "${AKV_TEST_PRINCIPAL_TYPE:?supply User or ServicePrincipal}"
: "${AKV_TEST_RUNNER_CIDR:?supply the stable public runner IPv4/CIDR}"

cargo build --release --locked
AKV_BIN="$PWD/target/release/akvutil"
AKV_RUN_ID="$(date -u +%y%m%d)$(openssl rand -hex 3)"
AKV_RG="akvutil-live-$AKV_RUN_ID"
AKV_SRC="av-$AKV_RUN_ID-s"
AKV_LOOKALIKE="$AKV_SRC-old"
AKV_RECREATE="av-$AKV_RUN_ID-r"
AKV_RESTORE="av-$AKV_RUN_ID-b"
AKV_POLICY="av-$AKV_RUN_ID-p"
AKV_DRY="av-$AKV_RUN_ID-d"
AKV_EVIDENCE="$(mktemp -d /tmp/akvutil-live.XXXXXX)"

akv() { "$AKV_BIN" --subscription "$AKV_TEST_SUBSCRIPTION" "$@"; }
azt() { az "$@" --subscription "$AKV_TEST_SUBSCRIPTION"; }

azt account show --query '{id:id,tenantId:tenantId,name:name}' -o json
test "$(azt group exists --name "$AKV_RG" -o tsv)" = false
azt group create --name "$AKV_RG" --location "$AKV_TEST_LOCATION" \
  --tags purpose=akvutil-live-test run="$AKV_RUN_ID"
AKV_RG_ID="$(azt group show --name "$AKV_RG" --query id -o tsv)"
azt role assignment create --assignee-object-id "$AKV_TEST_PRINCIPAL_ID" \
  --assignee-principal-type "$AKV_TEST_PRINCIPAL_TYPE" \
  --role 'Key Vault Crypto Officer' --scope "$AKV_RG_ID"
```

The group-scoped data-plane role covers vaults subsequently created by migration. This avoids depending on a vault-specific assignment appearing during the CLI's three-minute readiness window. Wait for effective data-plane access after source creation; if propagation still exceeds the CLI window later, record it and retry only after inventorying the destination.

Record the exact binary commit, `akv --version`, `az version`, input resource names, group ID, and role assignment ID in the evidence directory. Check vault name availability before creating each vault; generate a fresh run ID if any name is already active or soft-deleted. Never reuse an existing resource group.

## 2. Create, show, key inventory, and rotation

```bash
akv vault create --name "$AKV_SRC" -g "$AKV_RG" \
  -l "$AKV_TEST_LOCATION" --retention-days 7 --tag purpose=akvutil-live-test
akv --output json vault show --name "$AKV_SRC" -g "$AKV_RG"
akv --output json key list --vault "$AKV_SRC"
```

Wait until list succeeds, then create two versions of the RSA fixture and one EC fixture. Use a separate key for rotation so migration fingerprint comparisons remain stable.

```bash
akv key create --vault "$AKV_SRC" --name rsa-copy --kty rsa --size 2048 \
  --ops encrypt,decrypt,wrapKey,unwrapKey
akv key create --vault "$AKV_SRC" --name rsa-copy --kty rsa --size 2048 \
  --ops encrypt,decrypt,wrapKey,unwrapKey
akv key create --vault "$AKV_SRC" --name ec-copy --kty ec --curve p-256 \
  --ops sign,verify
akv key create --vault "$AKV_SRC" --name rotation-only --kty rsa --size 2048 \
  --rotate-after 90d --policy-expiry 2y --notify-before 30d
akv key rotation show --vault "$AKV_SRC" --name rotation-only
akv key rotation set --vault "$AKV_SRC" --name rotation-only --rotate-after 120d
akv key rotate --vault "$AKV_SRC" --name rotation-only
akv --output json key list --vault "$AKV_SRC"
```

**Assert:** ARM reports standard SKU, RBAC enabled, expected location and 7-day retention. There are three distinct key names. Azure CLI `key list-versions` reports two `rsa-copy` versions and an increased rotation-only version count. The rotation policy now uses 120 days and retains the original expiry/notification settings.

Use `az keyvault key show`/`list-versions` as the independent data-plane oracle. Capture each selected version's `kty`, `n/e` for RSA or `crv/x/y` for EC, operations, and version identifier. Compare public material only; do not export private keys or persist backups.

## 3. Dry-run guarantees

```bash
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_DRY" --target-rg "$AKV_RG" \
  --keys rsa-copy,ec-copy --strategy recreate --dry-run --report-usage false
```

**Assert:** Output says the target would be created; an ARM GET returns 404 afterward; source names/version counts remain unchanged. Do not interpret 403 or a transport failure as proof the target is absent. Repeat the dry-run against an existing destination after Phase 4 and assert no configuration or key-version changes. Also run `key migrate --dry-run` for both strategies and compare version inventories before/after.

## 4. New-vault migration: recreate and backup/restore

```bash
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_RECREATE" --target-rg "$AKV_RG" \
  --keys rsa-copy,ec-copy --strategy recreate --report-usage false
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_RESTORE" --target-rg "$AKV_RG" \
  --keys rsa-copy,ec-copy --strategy backup-restore --report-usage false
```

**Assert for recreate:** Destination contains only the selected names, with one version each; RSA size, EC curve, and operations match the source, but public key material differs. Source keys and versions remain unchanged. Do not assert attribute/tag/rotation-policy copying: it is outside recreate's documented contract.

**Assert for backup/restore:** Destination contains both RSA versions and the EC version; compare version identifiers and public material against the source for every version. Vault portions of key URIs must differ. `rotation-only` is absent. Same region/subscription satisfies the backup/restore boundary.

If a command fails after partial progress, record destination inventory before any retry. A repeat backup/restore into an occupied key name is expected to fail; it must leave the restored versions intact. A recreate retry may add versions and must not be described as idempotent.

## 5. Preserve an existing restricted destination on repeat runs

Configure only the disposable recreate target using Azure CLI, then capture a stable configuration projection:

```bash
azt keyvault network-rule add --name "$AKV_RECREATE" \
  --resource-group "$AKV_RG" --ip-address "$AKV_TEST_RUNNER_CIDR"
azt keyvault update --name "$AKV_RECREATE" --resource-group "$AKV_RG" \
  --default-action Deny --bypass None --public-network-access Enabled

vault_config() {
  azt keyvault show --name "$1" --resource-group "$AKV_RG" \
    --query '{tags:tags,sku:properties.sku,rbac:properties.enableRbacAuthorization,policies:properties.accessPolicies,network:properties.networkAcls,public:properties.publicNetworkAccess,retention:properties.softDeleteRetentionInDays,purge:properties.enablePurgeProtection,deployment:properties.enabledForDeployment,disk:properties.enabledForDiskEncryption,template:properties.enabledForTemplateDeployment}' \
    -o json | jq -S .
}
vault_config "$AKV_RECREATE" > "$AKV_EVIDENCE/restricted-before.json"
akv key list --vault "$AKV_RECREATE"
```

Wait for the runner allow rule to take effect. Then create a fresh selected source key and migrate it twice into that destination:

```bash
akv key create --vault "$AKV_SRC" --name retry-only --kty rsa --size 2048
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_RECREATE" --target-rg "$AKV_RG" \
  --keys retry-only --strategy recreate --report-usage false
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_RECREATE" --target-rg "$AKV_RG" \
  --keys retry-only --strategy recreate --report-usage false
vault_config "$AKV_RECREATE" > "$AKV_EVIDENCE/restricted-after.json"
diff -u "$AKV_EVIDENCE/restricted-before.json" "$AKV_EVIDENCE/restricted-after.json"
```

**Assert:** Both runs report reuse, configuration diff is empty, and only `retry-only` gains the expected versions. Check Activity Log after ingestion for zero `Microsoft.KeyVault/vaults/write` operations during the migration interval, excluding fixture setup. Snapshot equality is required even if Activity Log evidence is delayed.

Repeat preservation using an access-policy target to catch the permission-wiping bug directly:

```bash
akv vault create --name "$AKV_POLICY" -g "$AKV_RG" \
  -l "$AKV_TEST_LOCATION" --retention-days 7 --rbac false
azt keyvault set-policy --name "$AKV_POLICY" --resource-group "$AKV_RG" \
  --object-id "$AKV_TEST_PRINCIPAL_ID" \
  --key-permissions get list create backup restore
vault_config "$AKV_POLICY" > "$AKV_EVIDENCE/policy-before.json"
akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_POLICY" --target-rg "$AKV_RG" \
  --keys rsa-copy --strategy backup-restore --report-usage false
vault_config "$AKV_POLICY" > "$AKV_EVIDENCE/policy-after.json"
diff -u "$AKV_EVIDENCE/policy-before.json" "$AKV_EVIDENCE/policy-after.json"
```

**Assert:** The access policy and non-RBAC mode survive; restore succeeds after permissions propagate. Repeating restore is expected to fail because the name exists, but must not erase permissions or vault configuration. If policy disallows access-policy vaults, mark this subcase blocked and retain its offline test evidence.

## 6. Negative and local-validation cases

Use a command wrapper that captures exit status instead of allowing `set -e` to terminate the routine:

```bash
expect_failure() {
  local status=0
  "$@" > "$AKV_EVIDENCE/negative.stdout" 2> "$AKV_EVIDENCE/negative.stderr" || status=$?
  test "$status" -ne 0
}

expect_failure akv key migrate --source-vault "$AKV_SRC" \
  --target-vault "https://$AKV_SRC.vault.azure.net/" --strategy recreate
expect_failure akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_SRC" --target-rg "$AKV_RG" --strategy recreate
expect_failure akv vault migrate --source "$AKV_SRC" --source-rg "$AKV_RG" \
  --target "$AKV_RECREATE" --target-rg "$AKV_RG" --sku premium --dry-run
```

**Assert:** The first two fail with the distinct-vault message and preserve source configuration/version counts. Repeat with uppercase host, both strategies, and dry-run mode. The last fails compatibility checking without upgrading the destination. Repeat that mismatch without `--dry-run` and assert no writes. Add each case's stdout/stderr/status to a separate evidence file before the next call overwrites temporary negative output.

Exercise endpoint rejection only after the unit tests pass. Use reserved `.invalid` domains rather than real third-party endpoints:

```bash
expect_failure akv key list --vault 'https://attacker.invalid?.vault.azure.net'
expect_failure akv key list --vault 'https://attacker.invalid#.vault.azure.net'
expect_failure akv key list --vault "https://$AKV_SRC.vault.azure.net:443"
```

**Assert:** Errors are local endpoint validation errors, not DNS, auth, HTTP, or challenge failures. Successful `key list` using the valid source URI remains the positive control. Keep 403/500-to-creation negative cases in offline fault-injection tests; do not strip the runner's cleanup permissions to manufacture them live.

## 7. Location and general discovery regression checks

```bash
akv --output json locations > "$AKV_EVIDENCE/locations.json"
akv --output json locations --name '*south' > "$AKV_EVIDENCE/south.json"
akv --output json locations --name '*a' > "$AKV_EVIDENCE/a.json"
akv --output json search --type keyvault --name "av-$AKV_RUN_ID*"
akv --output json search --type keyvault,rg --name "*$AKV_RUN_ID*"
```

**Assert:** Derive expected suffix matches from the unfiltered live location list using an independent `endswith` comparison, then compare sorted names with filtered output. If available to the subscription, `southafricasouth` and `eastasia` must appear in their respective results. Do not assume every subscription exposes every region. Allow Resource Graph indexing time before requiring all test vaults in search results. Confirm the multi-type query succeeds, guarding the historical union-query regression.

## 8. Actual Resource Graph usage-prefix fixture

This phase makes the resource-ID prefix finding observable in live KQL. It adds one standard vault, two keys (one per source fixture), and two disk encryption sets, with no disks or VMs. Run after all migration comparisons because this phase enables purge protection on the source and lookalike vaults. Azure managed-disk CMK setup requires protected vaults; account for seven-day retention in cleanup.

```bash
akv vault create --name "$AKV_LOOKALIKE" -g "$AKV_RG" \
  -l "$AKV_TEST_LOCATION" --retention-days 7 --purge-protection
azt keyvault update --name "$AKV_SRC" --resource-group "$AKV_RG" \
  --enable-purge-protection true
```

Wait for access to the new lookalike, then create a key and DES for each:

```bash
for AKV_FIXTURE in "$AKV_SRC" "$AKV_LOOKALIKE"; do
  akv key create --vault "$AKV_FIXTURE" --name des-only --kty rsa --size 2048 \
    --ops encrypt,decrypt,wrapKey,unwrapKey
  AKV_FIXTURE_ID="$(azt keyvault show --name "$AKV_FIXTURE" --query id -o tsv)"
  AKV_FIXTURE_KID="$(azt keyvault key show --vault-name "$AKV_FIXTURE" \
    --name des-only --query key.kid -o tsv)"
  azt disk-encryption-set create --name "des-$AKV_FIXTURE" \
    --resource-group "$AKV_RG" --location "$AKV_TEST_LOCATION" \
    --source-vault "$AKV_FIXTURE_ID" --key-url "$AKV_FIXTURE_KID" \
    --mi-system-assigned
  AKV_DES_PRINCIPAL="$(azt disk-encryption-set show --name "des-$AKV_FIXTURE" \
    --resource-group "$AKV_RG" --query identity.principalId -o tsv)"
  azt role assignment create --assignee-object-id "$AKV_DES_PRINCIPAL" \
    --assignee-principal-type ServicePrincipal \
    --role 'Key Vault Crypto Service Encryption User' --scope "$AKV_FIXTURE_ID"
done
```

First query Resource Graph directly via `az graph query` (install its Azure CLI extension only if needed) to prove both DES resources and their `properties.activeKey.sourceVault.id` values have indexed. The query must filter the exact test group and DES names. Only then run:

```bash
akv --output json search usage --vault "$AKV_SRC" > "$AKV_EVIDENCE/usage-src.json"
akv --output json search usage --vault "$AKV_LOOKALIKE" > "$AKV_EVIDENCE/usage-lookalike.json"
```

**Assert:** Source usage includes `des-$AKV_SRC` but excludes `des-$AKV_LOOKALIKE`; reverse lookup includes the lookalike DES. Both fixtures must be present in the independent indexed baseline, so a missing negative fixture cannot create a false pass. Match resource IDs, not just names. Preserve the returned query/result evidence. If this phase is omitted, mark the live usage-prefix regression unverified rather than claiming the full suite passed.

## 9. Cleanup and evidence

Always attempt scoped cleanup after recording evidence, including on a test failure. Do not put unconditional deletion of an inferred group into a shell trap. Check the exact group ID and run tag first:

```bash
test "$(azt group show --name "$AKV_RG" --query id -o tsv)" = "$AKV_RG_ID"
test "$(azt group show --name "$AKV_RG" --query tags.run -o tsv)" = "$AKV_RUN_ID"
azt resource list --resource-group "$AKV_RG" -o json \
  > "$AKV_EVIDENCE/resources-before-cleanup.json"
azt group delete --name "$AKV_RG" --yes --no-wait
```

Poll group existence until false, with a bounded deadline and an explicit follow-up if deletion remains in progress. Verify all role assignments created by the routine have disappeared with their scopes; remove any surviving assignment by its recorded assignment ID. Record soft-deleted test vault names and scheduled retention expiry. Do not purge vaults or touch unrelated groups, identities, or role assignments.

The final test report lists each phase as PASS/FAIL/BLOCKED/SKIPPED, exact commit/binary, subscription/region in private evidence, observed version/material comparisons, configuration diffs, remaining resources, and cleanup status. Public PR validation can summarize outcomes without exposing private environment identifiers.
