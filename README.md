# akvutil

Azure Key Vault utility in Rust: create and migrate key vaults and keys, and discover which resources (storage accounts, disk encryption sets, SQL servers, VMs, ...) use a given vault.

## Architecture

Data plane (keys) uses the GA Azure SDK for Rust: `azure_identity` 1.0 + `azure_security_keyvault_keys` 1.0. Control plane (vault CRUD) and Azure Resource Graph have no stable Rust management crate yet, so those go through the ARM REST API directly with tokens from the same credential.

Authentication uses `DeveloperToolsCredential` (Azure CLI / Azure Developer CLI chain) — run `az login` first. Data-plane operations additionally require an RBAC role such as Key Vault Crypto Officer on the vault.

## Build

Requires Rust 1.88+.

```
cargo build --release
```

## Usage

Set the subscription once via `export AZURE_SUBSCRIPTION_ID=...` or pass `--subscription` per command. Add `--output json` to any command for machine-readable output.

### Vaults

```
# Create a premium (HSM-backed) vault with purge protection
akvutil vault create --name kv-prod-01 -g rg-security -l eastus2 \
    --sku premium --purge-protection --tag env=prod

akvutil vault show --name kv-prod-01 -g rg-security

# Migrate: creates the target vault (inheriting SKU/RBAC/retention from the
# source unless overridden), moves the keys, then reports every resource
# still pointing at the source vault.
akvutil vault migrate --source kv-old --source-rg rg-a \
    --target kv-new --target-rg rg-b --sku premium \
    --strategy recreate --dry-run
```

### Keys

```
akvutil key create --vault kv-prod-01 --name data-key --kty rsa --size 3072
akvutil key create --vault kv-prod-01 --name sign-key --kty ec-hsm --curve p-384 \
    --ops sign,verify
akvutil key list --vault kv-prod-01

akvutil key migrate --source-vault kv-old --target-vault kv-new \
    --keys data-key,sign-key --strategy backup-restore
```

Migration strategies: `recreate` builds same-shape keys (type, size, curve, ops) in the target — new key material, so consumers must be repointed and data re-wrapped. `backup-restore` preserves key material and versions but Azure only allows it within the same geography and subscription. Octet (oct/oct-HSM) keys never expose material, so `recreate` uses the service default size for those.

### Search

```
akvutil search --type keyvault --name 'testfoo*'   # prefix match
akvutil search --type storage,des,rg --name prod   # substring match
akvutil search --name '*crypto*'                   # all types
akvutil search usage --vault myvault               # who uses this vault?
```

`--name` matches substrings by default; `*` wildcards anchor the match (`foo*` prefix, `*foo` suffix, `f*o` regex).

Usage search runs a Resource Graph query matching the vault URI (`<name>.vault.azure.net`) and vault resource ID against every resource's ARM properties, which catches storage account CMK configs, disk encryption sets, SQL TDE, ADE-enabled VMs, and anything else that stores the reference in ARM. It cannot see references living only in app settings, code, or pipelines. When no `--subscription` is given, Resource Graph searches all subscriptions visible to your credential.

### Key rotation

```
akvutil key create --vault v --name k --rotate-after 90d --policy-expiry 2y
akvutil key rotation show --vault v --name k
akvutil key rotation set --vault v --name k --notify-before 30d
akvutil key rotate --vault v --name k
```

## Notes

- Crate versions in `Cargo.toml` were verified against crates.io in July 2026. The SDK models are generated; if a point release renames a field the compiler will point right at it.
- `cargo test` runs a few offline unit tests (URI normalization, RSA size inference).
