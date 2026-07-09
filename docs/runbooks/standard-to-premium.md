# Runbook: standard → premium vault

Two distinct goals — be explicit about which one you have **before** starting:

- **A. Move to a premium vault** (keep software-protected keys): key material
  is preserved; consumers keep working after a URI re-point.
- **B. Upgrade keys to HSM-protected**: requires **new key material** — the
  protection type (`RSA` vs `RSA-HSM`) is fixed at key creation and a
  software key can never become HSM-backed. Restoring a software key into a
  premium vault restores it exactly as it was: software-protected,
  FIPS 140-2 Level 1.

## A. Same material, premium vault (backup-restore)

Viable only when target is in the **same geography and same subscription**.

```sh
# 1. Plan — verify key inventory and target shape
akvutil vault migrate --source kv-old --source-rg rg-app \
    --target kv-new --target-rg rg-app --sku premium \
    --strategy backup-restore --dry-run

# 2. Execute (creates the premium vault, moves keys, reports usage)
akvutil vault migrate --source kv-old --source-rg rg-app \
    --target kv-new --target-rg rg-app --sku premium \
    --strategy backup-restore

# 3. Verify — names, versions, and attributes carry over
akvutil key list --vault kv-new
```

Notes:
- All versions and attributes are preserved; the key **URI changes** (new
  vault name), so consumers must still be re-pointed.
- Restore fails if a key of the same name already exists in the target.

## B. HSM-backed keys (recreate, new material)

`vault migrate --strategy recreate` preserves each key's shape *including
its type* — it will not upgrade `rsa` → `rsa-hsm`. Create the HSM keys
explicitly:

```sh
# 1. Create the premium vault
akvutil vault create --name kv-new -g rg-app -l eastus2 --sku premium

# 2. Recreate each key as its -hsm counterpart
akvutil key create --vault kv-new --name data-key --kty rsa-hsm --size 3072
akvutil key create --vault kv-new --name sign-key --kty ec-hsm --curve p-384 \
    --ops sign,verify

# 3. Re-point every consumer to the new key URIs, re-wrap enveloped DEKs

# 4. Find anything still on the old vault before decommissioning it
akvutil search usage --vault kv-old
```

Notes:
- **This is a one-way street**: after consumers re-wrap under the HSM keys,
  there is no path back to a standard vault (see
  [premium-to-standard](premium-to-standard.md)).
- Keep the source vault until every backup encrypted under the old keys has
  aged out.
- Verify the created keys really are HSM-backed: `key list` / `key show`
  should report `RSA-HSM` / `EC-HSM`, not `RSA` / `EC`. Premium happily
  hosts both types side by side — the SKU does not imply the protection.
