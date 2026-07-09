# Runbook: Key Vault ↔ Managed HSM

> **akvutil scope note**: Managed HSM (`Microsoft.KeyVault/managedHSMs`,
> `*.managedhsm.azure.net`) is a different resource type with its own data
> plane and local RBAC; `akvutil vault migrate` does not target it. The
> steps below use `az`.

## Key Vault → Managed HSM: no direct path, ever

Key Vault and Managed HSM always have **separate security domains**, even in
the same geography — key material cannot be replicated or transferred
between them, and neither service exports private key material.

### Option 1 — recreate + re-point (recommended for CMK workloads)

```sh
# 1. Create the new key in the Managed HSM
az keyvault key create --hsm-name mhsm-prod --name data-key \
    --kty RSA-HSM --size 3072

# 2. Grant the workload's managed identity access (MHSM local RBAC)
az keyvault role assignment create --hsm-name mhsm-prod \
    --role "Managed HSM Crypto User" \
    --assignee-object-id <workload-identity-oid> --scope /keys/data-key

# 3. Re-point the service (Storage CMK, SQL TDE, ...) to the new key URI

# 4. Retain the old vault key until nothing encrypted under it remains
akvutil search usage --vault kv-old   # who still references the old vault?
```

Envelope encryption makes step 3 a KEK re-wrap, not a bulk data re-encrypt.

### Option 2 — BYOK (same material in both places)

Only possible when the key was (or can be) **generated in an HSM you control
outside Azure**. Import it into the vault and/or MHSM via the BYOK flows;
each copy gets its own URI. Constraints: the transfer KEK must be RSA-HSM
2048/3072/4096 with `import` as its only key op; RSA-1024 import is not
supported. Material already generated *inside* Key Vault can never take this
path — the decision to BYOK is made before key creation, not after.

## Managed HSM → Key Vault: NOT viable

MHSM key backups are cryptographically tied to the source HSM's security
domain and restore **only** into HSMs sharing that domain (that is also how
MHSM cross-region DR works: provision, load security domain, restore full
backup). There is no downgrade path to a vault — treat any move onto
Managed HSM as permanent for that key material. If a workload might need to
come back to Key Vault, keep its keys in a premium vault instead.
