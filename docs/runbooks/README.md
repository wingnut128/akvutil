# Key migration runbooks

Operational runbooks for moving keys between Azure Key Vault tiers and
Managed HSM, including which paths are **not viable**. Facts verified against
Microsoft Learn docs, July 2026.

## Viability matrix

| From → To | Same key material? | Path | Runbook |
|---|---|---|---|
| Standard → Premium (same geo + sub) | ✅ yes | `backup-restore` — but keys **stay software-protected** | [standard-to-premium](standard-to-premium.md) |
| Standard → Premium, HSM-backed keys | ❌ new material | `recreate` with `*-hsm` key types + re-point consumers | [standard-to-premium](standard-to-premium.md) |
| Premium (software keys) → Standard | ✅ yes | `backup-restore` | [premium-to-standard](premium-to-standard.md) |
| Premium (HSM keys) → Standard | ❌ **not viable as-is** | standard cannot host `*-hsm` types; `recreate` as software keys = security downgrade, new material | [premium-to-standard](premium-to-standard.md) |
| Key Vault (any tier) → Managed HSM | ❌ never directly | recreate in MHSM + re-point, or BYOK from an external HSM | [vault-to-managed-hsm](vault-to-managed-hsm.md) |
| Managed HSM → Key Vault | ❌ **not viable** | separate security domains — no backup/restore path exists, ever | [vault-to-managed-hsm](vault-to-managed-hsm.md) |
| Cross-geography (any tier) | ❌ | `backup-restore` blobs only restore within the same geography ("security world"); use `recreate` | [constraints](constraints.md) |
| Cross-subscription | ❌ | `backup-restore` requires the same subscription; use `recreate` | [constraints](constraints.md) |

## The one-way streets

Migrations that **cannot be reversed** (plan accordingly before executing):

1. **Software → HSM-protected**: once consumers are re-pointed at new
   `*-hsm` keys, there is no path back to the original key material in a
   standard vault — HSM key backups will not restore there.
2. **Key Vault → Managed HSM**: key material can never come back out.
   MHSM backups restore only into HSMs sharing the same security domain.
3. **Purge-protected vaults**: `--purge-protection` can never be disabled,
   and the vault name stays reserved for the full retention period after
   deletion.
4. **Key material generally**: Key Vault and Managed HSM never export
   private key material (sole exception: secure-key-release to attested
   confidential-computing enclaves). The only way to hold the same material
   in two places is to generate it outside Azure and BYOK-import it into
   each — decide this *before* creating keys, not after.

## General preconditions (all runbooks)

- `az login` completed; `AZURE_SUBSCRIPTION_ID` set or `--subscription` passed
- Key Vault Crypto Officer (or equivalent) on both source and target vaults
- Target vault name available — remember names are **globally unique** and
  soft-deleted vaults hold their name until purged
- Run every `akvutil vault migrate` with `--dry-run` first
