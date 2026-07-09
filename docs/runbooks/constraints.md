# Hard constraints reference

The rules behind the viability matrix — what `backup-restore` can and cannot
do, and the traps that surface mid-migration.

## backup-restore boundaries

A vault key backup blob restores only when **all** of these hold:

1. **Same geography** ("security world") — all multitenant vaults in a
   geography, standard and premium alike, share one cryptographic boundary.
   Cross-geo restore fails regardless of tier. (US DOD regions form their
   own security world.)
2. **Same subscription** — cross-subscription restore fails even within a
   geography.
3. **Target supports the key type** — `*-hsm` blobs will not restore into a
   standard vault.
4. **Name is free in the target** — restore is rejected if a key with the
   same name exists.

When any of these fail, the only path is `--strategy recreate` (new key
material, consumers re-pointed, data re-wrapped).

What restore preserves: name, every version, attributes, key type. What
changes: the key URI (new vault name). Version identifiers are preserved,
so version-pinned consumers only need the host part of the URI updated.

Paired regions (see `akvutil locations`) are a *deployment* concept — they
do **not** relax the geography rule, but a pair is usually within the same
geography, which is what makes it a good DR target for backup-restore.

## Soft-delete and naming traps

- Vault names are **globally unique** (they become
  `https://<name>.vault.azure.net`). A 409 on create can mean another
  tenant owns the name — check `az keyvault list-deleted` to distinguish
  "mine, soft-deleted" from "taken globally".
- A deleted vault holds its name for the soft-delete retention period
  (default 90 days) unless purged. **Purge-protected vaults cannot be
  purged** — the name is locked for the full retention period, no override.
- Plan migrate-then-rename flows accordingly: you cannot delete a source
  vault and immediately recreate it under the same name.

## Key material export

Neither Key Vault nor Managed HSM ever exports private key material. The
sole exception is secure-key-release to attested confidential-computing
enclaves — not a migration mechanism. Same material in two places requires
generating it outside Azure and BYOK-importing into each target, decided
before the key is created.

## Octet keys

`oct`/`oct-HSM` keys never expose material and have no backup-restore
portability story across vault boundaries that `recreate` can reproduce —
akvutil's `recreate` uses the service default size for those. Data
encrypted directly under an octet key must be re-encrypted under the new
key.
