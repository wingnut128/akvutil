# Runbook: premium → standard vault (the backwards direction)

**Check key types first** — this direction is only cleanly viable for
software-protected keys:

```sh
akvutil key list --vault kv-premium --output json   # inspect kty per key
```

## Software-protected keys (`RSA`, `EC`, `oct`): viable

Backup-restore works standard ↔ premium in **both** directions (same
geography + subscription) because tier is not a restore constraint — all
multitenant vaults in a geography share one security world.

```sh
akvutil vault migrate --source kv-premium --source-rg rg-app \
    --target kv-standard --target-rg rg-app --sku standard \
    --strategy backup-restore --dry-run
# then re-run without --dry-run
```

## HSM-protected keys (`RSA-HSM`, `EC-HSM`, `oct-HSM`): NOT viable as-is

- A backup of an HSM key **cannot be restored into a standard vault** —
  standard doesn't support HSM key types. The restore fails; there is no
  flag to convert it.
- `--strategy recreate` will attempt same-shape keys; HSM types cannot be
  created in a standard target. Recreating them as software types instead
  means **new key material and a deliberate security downgrade**
  (FIPS 140-2 Level 3 → Level 1) — do this only with sign-off, and expect
  to re-point consumers and re-wrap data.

This asymmetry is why the standard→premium HSM upgrade is a one-way door:
plan the tier decision as if it were permanent.

## Common trap

Downgrading to save cost while compliance requires HSM protection: the
premium SKU price difference is per-key-use, small next to the blast radius
of a Level-3 → Level-1 downgrade. Confirm the compliance posture before
running anything in this runbook.
