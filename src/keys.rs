//! Key operations against the Key Vault data plane
//! (azure_security_keyvault_keys 1.0).

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use azure_security_keyvault_keys::{
    models::{
        CreateKeyParameters, CurveName, KeyAttributes, KeyRotationPolicy, KeyRotationPolicyAction,
        KeyType, LifetimeAction, LifetimeActionTrigger, LifetimeActionType, RestoreKeyParameters,
    },
    KeyClient, ResourceExt as _,
};
use futures::TryStreamExt;
use serde_json::json;
use tokio::time::sleep;

use crate::auth::Context;
use crate::output;
use crate::timespec;
use crate::{
    Curve, KeyCreateArgs, KeyKind, KeyMigrateArgs, MigrateStrategy, OutputFormat, RotationSetArgs,
};

fn client(ctx: &Context, vault: &str) -> Result<KeyClient> {
    KeyClient::new(&Context::vault_uri(vault)?, ctx.credential.clone(), None)
        .context("failed to build KeyClient")
}

/// Poll a vault's data plane until a request succeeds. A just-created vault is
/// not immediately usable: its DNS name and (with RBAC) the caller's role
/// assignment take time to propagate, so the first key operation can otherwise
/// fail with a spurious 403 or name-resolution error. A successful list — even
/// of an empty vault — proves both DNS and data-plane authorization are live.
pub async fn wait_until_ready(ctx: &Context, vault: &str) -> Result<()> {
    const TIMEOUT: Duration = Duration::from_secs(180);
    const MAX_BACKOFF: Duration = Duration::from_secs(15);

    let client = client(ctx, vault)?;
    let mut waited = Duration::ZERO;
    let mut backoff = Duration::from_secs(2);
    loop {
        let probe = async {
            client.list_key_properties(None)?.try_next().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match probe {
            Ok(()) => return Ok(()),
            Err(e) if waited >= TIMEOUT => {
                return Err(e).with_context(|| {
                    format!(
                        "target vault '{}' still not reachable after {}s; if it uses RBAC, \
                         grant yourself a data-plane role (e.g. 'Key Vault Crypto Officer') \
                         and re-run",
                        Context::vault_name(vault),
                        TIMEOUT.as_secs()
                    )
                });
            }
            Err(_) => {
                sleep(backoff).await;
                waited += backoff;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Infer an RSA key size in bits from its modulus. Per RFC 7518 the JWK
/// modulus is the minimal big-endian octet string (no leading zero byte), so
/// its length in bits is the key size.
fn rsa_key_size_bits(modulus: &[u8]) -> i32 {
    (modulus.len() * 8) as i32
}

impl KeyKind {
    fn to_key_type(self) -> KeyType {
        match self {
            KeyKind::Rsa => KeyType::Rsa,
            KeyKind::RsaHsm => KeyType::RsaHsm,
            KeyKind::Ec => KeyType::Ec,
            KeyKind::EcHsm => KeyType::EcHsm,
            KeyKind::Oct => KeyType::Oct,
            KeyKind::OctHsm => KeyType::OctHsm,
        }
    }
}

impl Curve {
    fn to_curve_name(self) -> CurveName {
        match self {
            Curve::P256 => CurveName::P256,
            Curve::P256k => CurveName::P256K,
            Curve::P384 => CurveName::P384,
            Curve::P521 => CurveName::P521,
        }
    }
}

/// Overlay rotation-policy values onto `policy`. Pass
/// `KeyRotationPolicy::default()` to build a policy from scratch. The
/// service requires an expiry time whenever a Notify action exists, so that
/// combination is rejected here with a actionable message instead of a 400.
pub fn merge_rotation_policy(
    mut policy: KeyRotationPolicy,
    rotate_after: Option<&str>,
    notify_before: Option<&str>,
    policy_expiry: Option<&str>,
) -> Result<KeyRotationPolicy> {
    fn upsert(
        actions: &mut Vec<LifetimeAction>,
        kind: KeyRotationPolicyAction,
        trigger: LifetimeActionTrigger,
    ) {
        let action = LifetimeAction {
            action: Some(LifetimeActionType {
                type_prop: Some(kind),
            }),
            trigger: Some(trigger),
        };
        let existing = actions
            .iter_mut()
            .find(|a| a.action.as_ref().and_then(|t| t.type_prop) == Some(kind));
        match existing {
            Some(slot) => *slot = action,
            None => actions.push(action),
        }
    }

    let mut actions = policy.lifetime_actions.take().unwrap_or_default();
    if let Some(d) = rotate_after {
        upsert(
            &mut actions,
            KeyRotationPolicyAction::Rotate,
            LifetimeActionTrigger {
                time_after_create: Some(timespec::policy_duration(d)?),
                time_before_expiry: None,
            },
        );
    }
    if let Some(d) = notify_before {
        upsert(
            &mut actions,
            KeyRotationPolicyAction::Notify,
            LifetimeActionTrigger {
                time_after_create: None,
                time_before_expiry: Some(timespec::policy_duration(d)?),
            },
        );
    }
    if let Some(d) = policy_expiry {
        policy
            .attributes
            .get_or_insert_with(Default::default)
            .expiry_time = Some(timespec::policy_duration(d)?);
    }

    let has_expiry = policy
        .attributes
        .as_ref()
        .and_then(|a| a.expiry_time.as_ref())
        .is_some();
    let has_notify = actions.iter().any(|a| {
        a.action.as_ref().and_then(|t| t.type_prop) == Some(KeyRotationPolicyAction::Notify)
    });
    if has_notify && !has_expiry {
        bail!("a notify action requires an expiry time: set --policy-expiry");
    }

    policy.lifetime_actions = Some(actions);
    Ok(policy)
}

pub async fn create(ctx: &Context, args: &KeyCreateArgs, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, &args.vault)?;

    // Fail on bad policy flags before creating anything.
    let policy = if args.rotate_after.is_some()
        || args.notify_before.is_some()
        || args.policy_expiry.is_some()
    {
        Some(merge_rotation_policy(
            KeyRotationPolicy::default(),
            args.rotate_after.as_deref(),
            args.notify_before.as_deref(),
            args.policy_expiry.as_deref(),
        )?)
    } else {
        None
    };

    let now = azure_core::time::OffsetDateTime::now_utc();
    let attributes = KeyAttributes {
        enabled: args.enabled,
        expires: args
            .expires
            .as_deref()
            .map(|s| timespec::timestamp(s, now))
            .transpose()?,
        not_before: args
            .not_before
            .as_deref()
            .map(|s| timespec::timestamp(s, now))
            .transpose()?,
        exportable: args.exportable.then_some(true),
        ..Default::default()
    };
    let has_attributes = args.enabled.is_some()
        || args.expires.is_some()
        || args.not_before.is_some()
        || args.exportable;

    let params = CreateKeyParameters {
        kty: Some(args.kty.to_key_type()),
        key_size: args.size,
        curve: args.curve.map(Curve::to_curve_name),
        key_ops: if args.ops.is_empty() {
            None
        } else {
            // KeyOperation is an extensible enum; round-trip through JSON to
            // convert the user's strings.
            Some(serde_json::from_value(json!(args.ops))?)
        },
        key_attributes: has_attributes.then_some(attributes),
        tags: if args.tag.is_empty() {
            None
        } else {
            Some(args.tag.iter().cloned().collect())
        },
        ..Default::default()
    };

    let key = client
        .create_key(&args.name, params.try_into()?, None)
        .await
        .with_context(|| format!("failed to create key '{}'", args.name))?
        .into_model()?;

    if let Some(policy) = policy {
        client
            .update_key_rotation_policy(&args.name, policy.try_into()?, None)
            .await
            .with_context(|| {
                format!(
                    "key '{}' was created, but setting its rotation policy failed",
                    args.name
                )
            })?;
    }

    let kid = key
        .key
        .as_ref()
        .and_then(|k| k.kid.clone())
        .unwrap_or_default();
    match fmt {
        OutputFormat::Json => output::print_json(&json!({ "name": args.name, "kid": kid })),
        OutputFormat::Table => println!("Created key '{}'\n  kid: {kid}", args.name),
    }
    Ok(())
}

/// Names of all keys in a vault.
pub async fn key_names(client: &KeyClient) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut pager = client.list_key_properties(None)?;
    while let Some(props) = pager.try_next().await? {
        names.push(props.resource_id()?.name);
    }
    Ok(names)
}

pub async fn list(ctx: &Context, vault: &str, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, vault)?;
    let mut rows = Vec::new();

    let mut pager = client.list_key_properties(None)?;
    while let Some(props) = pager.try_next().await? {
        let id = props.resource_id()?;
        let enabled = props
            .attributes
            .as_ref()
            .and_then(|a| a.enabled)
            .map(|e| e.to_string())
            .unwrap_or_else(|| "-".into());
        rows.push(json!({
            "name": id.name,
            "enabled": enabled,
            "kid": format!("{}/keys/{}", id.vault_url, id.name),
        }));
    }

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => output::print_table(
            &["NAME", "ENABLED", "KID"],
            &rows,
            &["name", "enabled", "kid"],
        ),
    }
    Ok(())
}

pub async fn migrate(ctx: &Context, args: &KeyMigrateArgs, fmt: OutputFormat) -> Result<()> {
    let report = migrate_keys(
        ctx,
        &args.source_vault,
        &args.target_vault,
        &args.keys,
        args.strategy,
        args.dry_run,
    )
    .await?;
    match fmt {
        OutputFormat::Json => output::print_json(&json!(report)),
        OutputFormat::Table => {
            for line in &report {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// Migrate keys from source to target vault. Returns a human-readable report.
pub async fn migrate_keys(
    ctx: &Context,
    source_vault: &str,
    target_vault: &str,
    only: &[String],
    strategy: MigrateStrategy,
    dry_run: bool,
) -> Result<Vec<String>> {
    let source = client(ctx, source_vault)?;
    let target = client(ctx, target_vault)?;
    let mut report = Vec::new();

    let names = if only.is_empty() {
        key_names(&source).await?
    } else {
        only.to_vec()
    };
    if names.is_empty() {
        report.push("No keys found in source vault.".to_string());
        return Ok(report);
    }

    for name in &names {
        match strategy {
            MigrateStrategy::BackupRestore => {
                if dry_run {
                    report.push(format!("[dry-run] would backup/restore key '{name}'"));
                    continue;
                }
                let backup = source
                    .backup_key(name, None)
                    .await
                    .with_context(|| format!("backup failed for key '{name}'"))?
                    .into_model()?;
                let blob = backup.value.context("backup returned no blob")?;
                let params = RestoreKeyParameters {
                    key_backup: Some(blob),
                };
                target
                    .restore_key(params.try_into()?, None)
                    .await
                    .with_context(|| {
                        format!(
                            "restore failed for key '{name}' (backup/restore only works \
                             within the same geography and subscription; try --strategy recreate)"
                        )
                    })?;
                report.push(format!(
                    "restored key '{name}' (material + versions preserved)"
                ));
            }
            MigrateStrategy::Recreate => {
                let key = source
                    .get_key(name, None)
                    .await
                    .with_context(|| format!("failed to read key '{name}'"))?
                    .into_model()?;
                let jwk = key.key.context("key has no JWK payload")?;
                let kty = jwk.kty.clone().context("key has no key type")?;

                // Infer RSA size from the modulus length.
                let key_size = jwk.n.as_ref().map(|n| rsa_key_size_bits(n));
                let curve = jwk.crv.clone();
                // KeyOperation is extensible; round-trip via JSON so we don't
                // depend on the exact field type.
                let key_ops = jwk
                    .key_ops
                    .as_ref()
                    .map(|ops| serde_json::from_value(json!(ops)))
                    .transpose()?;

                let is_oct = matches!(kty, KeyType::Oct | KeyType::OctHsm);
                let desc = if let Some(c) = &curve {
                    format!("{kty:?}/{c:?}")
                } else if let Some(s) = key_size {
                    format!("{kty:?}/{s} bits")
                } else {
                    format!("{kty:?}")
                };

                if dry_run {
                    report.push(format!("[dry-run] would recreate key '{name}' as {desc}"));
                    continue;
                }

                let params = CreateKeyParameters {
                    kty: Some(kty),
                    key_size,
                    curve,
                    key_ops,
                    ..Default::default()
                };
                target
                    .create_key(name, params.try_into()?, None)
                    .await
                    .with_context(|| format!("failed to recreate key '{name}' in target"))?;

                let mut line = format!("recreated key '{name}' as {desc} (NEW key material)");
                if is_oct {
                    line.push_str(" [oct: size not inferable, service default used]");
                }
                report.push(line);
            }
        }
    }

    if strategy == MigrateStrategy::Recreate && !dry_run {
        report.push(
            "NOTE: recreated keys have new material. Repoint consumers to the target vault \
             and re-encrypt/rotate where necessary."
                .to_string(),
        );
    }
    Ok(report)
}

/// Render a rotation policy as table lines or JSON.
fn print_rotation_policy(policy: &KeyRotationPolicy, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => output::print_json(&serde_json::to_value(policy)?),
        OutputFormat::Table => {
            let expiry = policy
                .attributes
                .as_ref()
                .and_then(|a| a.expiry_time.as_deref())
                .unwrap_or("-");
            println!("{:<22} {expiry}", "Version expiry");
            for action in policy.lifetime_actions.iter().flatten() {
                let kind = action
                    .action
                    .as_ref()
                    .and_then(|t| t.type_prop)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| "?".into());
                let trigger = action.trigger.as_ref();
                let when = match (
                    trigger.and_then(|t| t.time_after_create.as_deref()),
                    trigger.and_then(|t| t.time_before_expiry.as_deref()),
                ) {
                    (Some(d), _) => format!("{d} after creation"),
                    (_, Some(d)) => format!("{d} before expiry"),
                    _ => "-".into(),
                };
                println!("{kind:<22} {when}");
            }
        }
    }
    Ok(())
}

pub async fn rotation_show(
    ctx: &Context,
    vault: &str,
    name: &str,
    fmt: OutputFormat,
) -> Result<()> {
    let client = client(ctx, vault)?;
    let policy = client
        .get_key_rotation_policy(name, None)
        .await
        .with_context(|| format!("failed to read rotation policy for key '{name}'"))?
        .into_model()?;
    print_rotation_policy(&policy, fmt)
}

pub async fn rotation_set(ctx: &Context, args: &RotationSetArgs, fmt: OutputFormat) -> Result<()> {
    if args.rotate_after.is_none() && args.notify_before.is_none() && args.policy_expiry.is_none() {
        bail!(
            "nothing to set: pass at least one of --rotate-after, --notify-before, --policy-expiry"
        );
    }
    let client = client(ctx, &args.vault)?;
    // Read-modify-write: the PUT replaces the whole policy, so start from the
    // current one to preserve whatever the caller didn't specify.
    let current = client
        .get_key_rotation_policy(&args.name, None)
        .await
        .with_context(|| format!("failed to read rotation policy for key '{}'", args.name))?
        .into_model()?;
    let merged = merge_rotation_policy(
        current,
        args.rotate_after.as_deref(),
        args.notify_before.as_deref(),
        args.policy_expiry.as_deref(),
    )?;
    let updated = client
        .update_key_rotation_policy(&args.name, merged.try_into()?, None)
        .await
        .with_context(|| format!("failed to update rotation policy for key '{}'", args.name))?
        .into_model()?;
    print_rotation_policy(&updated, fmt)
}

pub async fn rotate(ctx: &Context, vault: &str, name: &str, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, vault)?;
    let key = client
        .rotate_key(name, None)
        .await
        .with_context(|| format!("failed to rotate key '{name}'"))?
        .into_model()?;
    let kid = key
        .key
        .as_ref()
        .and_then(|k| k.kid.clone())
        .unwrap_or_default();
    match fmt {
        OutputFormat::Json => output::print_json(&json!({ "name": name, "kid": kid })),
        OutputFormat::Table => println!("Rotated key '{name}'\n  new version kid: {kid}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_size_from_modulus() {
        // Exercises the production inference used by migrate_keys' Recreate
        // path, not a re-implementation of it.
        assert_eq!(rsa_key_size_bits(&vec![0u8; 256]), 2048);
        assert_eq!(rsa_key_size_bits(&vec![0u8; 384]), 3072);
        assert_eq!(rsa_key_size_bits(&vec![0u8; 512]), 4096);
    }

    use azure_security_keyvault_keys::models::KeyRotationPolicy;

    #[test]
    fn builds_policy_from_scratch() {
        let p = merge_rotation_policy(
            KeyRotationPolicy::default(),
            Some("90d"),
            Some("30d"),
            Some("2y"),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            json!({
                "attributes": { "expiryTime": "P2Y" },
                "lifetimeActions": [
                    { "action": { "type": "Rotate" }, "trigger": { "timeAfterCreate": "P90D" } },
                    { "action": { "type": "Notify" }, "trigger": { "timeBeforeExpiry": "P30D" } },
                ],
            })
        );
    }

    #[test]
    fn overlay_replaces_only_given_actions() {
        let existing: KeyRotationPolicy = serde_json::from_value(json!({
            "attributes": { "expiryTime": "P1Y" },
            "lifetimeActions": [
                { "action": { "type": "Rotate" }, "trigger": { "timeAfterCreate": "P30D" } },
            ],
        }))
        .unwrap();
        let p = merge_rotation_policy(existing, Some("90d"), None, None).unwrap();
        let v = serde_json::to_value(&p).unwrap();
        // Rotate trigger updated, expiry preserved, no Notify action invented.
        assert_eq!(v["attributes"]["expiryTime"], "P1Y");
        assert_eq!(
            v["lifetimeActions"][0]["trigger"]["timeAfterCreate"],
            "P90D"
        );
        assert_eq!(v["lifetimeActions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn notify_without_expiry_is_rejected() {
        let err = merge_rotation_policy(KeyRotationPolicy::default(), None, Some("30d"), None)
            .unwrap_err();
        assert!(err.to_string().contains("--policy-expiry"));
    }

    #[test]
    fn bad_duration_propagates() {
        assert!(
            merge_rotation_policy(KeyRotationPolicy::default(), Some("90x"), None, None).is_err()
        );
    }
}
