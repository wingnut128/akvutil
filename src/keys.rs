//! Key operations against the Key Vault data plane
//! (azure_security_keyvault_keys 1.0).

use anyhow::{Context as _, Result};
use azure_security_keyvault_keys::{
    models::{CreateKeyParameters, CurveName, KeyType, RestoreKeyParameters},
    KeyClient, ResourceExt as _,
};
use futures::TryStreamExt;
use serde_json::json;

use crate::auth::Context;
use crate::output;
use crate::{Curve, KeyCreateArgs, KeyKind, KeyMigrateArgs, MigrateStrategy, OutputFormat};

fn client(ctx: &Context, vault: &str) -> Result<KeyClient> {
    KeyClient::new(&Context::vault_uri(vault), ctx.credential.clone(), None)
        .context("failed to build KeyClient")
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

pub async fn create(ctx: &Context, args: &KeyCreateArgs, fmt: OutputFormat) -> Result<()> {
    let client = client(ctx, &args.vault)?;

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
        ..Default::default()
    };

    let key = client
        .create_key(&args.name, params.try_into()?, None)
        .await
        .with_context(|| format!("failed to create key '{}'", args.name))?
        .into_model()?;

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
                let key_size = jwk.n.as_ref().map(|n| (n.len() * 8) as i32);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_uri_normalization() {
        assert_eq!(
            Context::vault_uri("myvault"),
            "https://myvault.vault.azure.net"
        );
        assert_eq!(
            Context::vault_uri("https://myvault.vault.azure.net/"),
            "https://myvault.vault.azure.net"
        );
        assert_eq!(
            Context::vault_name("https://myvault.vault.azure.net"),
            "myvault"
        );
        assert_eq!(Context::vault_name("myvault"), "myvault");
    }

    #[test]
    fn rsa_size_from_modulus() {
        let n_2048 = vec![0u8; 256];
        assert_eq!((n_2048.len() * 8) as i32, 2048);
    }
}
