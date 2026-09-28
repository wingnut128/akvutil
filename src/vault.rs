//! Vault-level commands: create, show, migrate.

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use crate::arm::{self, VaultSpec};
use crate::auth::Context;
use crate::keys;
use crate::output;
use crate::search;
use crate::{OutputFormat, VaultCreateArgs, VaultMigrateArgs};

fn summarize(vault: &Value) -> Value {
    json!({
        "name": vault.get("name"),
        "location": vault.get("location"),
        "sku": vault.pointer("/properties/sku/name"),
        "rbac": vault.pointer("/properties/enableRbacAuthorization"),
        "retentionDays": vault.pointer("/properties/softDeleteRetentionInDays"),
        "purgeProtection": vault.pointer("/properties/enablePurgeProtection"),
        "uri": vault.pointer("/properties/vaultUri"),
        "provisioningState": vault.pointer("/properties/provisioningState"),
        "publicNetworkAccess": vault.pointer("/properties/publicNetworkAccess"),
        "networkDefaultAction": vault.pointer("/properties/networkAcls/defaultAction"),
        "networkBypass": vault.pointer("/properties/networkAcls/bypass"),
        "ipRules": vault.pointer("/properties/networkAcls/ipRules")
            .and_then(Value::as_array).map(Vec::len),
        "enabledForDeployment": vault.pointer("/properties/enabledForDeployment"),
        "enabledForDiskEncryption": vault.pointer("/properties/enabledForDiskEncryption"),
        "enabledForTemplateDeployment": vault.pointer("/properties/enabledForTemplateDeployment"),
    })
}

fn print_vault(vault: &Value, fmt: OutputFormat) {
    let s = summarize(vault);
    match fmt {
        OutputFormat::Json => output::print_json(&s),
        OutputFormat::Table => {
            for (label, key) in [
                ("Name", "name"),
                ("Location", "location"),
                ("SKU", "sku"),
                ("RBAC", "rbac"),
                ("Retention (days)", "retentionDays"),
                ("Purge protection", "purgeProtection"),
                ("URI", "uri"),
                ("State", "provisioningState"),
                ("Public network", "publicNetworkAccess"),
                ("Net default", "networkDefaultAction"),
                ("Net bypass", "networkBypass"),
                ("IP rules", "ipRules"),
                ("For deployment", "enabledForDeployment"),
                ("For disk encrypt", "enabledForDiskEncryption"),
                ("For templates", "enabledForTemplateDeployment"),
            ] {
                println!("{label:<18} {}", output::display(&s[key]));
            }
        }
    }
}

pub async fn create(ctx: &Context, args: &VaultCreateArgs, fmt: OutputFormat) -> Result<()> {
    if !args.allow_ip.is_empty() && args.default_action == crate::NetworkAction::Allow {
        eprintln!(
            "warning: --allow-ip has no effect while --default-action is 'allow'; \
             use --default-action deny to enforce the IP rules"
        );
    }
    let spec = VaultSpec {
        name: &args.name,
        resource_group: &args.resource_group,
        location: &args.location,
        sku: args.sku.as_str(),
        rbac: args.rbac,
        retention_days: args.retention_days,
        purge_protection: args.purge_protection,
        tags: &args.tag,
        public_network_access: args.public_network_access.as_str(),
        default_action: args.default_action.as_str(),
        bypass: args.bypass.as_str(),
        ip_rules: &args.allow_ip,
        enabled_for_deployment: args.enabled_for_deployment,
        enabled_for_disk_encryption: args.enabled_for_disk_encryption,
        enabled_for_template_deployment: args.enabled_for_template_deployment,
    };
    let vault = arm::create_vault(ctx, &spec).await?;
    print_vault(&vault, fmt);
    Ok(())
}

pub async fn show(
    ctx: &Context,
    name: &str,
    resource_group: &str,
    fmt: OutputFormat,
) -> Result<()> {
    let vault = arm::get_vault(ctx, name, resource_group).await?;
    print_vault(&vault, fmt);
    Ok(())
}

/// Migration may reuse compatible targets, but must never reconfigure them.
fn validate_existing_target(
    target: &Value,
    location: &str,
    sku: &str,
    retention_days: u32,
    purge_protection: bool,
) -> Result<()> {
    let unchanged = "migration will not reconfigure an existing destination";
    for (pointer, expected, field) in [
        ("/location", location, "location"),
        ("/properties/sku/name", sku, "SKU"),
    ] {
        let actual = target
            .pointer(pointer)
            .and_then(Value::as_str)
            .with_context(|| format!("existing target missing valid {field}; {unchanged}"))?;
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("existing target {field} is '{actual}', expected '{expected}'; {unchanged}");
        }
    }
    let retention = target
        .pointer("/properties/softDeleteRetentionInDays")
        .and_then(Value::as_u64)
        .with_context(|| format!("existing target missing valid retention; {unchanged}"))?;
    if retention < u64::from(retention_days) {
        bail!(
            "existing target retention is {retention} days, expected at least {retention_days}; {unchanged}"
        );
    }
    let protected = match target.pointer("/properties/enablePurgeProtection") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(enabled)) => *enabled,
        _ => bail!("existing target has invalid purge protection; {unchanged}"),
    };
    if purge_protection && !protected {
        bail!("existing target requires purge protection to match the source; {unchanged}");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum TargetAction {
    Reuse,
    Create,
    WouldCreate,
}

/// Keep the write decision testable independently of ARM transport and auth.
async fn select_target<L, LF, C, CF, V>(
    dry_run: bool,
    lookup: L,
    create: C,
    validate: V,
) -> Result<TargetAction>
where
    L: FnOnce() -> LF,
    LF: std::future::Future<Output = Result<Option<Value>>>,
    C: FnOnce() -> CF,
    CF: std::future::Future<Output = Result<Value>>,
    V: FnOnce(&Value) -> Result<()>,
{
    match lookup().await? {
        Some(target) => {
            validate(&target)?;
            Ok(TargetAction::Reuse)
        }
        None if dry_run => Ok(TargetAction::WouldCreate),
        None => {
            create().await?;
            Ok(TargetAction::Create)
        }
    }
}

pub async fn migrate(ctx: &Context, args: &VaultMigrateArgs, fmt: OutputFormat) -> Result<()> {
    crate::auth::ensure_distinct_vaults(&args.source, &args.target)?;
    // 1. Read the source vault so the target can inherit its shape.
    let source = arm::get_vault(ctx, &args.source, &args.source_rg).await?;
    let src_location = source
        .get("location")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let src_sku = source
        .pointer("/properties/sku/name")
        .and_then(Value::as_str)
        .unwrap_or("standard")
        .to_string();
    let src_rbac = source
        .pointer("/properties/enableRbacAuthorization")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let src_retention = source
        .pointer("/properties/softDeleteRetentionInDays")
        .and_then(Value::as_u64)
        .unwrap_or(90) as u32;
    let src_purge = source
        .pointer("/properties/enablePurgeProtection")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let target_location = args.target_location.clone().unwrap_or(src_location);
    let target_sku = args.sku.map(|s| s.as_str().to_string()).unwrap_or(src_sku);

    let mut log: Vec<String> = Vec::new();

    let spec = VaultSpec {
        name: &args.target,
        resource_group: &args.target_rg,
        location: &target_location,
        sku: &target_sku,
        rbac: src_rbac,
        retention_days: src_retention,
        purge_protection: src_purge,
        tags: &[],
        public_network_access: crate::PublicNetworkAccess::Enabled.as_str(),
        default_action: crate::NetworkAction::Allow.as_str(),
        bypass: crate::NetworkBypass::AzureServices.as_str(),
        ip_rules: &[],
        enabled_for_deployment: false,
        enabled_for_disk_encryption: false,
        enabled_for_template_deployment: false,
    };
    let action = select_target(
        args.dry_run,
        || arm::get_vault_if_exists(ctx, &args.target, &args.target_rg),
        || arm::create_vault(ctx, &spec),
        |target| {
            validate_existing_target(
                target,
                &target_location,
                &target_sku,
                src_retention,
                src_purge,
            )
        },
    )
    .await?;
    match action {
        TargetAction::WouldCreate => log.push(format!(
            "[dry-run] would create vault '{}' in rg '{}' ({}, sku {}, rbac {}, retention {}d, purge-protection {})",
            args.target, args.target_rg, target_location, target_sku, src_rbac, src_retention, src_purge
        )),
        TargetAction::Create => log.push(format!(
            "created vault '{}' ({}, sku {})", args.target, target_location, target_sku
        )),
        TargetAction::Reuse => log.push(format!(
            "{}reusing existing vault '{}' (configuration preserved)",
            if args.dry_run { "[dry-run] " } else { "" }, args.target
        )),
    }
    if !args.dry_run {
        // Check both newly created and existing targets without changing their
        // permissions or network settings when readiness fails.
        keys::wait_until_ready(ctx, &args.target).await?;
        log.push("target vault is ready for key operations".to_string());
    }
    log.push("note: network settings are not copied from the source vault".to_string());

    // 2. Migrate keys.
    let key_report = keys::migrate_keys(
        ctx,
        &args.source,
        &args.target,
        &args.keys,
        args.strategy,
        args.dry_run,
    )
    .await?;
    log.extend(key_report);

    // 3. Report resources still pointing at the source vault.
    if args.report_usage {
        let usage = search::find_usage(ctx, &args.source).await?;
        if usage.is_empty() {
            log.push("no resources found referencing the source vault".to_string());
        } else {
            log.push(format!(
                "{} resource(s) still reference the source vault and need repointing:",
                usage.len()
            ));
            for row in &usage {
                log.push(format!(
                    "  - {} ({})",
                    row.get("name").and_then(Value::as_str).unwrap_or("?"),
                    row.get("type").and_then(Value::as_str).unwrap_or("?"),
                ));
            }
        }
    }

    match fmt {
        OutputFormat::Json => output::print_json(&json!(log)),
        OutputFormat::Table => {
            for line in &log {
                println!("{line}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    fn target_fixture() -> Value {
        json!({
            "name": "target", "location": "eastus", "tags": {"env": "locked"},
            "properties": {
                "sku": {"family": "A", "name": "standard"},
                "softDeleteRetentionInDays": 90, "enablePurgeProtection": true,
                "enableRbacAuthorization": false, "publicNetworkAccess": "Disabled",
                "accessPolicies": [{"objectId": "operator", "permissions": {"keys": ["get", "list", "restore"]}}],
                "networkAcls": {"defaultAction": "Deny", "bypass": "None", "ipRules": []},
                "enabledForDeployment": true, "enabledForDiskEncryption": false,
                "enabledForTemplateDeployment": true
            }
        })
    }

    fn validate_fixture(target: &Value) -> Result<()> {
        validate_existing_target(target, "eastus", "standard", 7, false)
    }

    #[test]
    fn existing_target_compatibility_preserves_stricter_settings() {
        let mut target = target_fixture();
        target["location"] = json!("EASTUS");
        target["properties"]["sku"]["name"] = json!("Standard");
        validate_fixture(&target).unwrap();
        validate_existing_target(&target, "eastus", "standard", 90, true).unwrap();
        target["properties"]
            .as_object_mut()
            .unwrap()
            .remove("enablePurgeProtection");
        validate_fixture(&target).unwrap(); // Azure can omit disabled purge protection.
        assert!(validate_existing_target(&target, "eastus", "standard", 7, true).is_err());
    }

    #[test]
    fn incompatible_or_incomplete_targets_are_rejected() {
        for (pointer, value) in [
            ("/location", json!("westus")),
            ("/location", Value::Null),
            ("/properties/sku/name", json!("premium")),
            ("/properties/sku/name", Value::Null),
            ("/properties/softDeleteRetentionInDays", json!(6)),
            ("/properties/softDeleteRetentionInDays", json!("90")),
            ("/properties/softDeleteRetentionInDays", Value::Null),
            ("/properties/enablePurgeProtection", json!("true")),
        ] {
            let mut target = target_fixture();
            *target.pointer_mut(pointer).unwrap() = value;
            assert!(validate_fixture(&target).is_err(), "accepted {pointer}");
        }
        let mut target = target_fixture();
        target["properties"]["enablePurgeProtection"] = json!(false);
        assert!(validate_existing_target(&target, "eastus", "standard", 7, true).is_err());
    }

    #[tokio::test]
    async fn existing_targets_are_never_written_including_dry_runs() {
        for dry_run in [false, true] {
            let target = target_fixture();
            let result = select_target(
                dry_run,
                || async { Ok(Some(target.clone())) },
                || async { panic!("must not overwrite an existing target") },
                validate_fixture,
            )
            .await
            .unwrap();
            assert_eq!(result, TargetAction::Reuse);
        }
    }

    #[tokio::test]
    async fn lookup_and_compatibility_errors_never_create_targets() {
        for dry_run in [false, true] {
            let result = select_target(
                dry_run,
                || async { anyhow::bail!("forbidden") },
                || async { panic!("must not create after failed lookup") },
                validate_fixture,
            )
            .await;
            assert!(result.unwrap_err().to_string().contains("forbidden"));
            let mut target = target_fixture();
            target["location"] = json!("westus");
            assert!(
                select_target(
                    dry_run,
                    || async { Ok(Some(target)) },
                    || async { panic!("must not overwrite an incompatible target") },
                    validate_fixture,
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn dry_run_never_creates_missing_target() {
        let action = select_target(
            true,
            || async { Ok(None) },
            || async { panic!("dry run must not write") },
            validate_fixture,
        )
        .await
        .unwrap();
        assert_eq!(action, TargetAction::WouldCreate);
    }

    #[tokio::test]
    async fn retry_reuses_target_created_by_first_attempt() {
        use std::cell::RefCell;
        let stored = RefCell::new(None);
        let writes = std::cell::Cell::new(0);
        for expected in [TargetAction::Create, TargetAction::Reuse] {
            let action = select_target(
                false,
                || async { Ok(stored.borrow().clone()) },
                || async {
                    writes.set(writes.get() + 1);
                    let target = target_fixture();
                    *stored.borrow_mut() = Some(target.clone());
                    Ok(target)
                },
                validate_fixture,
            )
            .await
            .unwrap();
            assert_eq!(action, expected);
        }
        assert_eq!(writes.get(), 1);
        assert_eq!(*stored.borrow(), Some(target_fixture()));
    }

    #[tokio::test]
    async fn same_vault_migration_is_rejected_before_io() {
        let ctx = Context::new(None).unwrap();
        let cli = crate::Cli::try_parse_from([
            "akvutil",
            "vault",
            "migrate",
            "--source",
            "myvault",
            "--source-rg",
            "rg",
            "--target",
            "MYVAULT",
            "--target-rg",
            "rg",
        ])
        .unwrap();
        let Some(crate::Command::Vault(crate::VaultCommand::Migrate(mut args))) = cli.command
        else {
            panic!("expected migration");
        };
        for strategy in [
            crate::MigrateStrategy::BackupRestore,
            crate::MigrateStrategy::Recreate,
        ] {
            for dry_run in [false, true] {
                args.strategy = strategy;
                args.dry_run = dry_run;
                let error = migrate(&ctx, &args, OutputFormat::Json).await.unwrap_err();
                assert!(error.to_string().contains("different vaults"), "{error:#}");
            }
        }
    }
}
