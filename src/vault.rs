//! Vault-level commands: create, show, migrate.

use anyhow::Result;
use serde_json::{json, Value};

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

pub async fn migrate(ctx: &Context, args: &VaultMigrateArgs, fmt: OutputFormat) -> Result<()> {
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

    if args.dry_run {
        log.push(format!(
            "[dry-run] would create vault '{}' in rg '{}' ({}, sku {}, rbac {}, retention {}d, purge-protection {})",
            args.target, args.target_rg, target_location, target_sku, src_rbac, src_retention, src_purge
        ));
    } else {
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
        arm::create_vault(ctx, &spec).await?;
        log.push(format!(
            "created vault '{}' ({}, sku {})",
            args.target, target_location, target_sku
        ));
        // A freshly-created vault isn't immediately usable (DNS + RBAC role
        // propagation), so wait for its data plane before migrating keys rather
        // than racing it into a spurious 403.
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
