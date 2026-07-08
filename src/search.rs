//! Discovery via Azure Resource Graph: find vaults, and find the resources
//! that reference a vault (storage accounts, disk encryption sets, SQL
//! servers, VMs with ADE, App Services with key vault references, etc.).

use anyhow::Result;
use serde_json::{json, Value};

use crate::arm;
use crate::auth::Context;
use crate::output;
use crate::OutputFormat;

/// Escape a value for embedding in a single-quoted KQL string literal. KQL
/// uses backslash escaping, so the backslash must be escaped *before* the
/// quote — otherwise an input like `\'` collapses to `\\'`, which KQL reads as
/// an escaped backslash followed by a closing quote, breaking out of the
/// literal and allowing query injection.
fn kql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

pub async fn vaults(ctx: &Context, query: Option<&str>, fmt: OutputFormat) -> Result<()> {
    let filter = match query {
        Some(q) => format!("| where name contains '{}'", kql_escape(q)),
        None => String::new(),
    };
    let kql = format!(
        "Resources \
         | where type =~ 'microsoft.keyvault/vaults' {filter} \
         | project name, resourceGroup, location, subscriptionId, \
                   sku = tostring(properties.sku.name), \
                   rbac = tostring(properties.enableRbacAuthorization), \
                   uri = tostring(properties.vaultUri) \
         | order by name asc"
    );
    let rows = arm::graph_query(ctx, &kql).await?;

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => output::print_table(
            &["NAME", "RESOURCE GROUP", "LOCATION", "SKU", "RBAC", "URI"],
            &rows,
            &["name", "resourceGroup", "location", "sku", "rbac", "uri"],
        ),
    }
    Ok(())
}

/// Find the vault's resource ID via Resource Graph (no resource group needed).
pub async fn find_vault_id(ctx: &Context, name: &str) -> Result<Option<String>> {
    let kql = format!(
        "Resources | where type =~ 'microsoft.keyvault/vaults' \
         | where name =~ '{}' | project id",
        kql_escape(name)
    );
    let rows = arm::graph_query(ctx, &kql).await?;
    Ok(rows
        .first()
        .and_then(|r| r.get("id"))
        .and_then(Value::as_str)
        .map(String::from))
}

/// Resources whose properties reference the vault by URI or resource ID.
pub async fn find_usage(ctx: &Context, vault: &str) -> Result<Vec<Value>> {
    let name = Context::vault_name(vault);
    // Match on the full scheme-qualified host so that vault `foo` does not also
    // match references to `barfoo.vault.azure.net`.
    let uri = format!("https://{}.vault.azure.net", kql_escape(&name));
    let vault_id = find_vault_id(ctx, &name).await?;

    let mut predicate = format!("tostring(properties) contains '{uri}'");
    if let Some(id) = &vault_id {
        predicate.push_str(&format!(
            " or tostring(properties) contains '{}'",
            kql_escape(id)
        ));
    }

    let kql = format!(
        "Resources \
         | where type !~ 'microsoft.keyvault/vaults' \
         | where {predicate} \
         | project name, type, resourceGroup, subscriptionId, location, id \
         | order by type asc, name asc"
    );
    arm::graph_query(ctx, &kql).await
}

pub async fn usage(ctx: &Context, vault: &str, fmt: OutputFormat) -> Result<()> {
    let rows = find_usage(ctx, vault).await?;

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "No resources found referencing vault '{}'.",
                    Context::vault_name(vault)
                );
                println!(
                    "(Resource Graph only sees ARM properties; app settings, code and \
                     pipeline references are not visible here.)"
                );
            } else {
                output::print_table(
                    &["NAME", "TYPE", "RESOURCE GROUP", "LOCATION"],
                    &rows,
                    &["name", "type", "resourceGroup", "location"],
                );
                println!("\n{} resource(s) reference this vault.", rows.len());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::kql_escape;

    #[test]
    fn escapes_backslash_before_quote() {
        // The injection payload `\'` must not collapse into a literal-closing
        // sequence: backslash is doubled, then the quote is escaped.
        assert_eq!(kql_escape(r"\'"), r"\\\'");
        assert_eq!(kql_escape("o'brien"), r"o\'brien");
        assert_eq!(kql_escape(r"c:\path"), r"c:\\path");
        assert_eq!(kql_escape("plain"), "plain");
    }
}
