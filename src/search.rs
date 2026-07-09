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

/// Escape regex metacharacters so a literal chunk of a wildcard pattern
/// cannot alter the regex built around it.
#[allow(dead_code)] // used by name_predicate
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Translate a glob-style pattern into a KQL predicate over `name`.
/// No '*' means substring match; a single leading/trailing '*' anchors the
/// match; anything else compiles to an anchored case-insensitive regex.
/// KQL contains/startswith/endswith are already case-insensitive.
#[allow(dead_code)] // used by build_search_query in the next task
pub fn name_predicate(pattern: &str) -> String {
    let stars = pattern.matches('*').count();
    match stars {
        0 => format!("name contains '{}'", kql_escape(pattern)),
        1 if pattern.ends_with('*') => format!(
            "name startswith '{}'",
            kql_escape(&pattern[..pattern.len() - 1])
        ),
        1 if pattern.starts_with('*') => {
            format!("name endswith '{}'", kql_escape(&pattern[1..]))
        }
        _ => {
            let body = pattern
                .split('*')
                .map(|part| kql_escape(&regex_escape(part)))
                .collect::<Vec<_>>()
                .join(".*");
            format!("name matches regex '(?i)^{body}$'")
        }
    }
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
    use super::{kql_escape, name_predicate};

    #[test]
    fn escapes_backslash_before_quote() {
        // The injection payload `\'` must not collapse into a literal-closing
        // sequence: backslash is doubled, then the quote is escaped.
        assert_eq!(kql_escape(r"\'"), r"\\\'");
        assert_eq!(kql_escape("o'brien"), r"o\'brien");
        assert_eq!(kql_escape(r"c:\path"), r"c:\\path");
        assert_eq!(kql_escape("plain"), "plain");
    }

    #[test]
    fn plain_name_is_contains() {
        assert_eq!(name_predicate("testfoo"), "name contains 'testfoo'");
    }

    #[test]
    fn trailing_star_is_startswith() {
        assert_eq!(name_predicate("testfoo*"), "name startswith 'testfoo'");
    }

    #[test]
    fn leading_star_is_endswith() {
        assert_eq!(name_predicate("*foo"), "name endswith 'foo'");
    }

    #[test]
    fn internal_star_is_case_insensitive_anchored_regex() {
        assert_eq!(
            name_predicate("te*foo"),
            r"name matches regex '(?i)^te.*foo$'"
        );
    }

    #[test]
    fn multiple_stars_use_regex() {
        assert_eq!(
            name_predicate("*crypto*"),
            r"name matches regex '(?i)^.*crypto.*$'"
        );
    }

    #[test]
    fn kql_injection_is_escaped_in_all_branches() {
        assert_eq!(name_predicate("o'brien"), r"name contains 'o\'brien'");
        assert_eq!(name_predicate(r"\'*"), r"name startswith '\\\''");
        assert_eq!(name_predicate("*'"), r"name endswith '\''");
        // Regex branch: quote must still be KQL-escaped inside the regex literal.
        assert_eq!(
            name_predicate("a'*b*c"),
            r"name matches regex '(?i)^a\'.*b.*c$'"
        );
    }

    #[test]
    fn regex_metacharacters_in_literals_are_escaped() {
        // '.' and '+' must match literally, and the regex backslashes must be
        // doubled by kql_escape so KQL hands the regex engine a single backslash.
        assert_eq!(
            name_predicate("te.st*a+b"),
            r"name matches regex '(?i)^te\\.st.*a\\+b$'"
        );
    }
}
