//! Discovery via Azure Resource Graph: find vaults, and find the resources
//! that reference a vault (storage accounts, disk encryption sets, SQL
//! servers, VMs with ADE, App Services with key vault references, etc.).

use anyhow::Result;
use serde_json::{json, Value};

use crate::arm;
use crate::auth::Context;
use crate::output;
use crate::OutputFormat;
use crate::ResourceType;

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

impl ResourceType {
    /// Source table + type filter for this resource type.
    fn branch(self) -> &'static str {
        match self {
            ResourceType::Keyvault => {
                "Resources | where type =~ 'microsoft.keyvault/vaults'"
            }
            ResourceType::Storage => {
                "Resources | where type =~ 'microsoft.storage/storageaccounts'"
            }
            ResourceType::Des => {
                "Resources | where type =~ 'microsoft.compute/diskencryptionsets'"
            }
            ResourceType::Rg => {
                "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
            }
        }
    }

    /// Common projection. Resource groups have no parent group, so they
    /// project their own name into the resourceGroup column.
    fn projection(self) -> &'static str {
        match self {
            ResourceType::Rg => {
                "project name, type, resourceGroup = name, location, subscriptionId, id"
            }
            _ => "project name, type, resourceGroup, location, subscriptionId, id",
        }
    }
}

/// One KQL query covering all requested types — a single Resource Graph
/// call regardless of how many types are searched.
pub fn build_search_query(types: &[ResourceType], name: Option<&str>) -> String {
    assert!(
        !types.is_empty(),
        "build_search_query requires at least one resource type"
    );
    let filter = name
        .map(|n| format!(" | where {}", name_predicate(n)))
        .unwrap_or_default();
    // Resource Graph rejects a leading `union (q1), (q2)` form
    // (Operator_FailedToResolveEntity on the table inside the parens), so
    // the first branch heads the pipeline and the rest are piped in.
    let mut branches = types
        .iter()
        .map(|t| format!("{}{filter} | {}", t.branch(), t.projection()));
    let first = branches.next().unwrap();
    let rest: Vec<String> = branches.map(|b| format!("({b})")).collect();
    let body = if rest.is_empty() {
        first
    } else {
        format!("{first} | union {}", rest.join(", "))
    };
    format!("{body} | order by type asc, name asc")
}

pub async fn resources(
    ctx: &Context,
    types: &[ResourceType],
    name: Option<&str>,
    fmt: OutputFormat,
) -> Result<()> {
    let kql = build_search_query(types, name);
    let rows = arm::graph_query(ctx, &kql).await?;

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No matching resources found.");
            } else {
                output::print_table(
                    &["NAME", "TYPE", "RESOURCE GROUP", "LOCATION", "SUBSCRIPTION"],
                    &rows,
                    &[
                        "name",
                        "type",
                        "resourceGroup",
                        "location",
                        "subscriptionId",
                    ],
                );
                println!("\n{} resource(s) found.", rows.len());
            }
        }
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
    use super::{build_search_query, kql_escape, name_predicate};
    use crate::ResourceType;

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

    #[test]
    fn backslash_adjacent_to_wildcard_compounds_correctly() {
        // regex_escape adds one backslash, kql_escape doubles both.
        assert_eq!(
            name_predicate(r"a\b*c*d"),
            r"name matches regex '(?i)^a\\\\b.*c.*d$'"
        );
    }

    #[test]
    fn bare_star_matches_everything_via_startswith() {
        // Single trailing '*': the startswith arm wins over endswith by order.
        assert_eq!(name_predicate("*"), "name startswith ''");
    }

    #[test]
    fn single_type_query_has_no_union() {
        assert_eq!(
            build_search_query(&[ResourceType::Keyvault], Some("foo*")),
            "Resources | where type =~ 'microsoft.keyvault/vaults' \
             | where name startswith 'foo' \
             | project name, type, resourceGroup, location, subscriptionId, id \
             | order by type asc, name asc"
        );
    }

    #[test]
    fn multi_type_query_unions_branches_and_repeats_filter() {
        let q = build_search_query(&[ResourceType::Storage, ResourceType::Des], Some("prod"));
        // Resource Graph rejects a leading `union (q1), (q2)` — the first
        // branch must be the pipeline head with the rest piped through union.
        assert!(q.starts_with("Resources | where type =~ 'microsoft.storage/storageaccounts'"));
        assert!(q.contains("| union (Resources | where type =~ 'microsoft.compute/diskencryptionsets'"));
        assert_eq!(q.matches("| where name contains 'prod'").count(), 2);
        assert!(q.ends_with("| order by type asc, name asc"));
    }

    #[test]
    fn multi_type_query_never_starts_with_union() {
        // Regression: ARG 400s on `union (Resources | ...)` with
        // Operator_FailedToResolveEntity — bare `akvutil search` hit this.
        let q = build_search_query(&ResourceType::ALL, None);
        assert!(!q.starts_with("union"));
        assert_eq!(q.matches("| union (").count(), 1);
        assert_eq!(q.matches("ResourceContainers").count(), 1);
    }

    #[test]
    fn rg_branch_uses_resourcecontainers_and_projects_own_name() {
        let q = build_search_query(&[ResourceType::Rg], None);
        assert!(q.contains(
            "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
        ));
        assert!(q.contains("resourceGroup = name"));
        // No name filter when no pattern given.
        assert!(!q.contains("| where name"));
    }
}
