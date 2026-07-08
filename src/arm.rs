//! Thin Azure Resource Manager (control-plane) client.
//!
//! The Rust Azure SDK is GA for data-plane crates, but there is no stable
//! management-plane crate for Microsoft.KeyVault yet, so vault CRUD and
//! Resource Graph queries go straight to the ARM REST API using tokens from
//! `azure_identity`.

use anyhow::{bail, Context as _, Result};
use serde_json::{json, Value};

use crate::auth::Context;

const ARM: &str = "https://management.azure.com";
const VAULT_API: &str = "2023-07-01";
const GRAPH_API: &str = "2022-10-01";
const SUB_API: &str = "2022-12-01";

pub struct VaultSpec<'a> {
    pub name: &'a str,
    pub resource_group: &'a str,
    pub location: &'a str,
    pub sku: &'a str,
    pub rbac: bool,
    pub retention_days: u32,
    pub purge_protection: bool,
    pub tags: &'a [(String, String)],
}

async fn check(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("no error detail");
        bail!("ARM request failed ({status}): {msg}");
    }
    Ok(body)
}

/// The tenant that owns a subscription (needed for vault creation).
pub async fn tenant_id(ctx: &Context) -> Result<String> {
    let sub = ctx.subscription()?;
    let url = format!("{ARM}/subscriptions/{sub}?api-version={SUB_API}");
    let body = check(
        ctx.http
            .get(&url)
            .bearer_auth(ctx.arm_token().await?)
            .send()
            .await?,
    )
    .await?;
    body.get("tenantId")
        .and_then(Value::as_str)
        .map(String::from)
        .context("subscription response missing tenantId")
}

pub async fn get_vault(ctx: &Context, name: &str, resource_group: &str) -> Result<Value> {
    let sub = ctx.subscription()?;
    let url = format!(
        "{ARM}/subscriptions/{sub}/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{name}?api-version={VAULT_API}"
    );
    check(
        ctx.http
            .get(&url)
            .bearer_auth(ctx.arm_token().await?)
            .send()
            .await?,
    )
    .await
}

pub async fn create_vault(ctx: &Context, spec: &VaultSpec<'_>) -> Result<Value> {
    let sub = ctx.subscription()?;
    let tenant = tenant_id(ctx).await?;

    let mut properties = json!({
        "tenantId": tenant,
        "sku": { "family": "A", "name": spec.sku },
        "enableRbacAuthorization": spec.rbac,
        "softDeleteRetentionInDays": spec.retention_days,
        "accessPolicies": [],
    });
    if spec.purge_protection {
        // Only send when enabling: the API rejects an explicit `false` on
        // vaults that already have it on, and it can never be turned off.
        properties["enablePurgeProtection"] = json!(true);
    }

    let mut body = json!({
        "location": spec.location,
        "properties": properties,
    });
    if !spec.tags.is_empty() {
        let tags: serde_json::Map<String, Value> = spec
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        body["tags"] = Value::Object(tags);
    }

    let url = format!(
        "{ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}?api-version={VAULT_API}",
        rg = spec.resource_group,
        name = spec.name,
    );
    check(
        ctx.http
            .put(&url)
            .bearer_auth(ctx.arm_token().await?)
            .json(&body)
            .send()
            .await?,
    )
    .await
}

/// Run a KQL query against Azure Resource Graph. Handles paging via $skipToken.
pub async fn graph_query(ctx: &Context, query: &str) -> Result<Vec<Value>> {
    let url = format!("{ARM}/providers/Microsoft.ResourceGraph/resources?api-version={GRAPH_API}");
    let mut rows = Vec::new();
    let mut skip_token: Option<String> = None;

    loop {
        let mut options = json!({ "resultFormat": "objectArray" });
        if let Some(token) = &skip_token {
            options["$skipToken"] = json!(token);
        }
        let mut body = json!({ "query": query, "options": options });
        // Scope to one subscription when set; otherwise Graph searches all
        // subscriptions visible to the caller.
        if let Some(sub) = &ctx.subscription {
            body["subscriptions"] = json!([sub]);
        }

        let resp = check(
            ctx.http
                .post(&url)
                .bearer_auth(ctx.arm_token().await?)
                .json(&body)
                .send()
                .await?,
        )
        .await?;

        if let Some(data) = resp.get("data").and_then(Value::as_array) {
            rows.extend(data.iter().cloned());
        }
        match resp.get("$skipToken").and_then(Value::as_str) {
            Some(token) => skip_token = Some(token.to_string()),
            None => break,
        }
    }
    Ok(rows)
}
