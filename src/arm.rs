//! Thin Azure Resource Manager (control-plane) client.
//!
//! The Rust Azure SDK is GA for data-plane crates, but there is no stable
//! management-plane crate for Microsoft.KeyVault yet, so vault CRUD and
//! Resource Graph queries go straight to the ARM REST API using tokens from
//! `azure_identity`.

use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Value};

use crate::auth::Context;

const ARM: &str = "https://management.azure.com";
const VAULT_API: &str = "2023-07-01";
const GRAPH_API: &str = "2022-10-01";
const SUB_API: &str = "2022-12-01";

/// Max retries for throttled / transient ARM responses.
const MAX_RETRIES: u32 = 5;

/// Characters allowed unescaped in a single ARM URL path segment. ARM resource
/// names permit a few punctuation characters, so keep them literal and encode
/// everything else — critically `/`, `?`, `#`, `%` — so an attacker-influenced
/// name cannot inject extra path or query structure into the request.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'(')
    .remove(b')');

fn seg(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

pub struct VaultSpec<'a> {
    pub name: &'a str,
    pub resource_group: &'a str,
    pub location: &'a str,
    pub sku: &'a str,
    pub rbac: bool,
    pub retention_days: u32,
    pub purge_protection: bool,
    pub tags: &'a [(String, String)],
    pub public_network_access: &'a str,
    pub default_action: &'a str,
    pub bypass: &'a str,
    pub ip_rules: &'a [String],
    pub enabled_for_deployment: bool,
    pub enabled_for_disk_encryption: bool,
    pub enabled_for_template_deployment: bool,
}

async fn check(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    // Read the body as text first: ARM error responses are not always JSON
    // (gateway 502/503 pages, auth challenges, empty bodies), and discarding
    // them hides the real cause behind "no error detail".
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|b| {
                b.pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| {
                let t = text.trim();
                if t.is_empty() {
                    "no error detail".to_string()
                } else {
                    t.chars().take(500).collect()
                }
            });
        bail!("ARM request failed ({status}): {msg}");
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Attach the ARM bearer token, send, and retry on throttling (429) and
/// transient server errors, honoring `Retry-After` when present. Returns the
/// parsed JSON body on success.
async fn send(ctx: &Context, req: reqwest::RequestBuilder) -> Result<Value> {
    let req = req.bearer_auth(ctx.arm_token().await?);
    let mut attempt = 0;
    loop {
        let this = req
            .try_clone()
            .context("ARM request body is not cloneable for retry")?;
        let resp = this.send().await?;
        let status = resp.status();
        let retryable = status.as_u16() == 429 || status.is_server_error();
        if retryable && attempt < MAX_RETRIES {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1u64 << attempt) // exponential backoff fallback
                .min(30);
            tokio::time::sleep(Duration::from_secs(wait)).await;
            attempt += 1;
            continue;
        }
        return check(resp).await;
    }
}

/// The tenant that owns a subscription (needed for vault creation).
pub async fn tenant_id(ctx: &Context) -> Result<String> {
    let sub = seg(ctx.subscription()?);
    let url = format!("{ARM}/subscriptions/{sub}?api-version={SUB_API}");
    let body = send(ctx, ctx.http.get(&url)).await?;
    body.get("tenantId")
        .and_then(Value::as_str)
        .map(String::from)
        .context("subscription response missing tenantId")
}

pub async fn get_vault(ctx: &Context, name: &str, resource_group: &str) -> Result<Value> {
    let sub = seg(ctx.subscription()?);
    let rg = seg(resource_group);
    let name = seg(name);
    let url = format!(
        "{ARM}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}?api-version={VAULT_API}"
    );
    send(ctx, ctx.http.get(&url)).await
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
        "publicNetworkAccess": spec.public_network_access,
        "enabledForDeployment": spec.enabled_for_deployment,
        "enabledForDiskEncryption": spec.enabled_for_disk_encryption,
        "enabledForTemplateDeployment": spec.enabled_for_template_deployment,
        // Defaults ("Allow"/"AzureServices"/no rules) match the service
        // defaults, so always sending networkAcls is behavior-preserving.
        "networkAcls": {
            "defaultAction": spec.default_action,
            "bypass": spec.bypass,
            "ipRules": spec.ip_rules.iter()
                .map(|ip| json!({ "value": ip }))
                .collect::<Vec<_>>(),
        },
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
        sub = seg(sub),
        rg = seg(spec.resource_group),
        name = seg(spec.name),
    );
    send(ctx, ctx.http.put(&url).json(&body)).await
}

/// All locations available to the subscription, with paired-region metadata.
pub async fn list_locations(ctx: &Context) -> Result<Vec<Value>> {
    let sub = seg(ctx.subscription()?);
    let url = format!("{ARM}/subscriptions/{sub}/locations?api-version={SUB_API}");
    let body = send(ctx, ctx.http.get(&url)).await?;
    body.get("value")
        .and_then(Value::as_array)
        .cloned()
        .context("locations response missing value array")
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

        let resp = send(ctx, ctx.http.post(&url).json(&body)).await?;

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
