use std::sync::Arc;

use anyhow::{Context as _, Result};
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;

const ARM_SCOPE: &str = "https://management.azure.com/.default";

/// Shared auth + subscription context.
pub struct Context {
    pub credential: Arc<DeveloperToolsCredential>,
    pub subscription: Option<String>,
    pub http: reqwest::Client,
}

impl Context {
    pub fn new(subscription: Option<String>) -> Result<Self> {
        let credential = DeveloperToolsCredential::new(None)
            .context("failed to build credential; run `az login` first")?;
        Ok(Self {
            credential,
            subscription,
            http: reqwest::Client::new(),
        })
    }

    pub fn subscription(&self) -> Result<&str> {
        self.subscription
            .as_deref()
            .context("no subscription set; pass --subscription or set AZURE_SUBSCRIPTION_ID")
    }

    /// Bearer token for Azure Resource Manager.
    pub async fn arm_token(&self) -> Result<String> {
        let token = self
            .credential
            .get_token(&[ARM_SCOPE], None)
            .await
            .context("failed to acquire ARM token; run `az login` first")?;
        Ok(token.token.secret().to_string())
    }

    /// Normalize a vault name or URI to a full vault URI.
    pub fn vault_uri(vault: &str) -> String {
        if vault.starts_with("https://") {
            vault.trim_end_matches('/').to_string()
        } else {
            format!("https://{vault}.vault.azure.net")
        }
    }

    /// Extract the bare vault name from a name or URI.
    pub fn vault_name(vault: &str) -> String {
        vault
            .trim_start_matches("https://")
            .split('.')
            .next()
            .unwrap_or(vault)
            .to_string()
    }
}
