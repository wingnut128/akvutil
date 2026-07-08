use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;

const ARM_SCOPE: &str = "https://management.azure.com/.default";

/// Host suffixes that identify a genuine Key Vault (or Managed HSM) data-plane
/// endpoint across Azure clouds. Any URI whose host does not end in one of
/// these is rejected so that a stray `--vault https://attacker.example` can
/// never receive the caller's Key Vault bearer token.
const VAULT_SUFFIXES: &[&str] = &[
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
    ".vault.microsoftazure.de",
    ".managedhsm.azure.net",
    ".managedhsm.azure.cn",
    ".managedhsm.usgovcloudapi.net",
];

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

    /// Normalize a vault name or URI to a full vault URI, rejecting anything
    /// that is not a recognized Key Vault host. The caller's data-plane token
    /// is attached to requests against the returned URI, so this is the guard
    /// that prevents that token (and, during migration, exported key backups)
    /// from being sent to an arbitrary host.
    pub fn vault_uri(vault: &str) -> Result<String> {
        let host = match vault.strip_prefix("https://") {
            // Already a URI: take the host, reject any path/port/userinfo.
            Some(rest) => rest.trim_end_matches('/').to_string(),
            // Bare name: it must be a valid vault name, then we build the
            // public-cloud host. Without this check a name like `evil.com/x`
            // would produce the host `evil.com`.
            None => {
                if !is_valid_vault_name(vault) {
                    bail!(
                        "invalid vault name '{vault}': expected 3-24 characters of \
                         letters, digits and hyphens, or a full https:// Key Vault URI"
                    );
                }
                format!("{vault}.vault.azure.net")
            }
        };

        let host_lc = host.to_ascii_lowercase();
        let is_vault_host = !host.contains('/')
            && !host.contains('@')
            && !host.contains(':')
            && VAULT_SUFFIXES.iter().any(|s| host_lc.ends_with(s));
        if !is_vault_host {
            bail!(
                "refusing to use vault endpoint '{vault}': host must be an Azure Key \
                 Vault domain (e.g. *.vault.azure.net)"
            );
        }
        Ok(format!("https://{host}"))
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

/// Azure Key Vault naming rule: 3-24 characters, alphanumerics and hyphens.
fn is_valid_vault_name(name: &str) -> bool {
    (3..=24).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bare_name_and_known_hosts() {
        assert_eq!(
            Context::vault_uri("myvault").unwrap(),
            "https://myvault.vault.azure.net"
        );
        assert_eq!(
            Context::vault_uri("https://myvault.vault.azure.net/").unwrap(),
            "https://myvault.vault.azure.net"
        );
        // Sovereign clouds and Managed HSM are recognized.
        assert!(Context::vault_uri("https://v.vault.usgovcloudapi.net").is_ok());
        assert!(Context::vault_uri("https://v.managedhsm.azure.net").is_ok());
    }

    #[test]
    fn rejects_non_keyvault_endpoints() {
        // Foreign host would otherwise receive the data-plane token.
        assert!(Context::vault_uri("https://evil.example").is_err());
        // Look-alike host that only contains the suffix mid-string.
        assert!(Context::vault_uri("https://vault.azure.net.evil.com").is_err());
        // Credentials / path / port smuggled into a URI.
        assert!(Context::vault_uri("https://foo.vault.azure.net/../steal").is_err());
        assert!(Context::vault_uri("https://user@evil.example").is_err());
        assert!(Context::vault_uri("https://foo.vault.azure.net:8080").is_err());
        // Bare name that would inject an arbitrary host.
        assert!(Context::vault_uri("evil.com/x").is_err());
        assert!(Context::vault_uri("ab").is_err()); // too short
    }

    #[test]
    fn vault_name_parsing() {
        assert_eq!(
            Context::vault_name("https://myvault.vault.azure.net"),
            "myvault"
        );
        assert_eq!(Context::vault_name("myvault"), "myvault");
    }
}
