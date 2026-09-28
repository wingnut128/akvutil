use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
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

        // Reject URL structure before parsing: URL normalization can discard
        // controls, collapse paths, or hide an explicit default port.
        if host.chars().any(|c| c.is_control() || c.is_whitespace())
            || host.contains(['/', '@', ':', '?', '#', '\\'])
        {
            bail!(
                "invalid vault endpoint '{vault}': expected an HTTPS host without URL components"
            );
        }
        let url = reqwest::Url::parse(&format!("https://{host}"))
            .context("invalid vault endpoint URL")?;
        let host = url.host_str().context("vault endpoint has no host")?;
        if !VAULT_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
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

/// Reject migrations into the source before either endpoint is used.
pub fn ensure_distinct_vaults(source: &str, target: &str) -> Result<()> {
    if Context::vault_uri(source)? == Context::vault_uri(target)? {
        bail!("source and target must identify different vaults");
    }
    Ok(())
}

/// Azure Key Vault naming rule: 3-24 characters, alphanumerics and hyphens.
fn is_valid_vault_name(name: &str) -> bool {
    (3..=24).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_requires_distinct_endpoints() {
        assert!(ensure_distinct_vaults("myvault", "myvault").is_err());
        assert!(ensure_distinct_vaults("myvault", "https://MYVAULT.vault.azure.net/").is_err());
        assert!(ensure_distinct_vaults("myvault", "othervault").is_ok());
        assert!(ensure_distinct_vaults("https://myvault.vault.azure.cn", "myvault").is_ok());
        assert!(ensure_distinct_vaults("bad/name", "othervault").is_err());
    }

    #[test]
    fn rejects_url_structure_disguised_as_vault_host() {
        for bad in [
            "https://attacker.example?.vault.azure.net",
            "https://attacker.example#.vault.azure.net",
            "https://foo.vault.azure.net?x=1",
            "https://foo.vault.azure.net#x",
            "https://foo.vault.azure.net:443",
            "https://user@foo.vault.azure.net",
            r"https://attacker.example\.vault.azure.net",
            "https://foo.vault.azure.net/keys",
            "https://foo.vault.azure.net/keys/..",
            "https://foo.vault.azure.net\n",
            "https://fo\to.vault.azure.net",
            "https://%61ttacker.example%23.vault.azure.net",
        ] {
            assert!(Context::vault_uri(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn canonicalizes_equivalent_endpoints() {
        for input in ["MyVault", "https://MYVAULT.vault.azure.net/"] {
            assert_eq!(
                Context::vault_uri(input).unwrap(),
                "https://myvault.vault.azure.net"
            );
        }
        for suffix in VAULT_SUFFIXES {
            let endpoint = format!("https://myvault{suffix}");
            assert_eq!(Context::vault_uri(&endpoint).unwrap(), endpoint);
        }
    }

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
