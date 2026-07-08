mod arm;
mod auth;
mod keys;
mod output;
mod search;
mod vault;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "akvutil",
    version,
    about = "Azure Key Vault utility: create/migrate vaults and keys, and find resources that use them"
)]
pub struct Cli {
    /// Azure subscription ID (falls back to $AZURE_SUBSCRIPTION_ID)
    #[arg(long, global = true, env = "AZURE_SUBSCRIPTION_ID")]
    pub subscription: Option<String>,

    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage key vaults
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Manage keys within a vault
    #[command(subcommand)]
    Key(KeyCommand),
    /// Find vaults and resources that use them
    #[command(subcommand)]
    Search(SearchCommand),
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Create a new key vault
    Create(VaultCreateArgs),
    /// Show a key vault
    Show {
        #[arg(long)]
        name: String,
        #[arg(long = "resource-group", short = 'g')]
        resource_group: String,
    },
    /// Migrate a vault: create the target vault and move its keys
    Migrate(VaultMigrateArgs),
}

#[derive(Args)]
pub struct VaultCreateArgs {
    /// Vault name (3-24 chars, becomes https://<name>.vault.azure.net)
    #[arg(long)]
    pub name: String,
    #[arg(long = "resource-group", short = 'g')]
    pub resource_group: String,
    #[arg(long, short = 'l')]
    pub location: String,
    /// Vault SKU
    #[arg(long, value_enum, default_value_t = VaultSku::Standard)]
    pub sku: VaultSku,
    /// Use Azure RBAC for data-plane authorization (recommended)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub rbac: bool,
    /// Soft-delete retention in days (7-90)
    #[arg(long, default_value_t = 90)]
    pub retention_days: u32,
    /// Enable purge protection (cannot be disabled later)
    #[arg(long)]
    pub purge_protection: bool,
    /// Tags as key=value pairs
    #[arg(long, value_parser = parse_tag)]
    pub tag: Vec<(String, String)>,
}

#[derive(Args)]
pub struct VaultMigrateArgs {
    #[arg(long)]
    pub source: String,
    #[arg(long = "source-rg")]
    pub source_rg: String,
    #[arg(long)]
    pub target: String,
    #[arg(long = "target-rg")]
    pub target_rg: String,
    /// Target location (defaults to the source vault's location)
    #[arg(long)]
    pub target_location: Option<String>,
    /// Target SKU (defaults to the source vault's SKU)
    #[arg(long, value_enum)]
    pub sku: Option<VaultSku>,
    /// Key migration strategy
    #[arg(long, value_enum, default_value_t = MigrateStrategy::Recreate)]
    pub strategy: MigrateStrategy,
    /// Only migrate these keys (comma-separated). Default: all keys
    #[arg(long, value_delimiter = ',')]
    pub keys: Vec<String>,
    /// Print the plan without changing anything
    #[arg(long)]
    pub dry_run: bool,
    /// After migrating, list resources still pointing at the source vault
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub report_usage: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum VaultSku {
    Standard,
    Premium,
}

impl VaultSku {
    pub fn as_str(&self) -> &'static str {
        match self {
            VaultSku::Standard => "standard",
            VaultSku::Premium => "premium",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum MigrateStrategy {
    /// Create same-shape keys (type/size/curve/ops) in the target vault.
    /// New key material; repoint consumers afterwards.
    Recreate,
    /// Key Vault backup/restore blobs. Preserves key material and versions,
    /// but only works within the same Azure geography and subscription.
    BackupRestore,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Create a key in a vault
    Create(KeyCreateArgs),
    /// List keys in a vault
    List {
        /// Vault name or full https URI
        #[arg(long)]
        vault: String,
    },
    /// Migrate keys between vaults
    Migrate(KeyMigrateArgs),
}

#[derive(Args)]
pub struct KeyCreateArgs {
    /// Vault name or full https URI
    #[arg(long)]
    pub vault: String,
    #[arg(long)]
    pub name: String,
    /// Key type (HSM variants require a premium vault or managed HSM)
    #[arg(long, value_enum, default_value_t = KeyKind::Rsa)]
    pub kty: KeyKind,
    /// RSA key size in bits (2048, 3072, 4096)
    #[arg(long)]
    pub size: Option<i32>,
    /// EC curve name
    #[arg(long, value_enum)]
    pub curve: Option<Curve>,
    /// Permitted operations (comma-separated): encrypt,decrypt,sign,verify,wrapKey,unwrapKey
    #[arg(long, value_delimiter = ',')]
    pub ops: Vec<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum KeyKind {
    Rsa,
    RsaHsm,
    Ec,
    EcHsm,
    Oct,
    OctHsm,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum Curve {
    #[value(name = "p-256")]
    P256,
    #[value(name = "p-256k")]
    P256k,
    #[value(name = "p-384")]
    P384,
    #[value(name = "p-521")]
    P521,
}

#[derive(Args)]
pub struct KeyMigrateArgs {
    /// Source vault name or URI
    #[arg(long = "source-vault")]
    pub source_vault: String,
    /// Target vault name or URI
    #[arg(long = "target-vault")]
    pub target_vault: String,
    /// Only migrate these keys (comma-separated). Default: all keys
    #[arg(long, value_delimiter = ',')]
    pub keys: Vec<String>,
    #[arg(long, value_enum, default_value_t = MigrateStrategy::Recreate)]
    pub strategy: MigrateStrategy,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand)]
pub enum SearchCommand {
    /// Find key vaults across the subscription(s)
    Vaults {
        /// Substring to match against vault names (optional)
        query: Option<String>,
    },
    /// Find resources that use a vault (storage accounts, disk encryption
    /// sets, SQL servers, VMs, etc.)
    Usage {
        /// Vault name
        #[arg(long)]
        vault: String,
    },
}

fn parse_tag(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("invalid tag '{s}', expected key=value"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = auth::Context::new(cli.subscription.clone())?;

    match cli.command {
        Command::Vault(cmd) => match cmd {
            VaultCommand::Create(args) => vault::create(&ctx, &args, cli.output).await,
            VaultCommand::Show {
                name,
                resource_group,
            } => vault::show(&ctx, &name, &resource_group, cli.output).await,
            VaultCommand::Migrate(args) => vault::migrate(&ctx, &args, cli.output).await,
        },
        Command::Key(cmd) => match cmd {
            KeyCommand::Create(args) => keys::create(&ctx, &args, cli.output).await,
            KeyCommand::List { vault } => keys::list(&ctx, &vault, cli.output).await,
            KeyCommand::Migrate(args) => keys::migrate(&ctx, &args, cli.output).await,
        },
        Command::Search(cmd) => match cmd {
            SearchCommand::Vaults { query } => {
                search::vaults(&ctx, query.as_deref(), cli.output).await
            }
            SearchCommand::Usage { vault } => search::usage(&ctx, &vault, cli.output).await,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::parse_tag;

    #[test]
    fn parses_key_value() {
        assert_eq!(parse_tag("env=prod"), Ok(("env".into(), "prod".into())));
        // Only the first '=' splits, so values may contain '='.
        assert_eq!(parse_tag("conn=a=b=c"), Ok(("conn".into(), "a=b=c".into())));
        // Empty value is allowed; empty key is preserved as given.
        assert_eq!(parse_tag("k="), Ok(("k".into(), String::new())));
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(parse_tag("novalue").is_err());
    }
}
