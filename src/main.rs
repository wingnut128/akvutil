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
    about = "Azure Key Vault utility: create/migrate vaults and keys, and find resources that use them",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Azure subscription ID (falls back to $AZURE_SUBSCRIPTION_ID)
    #[arg(long, global = true, env = "AZURE_SUBSCRIPTION_ID")]
    pub subscription: Option<String>,

    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Command>,
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
    /// Find resources by type and name, or find what uses a vault
    Search(SearchArgs),
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ResourceType {
    /// Key vaults (microsoft.keyvault/vaults)
    Keyvault,
    /// Storage accounts (microsoft.storage/storageaccounts)
    Storage,
    /// Disk encryption sets (microsoft.compute/diskencryptionsets)
    Des,
    /// Resource groups
    Rg,
}

impl ResourceType {
    pub const ALL: [ResourceType; 4] = [
        ResourceType::Keyvault,
        ResourceType::Storage,
        ResourceType::Des,
        ResourceType::Rg,
    ];
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

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SearchArgs {
    #[command(subcommand)]
    pub command: Option<SearchCommand>,

    /// Resource types to search (comma-separated or repeated; default: all)
    #[arg(long = "type", value_enum, value_delimiter = ',')]
    pub types: Vec<ResourceType>,

    /// Name pattern: substring match, or use '*' wildcards (foo*, *foo, f*o)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Subcommand)]
pub enum SearchCommand {
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

    // arg_required_else_help covers the bare invocation; this covers global
    // flags given without a subcommand (e.g. `akvutil --output json`).
    // Help goes to stderr to match clap's arg_required_else_help error path.
    let Some(command) = cli.command else {
        use clap::CommandFactory as _;
        eprint!("{}", Cli::command().render_help());
        std::process::exit(2);
    };

    let ctx = auth::Context::new(cli.subscription.clone())?;

    match command {
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
        Command::Search(args) => match args.command {
            Some(SearchCommand::Usage { vault }) => search::usage(&ctx, &vault, cli.output).await,
            None => {
                let mut types = if args.types.is_empty() {
                    ResourceType::ALL.to_vec()
                } else {
                    args.types
                };
                types.sort();
                types.dedup();
                search::resources(&ctx, &types, args.name.as_deref(), cli.output).await
            }
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

    use clap::Parser as _;

    #[test]
    fn bare_invocation_shows_help() {
        // An env-provided --subscription counts as "args present", which
        // suppresses arg_required_else_help; clear it so the test is
        // deterministic regardless of the local shell environment.
        std::env::remove_var("AZURE_SUBSCRIPTION_ID");
        // `unwrap_err()` would require `Cli: Debug`; match instead to avoid
        // adding Debug derives across every CLI type.
        let err = match super::Cli::try_parse_from(["akvutil"]) {
            Err(err) => err,
            Ok(_) => panic!("expected parse error on bare invocation"),
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn search_flags_parse() {
        let cli = super::Cli::try_parse_from([
            "akvutil",
            "search",
            "--type",
            "keyvault,storage",
            "--name",
            "testfoo*",
        ])
        .unwrap();
        let Some(super::Command::Search(args)) = cli.command else {
            panic!("expected search command");
        };
        assert!(args.command.is_none());
        assert_eq!(
            args.types,
            vec![super::ResourceType::Keyvault, super::ResourceType::Storage]
        );
        assert_eq!(args.name.as_deref(), Some("testfoo*"));
    }

    #[test]
    fn search_usage_subcommand_still_parses() {
        let cli = super::Cli::try_parse_from(["akvutil", "search", "usage", "--vault", "myvault"])
            .unwrap();
        let Some(super::Command::Search(args)) = cli.command else {
            panic!("expected search command");
        };
        assert!(matches!(
            args.command,
            Some(super::SearchCommand::Usage { vault }) if vault == "myvault"
        ));
    }
}
