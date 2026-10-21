//! Command definitions and handlers.
//!
//! `init` and `recover` work on the vault file directly (no daemon needed).
//! Everything else goes through the daemon, which is started on demand.

use crate::client::Client;
use crate::daemon;
use crate::io::{self as uio, CliError};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::import::parse_dotenv;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::{SecretKind, Vault, VaultError};
use unseenkey_daemon::VaultPaths;

#[derive(Parser)]
#[command(
    name = "usk",
    version,
    about = "Unseenkey: use secrets without seeing them"
)]
struct Cli {
    /// Path to the vault file (default: the user data directory).
    #[arg(long, global = true, env = "USK_VAULT")]
    vault: Option<PathBuf>,
    /// Machine-readable output where supported.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    Desktop,
    Light,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init {
        /// Argon2id cost profile.
        #[arg(long, value_enum, default_value = "desktop")]
        profile: Profile,
    },
    /// Unlock the vault in the daemon.
    Unlock,
    /// Lock the vault in the daemon.
    Lock,
    /// Add a secret. The value is read from a hidden prompt, or from stdin with --stdin.
    Add {
        /// Unique name, e.g. `openai` or `stripe-live`.
        name: String,
        /// Secret type (auto-detected when omitted).
        #[arg(long, value_parser = parse_kind)]
        r#type: Option<SecretKind>,
        /// Provider id (auto-detected when omitted).
        #[arg(long)]
        provider: Option<String>,
        /// Allowed upstream host; repeatable. Defaults from the provider.
        #[arg(long = "upstream")]
        upstreams: Vec<String>,
        /// Tag; repeatable.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Free-form note.
        #[arg(long)]
        notes: Option<String>,
        /// Read the value from stdin (after the password line when not a terminal).
        #[arg(long)]
        stdin: bool,
    },
    /// List secrets (never values).
    Ls,
    /// Show a secret's metadata (never the value).
    Show { name: String },
    /// Print a secret's value once. Requires --yes.
    Reveal {
        name: String,
        /// Confirm you want the value printed to this terminal.
        #[arg(long)]
        yes: bool,
        /// Why (recorded in the audit log).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Delete a secret.
    Rm {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// Import secrets from a .env file.
    Import {
        /// Path to the .env file.
        #[arg(long = "from-env")]
        from_env: PathBuf,
        /// Import every KEY=value line, not only ones that look like secrets.
        #[arg(long)]
        all: bool,
        /// Show what would be imported without writing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Set a new password using the recovery phrase.
    Recover {
        #[arg(long, value_enum, default_value = "desktop")]
        profile: Profile,
    },
    /// Show vault and daemon status.
    Status,
    /// Diagnose common problems.
    Doctor,
    /// Show requests waiting for your approval.
    Approvals,
    /// Approve a waiting request (default: the latest).
    Approve {
        /// Approval id, or `latest`.
        #[arg(default_value = "latest")]
        id: String,
        /// Remember this decision for the same handle and rule.
        #[arg(long)]
        remember: bool,
    },
    /// Deny a waiting request (default: the latest).
    Deny {
        /// Approval id, or `latest`.
        #[arg(default_value = "latest")]
        id: String,
    },
    /// MCP server for Claude Code, Claude Desktop, Cursor and Windsurf.
    Mcp {
        /// Run the stdio bridge as this registered client (used by the tools' configs).
        #[arg(long)]
        client: Option<String>,
        #[command(subcommand)]
        action: Option<McpAction>,
    },
    /// Run a program with secrets injected as environment variables (weaker mode:
    /// the program sees the values). Requires `usk secret set <name> --allow-injection true`.
    Run {
        /// `VAR=secret`, repeatable.
        #[arg(long = "with", value_name = "VAR=SECRET", required = true)]
        with: Vec<String>,
        /// The program and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Find real keys in a `.env` file and replace them with handles.
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },
    /// Change a secret's settings.
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// List provider presets and their ready-made policies.
    Presets,
    /// Create, list and revoke handles (the strings you give to tools instead of keys).
    Handle {
        #[command(subcommand)]
        action: HandleAction,
    },
    /// Create a handle and print the environment variables for the provider's SDK.
    Env {
        /// Secret name.
        secret: String,
        /// Preset policy id (e.g. `chat`, `payments`) or `provider:policy`.
        #[arg(long)]
        policy: Option<String>,
        /// Handle label (default: "<secret> env").
        #[arg(long)]
        label: Option<String>,
        /// Output form.
        #[arg(long, value_enum)]
        shell: Option<Shell>,
        /// Shape the handle like the provider's own keys, for tools that
        /// check the key format. It is still only a handle.
        #[arg(long)]
        camouflage: bool,
        /// Hard cap on requests: `1000/day` or `60/min` (repeatable).
        #[arg(long, value_name = "N/day|N/min")]
        cap: Vec<String>,
        /// What unusual activity does to the handle (default: throttle).
        #[arg(long, value_enum)]
        on_anomaly: Option<OnAnomaly>,
    },
    /// Show the audit log.
    Log {
        #[command(subcommand)]
        action: Option<LogAction>,
        /// Only events of this kind (use, deny, egress_blocked, reveal, ...).
        #[arg(long)]
        kind: Option<String>,
        /// Start at this sequence number.
        #[arg(long, default_value_t = 1)]
        since: u64,
        /// Show at most this many events.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Inspect policies.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Manage the background daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Run the daemon in this process.
    Run {
        /// Loopback address (default from config or 127.0.0.1:7391).
        #[arg(long)]
        listen: Option<String>,
        /// Lock after N idle minutes (0 disables).
        #[arg(long)]
        idle_lock_minutes: Option<u64>,
        /// Log to the vault's logs directory instead of stderr (used when spawned).
        #[arg(long, hide = true)]
        detached: bool,
    },
    /// Stop the running daemon.
    Stop,
    /// Show whether the daemon is running.
    Status,
}

fn parse_kind(s: &str) -> Result<SecretKind, String> {
    SecretKind::parse(s).ok_or_else(|| {
        format!(
            "unknown type; one of: {}",
            SecretKind::ALL
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn profile(p: Profile) -> Argon2Profile {
    match p {
        Profile::Desktop => Argon2Profile::DESKTOP,
        Profile::Light => Argon2Profile::LIGHT,
    }
}

fn map_vault_err(e: VaultError) -> CliError {
    match e {
        VaultError::Locked | VaultError::WrongCredential => {
            CliError::with_code(uio::EXIT_LOCKED, "wrong_password", e.to_string())
        }
        VaultError::NoVault => CliError::general("no vault found; run `usk init` first"),
        other => CliError::general(other.to_string()),
    }
}

/// Parse arguments and dispatch.
pub fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let vault = daemon::vault_path(cli.vault)?;
    let paths = VaultPaths::from_vault_file(&vault);
    match cli.command {
        Command::Init { profile: p } => init(&paths, profile(p)),
        Command::Unlock => {
            let c = Client::connect(&paths, true)?;
            c.ensure_unlocked()?;
            println!("Unlocked.");
            Ok(())
        }
        Command::Lock => {
            if let Some(c) = Client::try_connect(&paths) {
                c.post("/v1/lock", json!({}))?;
            }
            println!("Locked.");
            Ok(())
        }
        Command::Add {
            name,
            r#type,
            provider,
            upstreams,
            tags,
            notes,
            stdin,
        } => add(
            &paths, name, r#type, provider, upstreams, tags, notes, stdin,
        ),
        Command::Ls => ls(&paths, cli.json),
        Command::Show { name } => show(&paths, &name, cli.json),
        Command::Reveal { name, yes, reason } => reveal(&paths, &name, yes, reason),
        Command::Rm { name, yes } => rm(&paths, &name, yes),
        Command::Import {
            from_env,
            all,
            dry_run,
        } => import(&paths, &from_env, all, dry_run),
        Command::Recover { profile: p } => recover(&paths, profile(p)),
        Command::Status => status(&paths, cli.json),
        Command::Doctor => doctor(&paths),
        Command::Presets => presets(cli.json),
        Command::Run { with, command } => crate::run::run(&paths, with, command),
        Command::Approvals => approvals_list(&paths, cli.json),
        Command::Approve { id, remember } => approvals_decide(&paths, &id, true, remember),
        Command::Deny { id } => approvals_decide(&paths, &id, false, false),
        Command::Mcp { client, action } => match (client, action) {
            (Some(c), None) => crate::mcp::bridge(&paths, &c),
            (_, Some(McpAction::Install { client, home })) => {
                crate::mcp::install(&paths, &client, home.as_deref())
            }
            (_, Some(McpAction::Remove { client })) => crate::mcp::remove(&paths, &client),
            (_, Some(McpAction::Clients)) => crate::mcp::clients(&paths, cli.json),
            (None, None) => Err(CliError::general(
                "usage: usk mcp install <claude-code|claude-desktop|cursor|windsurf|all>, usk mcp clients, usk mcp remove <client>, or usk mcp --client <name> (stdio bridge)",
            )),
        },
        Command::Guard { action } => match action {
            GuardAction::Scan { path } => crate::guard::scan(&path, cli.json).map(|_| ()),
            GuardAction::Fix { path, dry_run } => crate::guard::fix(&paths, &path, dry_run),
        },
        Command::Secret { action } => match action {
            SecretAction::Set {
                name,
                allow_injection,
                no_scrub,
                notes,
                tags,
                upstreams,
            } => secret_set(
                &paths,
                &name,
                allow_injection,
                no_scrub,
                notes,
                tags,
                upstreams,
            ),
        },
        Command::Handle { action } => match action {
            HandleAction::Create {
                secret,
                label,
                policy,
                policy_file,
                expires_days,
                camouflage,
                cap,
                canary,
                on_anomaly,
            } => handle_create(
                &paths,
                &secret,
                label,
                policy,
                policy_file,
                expires_days,
                camouflage,
                Incidents {
                    cap,
                    canary,
                    on_anomaly,
                },
                cli.json,
            ),
            HandleAction::Ls => handle_ls(&paths, cli.json),
            HandleAction::Show { r#ref } => handle_show(&paths, &r#ref, cli.json),
            HandleAction::Revoke { r#ref } => handle_revoke(&paths, &r#ref),
            HandleAction::Forget { r#ref, rule } => handle_forget(&paths, &r#ref, rule),
            HandleAction::Resume { r#ref } => handle_resume(&paths, &r#ref),
            HandleAction::Policy {
                r#ref,
                preset,
                file,
            } => handle_policy(&paths, &r#ref, preset, file),
        },
        Command::Env {
            secret,
            policy,
            label,
            shell,
            camouflage,
            cap,
            on_anomaly,
        } => env_cmd(
            &paths,
            &secret,
            policy,
            label,
            shell,
            camouflage,
            Incidents {
                cap,
                canary: false,
                on_anomaly,
            },
        ),
        Command::Log {
            action,
            kind,
            since,
            limit,
        } => match action {
            Some(LogAction::Verify) => log_verify(&paths, cli.json),
            None => log_list(&paths, kind, since, limit, cli.json),
        },
        Command::Policy { action } => match action {
            PolicyAction::Explain { preset, file } => policy_explain(preset, file, cli.json),
            PolicyAction::Check { file } => policy_check(&file),
        },
        Command::Daemon { action } => match action {
            DaemonAction::Run {
                listen,
                idle_lock_minutes,
                detached,
            } => {
                let opts = daemon::resolve_options(&paths, listen, idle_lock_minutes)?;
                daemon::run(opts, &paths, detached)
            }
            DaemonAction::Stop => {
                match Client::try_connect(&paths) {
                    Some(c) => {
                        // The daemon answers first and exits ~200 ms later, so a
                        // dropped connection is fine. Either way, wait until it is
                        // really gone: a command run right after `stop` must not
                        // find the old daemon still answering.
                        let posted = c.post("/v1/shutdown", json!({}));
                        let gone = daemon::wait_until(std::time::Duration::from_secs(5), || {
                            (Client::try_connect(&paths).is_none() && !paths.addr.exists())
                                .then_some(())
                        });
                        match (posted, gone) {
                            (_, Some(())) => println!("Daemon stopped."),
                            (Err(e), None) => return Err(e),
                            (Ok(_), None) => {
                                return Err(CliError::general(
                                    "daemon acknowledged the stop but is still running",
                                ))
                            }
                        }
                    }
                    None => println!("Daemon is not running."),
                }
                Ok(())
            }
            DaemonAction::Status => {
                match Client::try_connect(&paths) {
                    Some(c) => {
                        let s = c.get("/v1/status")?;
                        println!(
                            "running (pid {}), locked={}, uptime={}s",
                            daemon::pid_file(&paths).unwrap_or(0),
                            s["locked"],
                            s["uptime_s"]
                        );
                    }
                    None => println!("not running"),
                }
                Ok(())
            }
        },
    }
}

fn unlocked(paths: &VaultPaths) -> Result<Client, CliError> {
    let c = Client::connect(paths, true)?;
    c.ensure_unlocked()?;
    Ok(c)
}

fn init(paths: &VaultPaths, profile: Argon2Profile) -> Result<(), CliError> {
    if paths.vault.exists() {
        let storage =
            SqliteStorage::open(&paths.vault).map_err(|e| CliError::general(e.to_string()))?;
        if Vault::open(storage, SystemClock).is_ok() {
            return Err(CliError::general(format!(
                "a vault already exists at {}",
                paths.vault.display()
            )));
        }
    }
    println!("Creating a vault at {}", paths.vault.display());
    println!(
        "Choose a password. It cannot be reset; the recovery phrase is the only other way in."
    );
    let pw = uio::read_secret_line("Password: ")?;
    if pw.len() < 12 {
        return Err(CliError::general("password must be at least 12 characters"));
    }
    if uio::is_tty() {
        let again = uio::read_secret_line("Repeat password: ")?;
        if again != pw {
            return Err(CliError::general("passwords do not match"));
        }
    }
    let storage =
        SqliteStorage::open(&paths.vault).map_err(|e| CliError::general(e.to_string()))?;
    let (v, kit) = Vault::create(storage, SystemClock, &pw, profile).map_err(map_vault_err)?;
    println!();
    println!("Vault {} created.", v.vault_id());
    println!();
    println!("RECOVERY PHRASE — write these 24 words down and keep them offline.");
    println!("They are shown once and never stored anywhere.");
    println!();
    for (i, w) in kit.words().iter().enumerate() {
        print!("{:>2}. {:<12}", i + 1, w);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();
    if uio::is_tty() && !uio::confirm("I have written the recovery phrase down.")? {
        println!("Please write it down now; you can view it only this once.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add(
    paths: &VaultPaths,
    name: String,
    kind: Option<SecretKind>,
    provider: Option<String>,
    upstreams: Vec<String>,
    tags: Vec<String>,
    notes: Option<String>,
    stdin: bool,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    // An OAuth client is four values; ask for each. (Piped with --stdin, the
    // JSON your OAuth tooling wrote is taken apart by the daemon instead.)
    if kind == Some(SecretKind::Oauth2Client) && !stdin {
        let ask = |prompt: &str| -> Result<String, CliError> {
            let v = uio::read_secret_line(prompt)?;
            Ok(std::str::from_utf8(v.expose())
                .map_err(|_| CliError::general("input must be UTF-8 text"))?
                .trim()
                .to_string())
        };
        let client_id = ask("Client ID: ")?;
        let client_secret = ask("Client secret (empty for a public client): ")?;
        let refresh_token = ask("Refresh token: ")?;
        let token_url = ask("Token URL (https://…/token): ")?;
        if client_id.is_empty() || refresh_token.is_empty() || token_url.is_empty() {
            return Err(CliError::general(
                "a client id, a refresh token and a token URL are all required",
            ));
        }
        let mut fields = serde_json::Map::new();
        fields.insert("client_id".into(), json!(client_id));
        fields.insert("token_url".into(), json!(token_url));
        if !client_secret.is_empty() {
            fields.insert("client_secret".into(), json!(client_secret));
        }
        let created = c.post(
            "/v1/secrets",
            json!({
                "name": name, "type": "oauth2_client", "value": refresh_token, "fields": fields,
                "provider": provider, "upstreams": upstreams, "tags": tags, "notes": notes,
            }),
        )?;
        let ups: Vec<&str> = created["upstreams"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        println!("Upstream locked to: {}", ups.join(", "));
        println!(
            "Saved {} ({}). Handles for it stand in for an access token; the daemon refreshes the real one.",
            created["name"].as_str().unwrap_or(""),
            created["id"].as_str().unwrap_or("")
        );
        return Ok(());
    }
    let value = if stdin {
        uio::read_secret_rest()?
    } else {
        uio::read_secret_line(&format!("Value for {name} (hidden): "))?
    };
    if value.is_empty() {
        return Err(CliError::general("empty value"));
    }
    let value_str = std::str::from_utf8(value.expose())
        .map_err(|_| CliError::general("value must be UTF-8 text; use import for binary"))?;
    // An AWS access key id on its own is half a credential: ask for the rest.
    // (Both halves can also be given at once: two lines, a ~/.aws/credentials
    // section or `aws sts` JSON; the daemon takes those apart.)
    let mut fields = serde_json::Map::new();
    let (mut kind, mut provider) = (kind, provider);
    let other_half;
    let value_str = if unseenkey_core::providers::is_aws_access_key_id(value_str.trim()) {
        other_half = uio::read_secret_line("AWS secret access key (hidden): ")?;
        if other_half.is_empty() {
            return Err(CliError::general(
                "an AWS access key id needs its secret access key as well",
            ));
        }
        fields.insert("access_key_id".into(), json!(value_str.trim()));
        kind = kind.or(Some(SecretKind::AwsCredentials));
        provider = provider.or_else(|| Some("aws".into()));
        std::str::from_utf8(other_half.expose())
            .map_err(|_| CliError::general("value must be UTF-8 text"))?
            .trim()
    } else {
        value_str
    };
    let body = json!({
        "name": name,
        "type": kind.map(|k| k.as_str()),
        "value": value_str,
        "fields": fields,
        "provider": provider,
        "upstreams": upstreams,
        "tags": tags,
        "notes": notes,
    });
    let created = c.post("/v1/secrets", body)?;
    if let Some(d) = created["detected"].as_object() {
        let note = d["note"].as_str().unwrap_or("");
        let suffix = if note.is_empty() {
            String::new()
        } else {
            format!(" ({note})")
        };
        println!("Detected: {}{suffix}", d["display"].as_str().unwrap_or("?"));
    }
    let ups: Vec<&str> = created["upstreams"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if ups.is_empty() {
        println!(
            "Warning: no upstream host locked. Add one with --upstream so the broker can use it."
        );
    } else {
        println!("Upstream locked to: {}", ups.join(", "));
    }
    println!(
        "Saved {} ({}).",
        created["name"].as_str().unwrap_or(""),
        created["id"].as_str().unwrap_or("")
    );
    Ok(())
}

fn ls(paths: &VaultPaths, json: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let list = c.get("/v1/secrets")?;
    let items = list.as_array().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return Ok(());
    }
    if items.is_empty() {
        println!("No secrets yet. Add one with `usk add <name>`.");
        return Ok(());
    }
    let (h_name, h_type, h_prov, h_up) = ("NAME", "TYPE", "PROVIDER", "UPSTREAMS");
    println!("{h_name:<28} {h_type:<18} {h_prov:<12} {h_up}");
    for m in items {
        let ups: Vec<&str> = m["upstreams"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        println!(
            "{:<28} {:<18} {:<12} {}",
            m["name"].as_str().unwrap_or(""),
            m["kind"].as_str().unwrap_or(""),
            m["provider"].as_str().unwrap_or("-"),
            if ups.is_empty() {
                "(none: not locked)".to_string()
            } else {
                ups.join(",")
            }
        );
    }
    Ok(())
}

fn show(paths: &VaultPaths, name: &str, json: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let m = c.get(&format!("/v1/secrets/{name}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&m).unwrap_or_default());
        return Ok(());
    }
    let list = |k: &str| -> String {
        let v: Vec<&str> = m[k]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if v.is_empty() {
            "-".into()
        } else {
            v.join(", ")
        }
    };
    println!("name:       {}", m["name"].as_str().unwrap_or(""));
    println!("id:         {}", m["secret_id"].as_str().unwrap_or(""));
    println!("type:       {}", m["kind"].as_str().unwrap_or(""));
    println!("provider:   {}", m["provider"].as_str().unwrap_or("-"));
    println!("upstreams:  {}", list("upstreams"));
    println!("tags:       {}", list("tags"));
    println!("notes:      {}", m["notes"].as_str().unwrap_or("-"));
    println!("versions:   {}", m["value_version"]);
    println!(
        "injection:  {}",
        if m["allow_injection"].as_bool().unwrap_or(false) {
            "allowed"
        } else {
            "off"
        }
    );
    println!("value:      [hidden] use `usk reveal {name} --yes` to print it once");
    Ok(())
}

fn reveal(
    paths: &VaultPaths,
    name: &str,
    yes: bool,
    reason: Option<String>,
) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::general(
            "reveal prints the secret to this terminal; add --yes to confirm",
        ));
    }
    let c = unlocked(paths)?;
    let r = c.post(
        &format!("/v1/secrets/{name}/reveal"),
        json!({ "confirm": true, "reason": reason }),
    )?;
    println!("{}", r["value"].as_str().unwrap_or(""));
    if let Some(fields) = r["fields"].as_object() {
        for (k, v) in fields {
            println!("{k}={}", v.as_str().unwrap_or(""));
        }
    }
    Ok(())
}

fn rm(paths: &VaultPaths, name: &str, yes: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    c.get(&format!("/v1/secrets/{name}"))?;
    if !yes && uio::is_tty() && !uio::confirm(&format!("Delete {name}?"))? {
        println!("Cancelled.");
        return Ok(());
    }
    c.delete(&format!("/v1/secrets/{name}"))?;
    println!("Deleted {name}.");
    Ok(())
}

fn import(paths: &VaultPaths, env_path: &Path, all: bool, dry_run: bool) -> Result<(), CliError> {
    let text = std::fs::read_to_string(env_path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", env_path.display())))?;
    let entries = parse_dotenv(&text);
    let candidates: Vec<_> = entries
        .into_iter()
        .filter(|e| all || e.looks_secret)
        .collect();
    if candidates.is_empty() {
        println!(
            "Nothing that looks like a secret in {}.",
            env_path.display()
        );
        return Ok(());
    }
    let (h_line, h_key, h_det) = ("LINE", "KEY", "DETECTED");
    println!("{h_line:<6} {h_key:<32} {h_det}");
    for e in &candidates {
        println!(
            "{:<6} {:<32} {}",
            e.line,
            e.key,
            e.detection.map(|d| d.display).unwrap_or("(by name)")
        );
    }
    if dry_run {
        println!("Dry run: nothing written.");
        return Ok(());
    }
    let c = unlocked(paths)?;
    let mut added = 0;
    for e in candidates {
        let name = e.key.to_lowercase().replace('_', "-");
        let value = match std::str::from_utf8(e.value.expose()) {
            Ok(s) => s.to_string(),
            Err(_) => {
                println!("skipped {name}: not UTF-8");
                continue;
            }
        };
        let body = json!({
            "name": name,
            "type": e.detection.map(|d| d.kind.as_str()).unwrap_or("note"),
            "value": value,
            "tags": ["imported"],
            "notes": format!("imported from {} ({})", env_path.display(), e.key),
        });
        match c.post("/v1/secrets", body) {
            Ok(_) => {
                added += 1;
                println!("added {name}");
            }
            Err(err) if err.kind == "name_exists" => println!("skipped {name}: already exists"),
            Err(err) => return Err(err),
        }
    }
    println!(
        "Imported {added} secret(s). Next: replace the values in {} with handles (M1.4).",
        env_path.display()
    );
    Ok(())
}

fn recover(paths: &VaultPaths, profile: Argon2Profile) -> Result<(), CliError> {
    // The daemon must not hold an unlocked copy while the header changes.
    if let Some(c) = Client::try_connect(paths) {
        c.post("/v1/lock", json!({}))?;
    }
    let storage =
        SqliteStorage::open(&paths.vault).map_err(|e| CliError::general(e.to_string()))?;
    let mut v = Vault::open(storage, SystemClock).map_err(map_vault_err)?;
    let phrase = uio::read_secret_line("Recovery phrase (24 words): ")?;
    let phrase_str = std::str::from_utf8(phrase.expose())
        .map_err(|_| CliError::general("invalid recovery phrase"))?;
    v.unlock_with_recovery(phrase_str).map_err(map_vault_err)?;
    let pw = uio::read_secret_line("New password: ")?;
    if pw.len() < 12 {
        return Err(CliError::general("password must be at least 12 characters"));
    }
    v.change_password(&pw, profile).map_err(map_vault_err)?;
    println!("Password changed. The recovery phrase still works; keep it safe.");
    Ok(())
}

fn status(paths: &VaultPaths, json: bool) -> Result<(), CliError> {
    let exists = paths.vault.exists()
        && SqliteStorage::open(&paths.vault)
            .ok()
            .and_then(|s| Vault::open(s, SystemClock).ok())
            .is_some();
    let daemon_status = Client::try_connect(paths).and_then(|c| c.get("/v1/status").ok());
    if json {
        println!(
            "{}",
            json!({
                "vault": paths.vault.display().to_string(),
                "exists": exists,
                "version": env!("CARGO_PKG_VERSION"),
                "daemon": daemon_status,
            })
        );
        return Ok(());
    }
    println!("vault:   {}", paths.vault.display());
    println!(
        "exists:  {}",
        if exists { "yes" } else { "no (run `usk init`)" }
    );
    println!("version: {}", env!("CARGO_PKG_VERSION"));
    match daemon_status {
        Some(s) => println!(
            "daemon:  running, {} (idle lock {} min)",
            if s["locked"].as_bool().unwrap_or(true) {
                "locked"
            } else {
                "unlocked"
            },
            s["idle_lock_minutes"]
        ),
        None => println!("daemon:  not running (starts on first use)"),
    }
    Ok(())
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Render a policy as plain English.
    Explain {
        /// A preset policy such as `stripe:payments`.
        #[arg(long, conflicts_with = "file")]
        preset: Option<String>,
        /// A policy file (TOML or JSON).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Validate a policy file.
    Check {
        /// A policy file (TOML or JSON).
        file: PathBuf,
    },
}

fn load_policy_file(file: &Path) -> Result<unseenkey_core::policy::Policy, CliError> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", file.display())))?;
    let is_json =
        file.extension().is_some_and(|e| e == "json") || text.trim_start().starts_with('{');
    let parsed = if is_json {
        unseenkey_core::policy::Policy::from_json(&text)
    } else {
        unseenkey_core::policy::Policy::from_toml(&text)
    };
    parsed.map_err(|e| CliError::with_code(2, "invalid_policy", e.to_string()))
}

#[derive(Subcommand)]
enum HandleAction {
    /// Create a handle for a secret. The handle string is shown once.
    Create {
        /// Secret name.
        secret: String,
        /// Label, e.g. "cursor on laptop" (default: the secret name).
        #[arg(long)]
        label: Option<String>,
        /// Preset policy id (e.g. `chat`, `payments`) or `provider:policy`.
        #[arg(long, conflicts_with = "policy_file")]
        policy: Option<String>,
        /// Policy file (TOML or JSON).
        #[arg(long)]
        policy_file: Option<PathBuf>,
        /// Expire after this many days.
        #[arg(long)]
        expires_days: Option<u32>,
        /// Shape the handle like the provider's own keys, for tools that
        /// check the key format. It is still only a handle.
        #[arg(long)]
        camouflage: bool,
        /// Hard cap on requests: `1000/day` or `60/min` (repeatable).
        #[arg(long, value_name = "N/day|N/min")]
        cap: Vec<String>,
        /// A canary: a handle that never works. Plant it where only an
        /// intruder would find it; any use locks the vault (see --on-anomaly).
        #[arg(long)]
        canary: bool,
        /// What unusual activity does to the handle (default: throttle; lock
        /// for a canary).
        #[arg(long, value_enum)]
        on_anomaly: Option<OnAnomaly>,
    },
    /// List handles.
    Ls,
    /// Put a handle back to normal after unusual activity (ends a throttle,
    /// approval mode or pause).
    Resume {
        /// Label or id.
        r#ref: String,
    },
    /// Show one handle and its policy in plain English.
    Show {
        /// Label or id.
        r#ref: String,
    },
    /// Revoke a handle immediately.
    Revoke {
        /// Label or id.
        r#ref: String,
    },
    /// Forget approvals remembered with "allow always" (all, or one rule).
    Forget {
        /// Label or id.
        r#ref: String,
        /// Only this rule, e.g. "POST /v1/refunds".
        #[arg(long)]
        rule: Option<String>,
    },
    /// Replace a handle's policy.
    Policy {
        /// Label or id.
        r#ref: String,
        /// Preset policy id or `provider:policy`.
        #[arg(long, conflicts_with = "file")]
        preset: Option<String>,
        /// Policy file (TOML or JSON).
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LogAction {
    /// Verify the audit log's hash chain.
    Verify,
}

#[derive(Clone, Copy, ValueEnum)]
enum Shell {
    /// `export VAR=value` (bash, zsh)
    Sh,
    /// `$env:VAR = "value"`
    Powershell,
    /// `set VAR=value`
    Cmd,
    /// `VAR=value` lines for a .env file
    Dotenv,
}

/// Turn `chat` into `openai:chat` using the secret's provider; pass through `a:b`.
fn qualify_policy(client: &Client, secret: &str, spec: &str) -> Result<String, CliError> {
    if spec.contains(':') {
        return Ok(spec.to_string());
    }
    let m = client.get(&format!("/v1/secrets/{secret}"))?;
    let provider = m["provider"].as_str().ok_or_else(|| {
        CliError::general(format!(
            "{secret} has no provider; pass --policy provider:policy or --policy-file"
        ))
    })?;
    Ok(format!("{provider}:{spec}"))
}

/// `--on-anomaly` choices, in the daemon's spelling.
#[derive(Clone, Copy, ValueEnum)]
enum OnAnomaly {
    /// Record it and notify; nothing else changes.
    Alert,
    /// A few requests a minute for an hour.
    Throttle,
    /// Every request needs your approval until you resume the handle.
    Approve,
    /// Refuse everything until you resume the handle.
    Pause,
    /// Lock the whole vault.
    Lock,
}

impl OnAnomaly {
    fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Throttle => "throttle",
            Self::Approve => "approve",
            Self::Pause => "pause",
            Self::Lock => "lock",
        }
    }
}

/// Incident settings from the command line.
struct Incidents {
    cap: Vec<String>,
    canary: bool,
    on_anomaly: Option<OnAnomaly>,
}

impl Incidents {
    /// Add the settings to a `POST /v1/handles` body.
    fn apply(&self, body: &mut Value) -> Result<(), CliError> {
        for cap in &self.cap {
            let (n, unit) = cap.split_once('/').ok_or_else(|| {
                CliError::general(format!("--cap {cap:?}: use N/day or N/min, e.g. 1000/day"))
            })?;
            let n: u32 = n
                .trim()
                .replace(['_', ','], "")
                .parse()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    CliError::general(format!("--cap {cap:?}: the number must be 1 or more"))
                })?;
            let field = match unit.trim().to_ascii_lowercase().as_str() {
                "day" | "d" | "daily" => "cap_per_day",
                "min" | "minute" | "m" => "cap_per_minute",
                _ => {
                    return Err(CliError::general(format!(
                        "--cap {cap:?}: the unit must be day or min"
                    )))
                }
            };
            body[field] = json!(n);
        }
        if self.canary {
            body["canary"] = json!(true);
        }
        if let Some(r) = self.on_anomaly {
            body["on_anomaly"] = json!(r.as_str());
        }
        Ok(())
    }
}

/// One word for a handle's standing, for lists.
fn handle_state(h: &Value) -> &'static str {
    if h["revoked_at"].is_i64() {
        "revoked"
    } else if h["active"].as_bool() == Some(false) {
        "expired"
    } else if h["canary"].as_bool() == Some(true) {
        "canary"
    } else {
        match h["status"]["state"].as_str() {
            Some("throttled") => "throttled",
            Some("approval_required") => "approval",
            Some("paused") => "paused",
            _ => "active",
        }
    }
}

fn print_handle_created(created: &Value, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(created).unwrap_or_default()
        );
        return;
    }
    if created["canary"].as_bool() == Some(true) {
        println!(
            "Canary created for {} (label: {}).",
            created["secret"].as_str().unwrap_or(""),
            created["label"].as_str().unwrap_or("")
        );
        println!();
        println!("  {}", created["handle"].as_str().unwrap_or(""));
        println!();
        println!("This is shown once. It never works: put it where only an intruder would find it");
        println!("(a .env.example, an old repo, a notes page). The moment anyone uses it the");
        println!(
            "response is \"{}\" and the event is in `usk log --kind canary_tripped`.",
            created["on_anomaly"].as_str().unwrap_or("lock")
        );
        if let Some(env) = created["env"].as_object().filter(|e| !e.is_empty()) {
            println!();
            println!("As the SDK would expect it:");
            for (k, v) in env {
                println!("  {k}={}", v.as_str().unwrap_or(""));
            }
        }
        return;
    }
    println!(
        "Handle created for {} (label: {}).",
        created["secret"].as_str().unwrap_or(""),
        created["label"].as_str().unwrap_or("")
    );
    println!();
    println!("  {}", created["handle"].as_str().unwrap_or(""));
    println!();
    println!("This is shown once. It is safe to paste into tools: it only works through this");
    println!(
        "computer's broker, only for {}, and only within this policy:",
        created["policy"]["upstreams"]
            .as_array()
            .map(|a| a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default()
    );
    for line in created["policy_explanation"].as_str().unwrap_or("").lines() {
        println!("  {line}");
    }
    if let Some(env) = created["env"].as_object().filter(|e| !e.is_empty()) {
        println!();
        println!("Environment for the provider's SDK:");
        for (k, v) in env {
            println!("  {k}={}", v.as_str().unwrap_or(""));
        }
    } else if let Some(b) = created["base_url"].as_str() {
        println!();
        println!("Base URL through the broker: {b}");
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_create(
    paths: &VaultPaths,
    secret: &str,
    label: Option<String>,
    policy: Option<String>,
    policy_file: Option<PathBuf>,
    expires_days: Option<u32>,
    camouflage: bool,
    incidents: Incidents,
    json: bool,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let mut body = json!({ "secret": secret, "label": label, "expires_in_days": expires_days, "camouflage": camouflage });
    if let Some(spec) = policy {
        body["preset_policy"] = json!(qualify_policy(&c, secret, &spec)?);
    } else if let Some(f) = policy_file {
        let p = load_policy_file(&f)?;
        body["policy"] = serde_json::from_str::<Value>(&p.to_json()).unwrap_or(Value::Null);
    }
    incidents.apply(&mut body)?;
    let created = c.post("/v1/handles", body)?;
    print_handle_created(&created, json);
    Ok(())
}

fn handle_resume(paths: &VaultPaths, r#ref: &str) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let h = c.post(&format!("/v1/handles/{ref}/resume"), json!({}))?;
    println!(
        "{} is back to normal ({}).",
        h["label"].as_str().unwrap_or(r#ref),
        h["policy_explanation"]
            .as_str()
            .and_then(|e| e.lines().next())
            .unwrap_or("")
            .trim_end_matches('.')
    );
    Ok(())
}

fn handle_ls(paths: &VaultPaths, json: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let list = c.get("/v1/handles")?;
    let items = list.as_array().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return Ok(());
    }
    if items.is_empty() {
        println!(
            "No handles yet. Create one with `usk handle create <secret>` or `usk env <secret>`."
        );
        return Ok(());
    }
    let (h_label, h_secret, h_state, h_uses, h_id) = ("LABEL", "SECRET", "STATE", "USES", "ID");
    println!("{h_label:<24} {h_secret:<20} {h_state:<9} {h_uses:>6}  {h_id}");
    for h in items {
        let state = handle_state(&h);
        println!(
            "{:<24} {:<20} {:<9} {:>6}  {}",
            h["label"].as_str().unwrap_or(""),
            h["secret"].as_str().unwrap_or(""),
            state,
            h["use_count"].as_u64().unwrap_or(0),
            h["id"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn handle_show(paths: &VaultPaths, r#ref: &str, json: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let h = c.get(&format!("/v1/handles/{ref}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&h).unwrap_or_default());
        return Ok(());
    }
    println!("label:      {}", h["label"].as_str().unwrap_or(""));
    println!("id:         {}", h["id"].as_str().unwrap_or(""));
    println!("secret:     {}", h["secret"].as_str().unwrap_or(""));
    println!("active:     {}", h["active"]);
    println!("uses:       {}", h["use_count"]);
    println!("created_at: {}", h["created_at"]);
    println!("expires_at: {}", h["expires_at"]);
    println!("revoked_at: {}", h["revoked_at"]);
    if h["canary"].as_bool() == Some(true) {
        println!("canary:     yes (never works; any use is an incident)");
    }
    println!(
        "on anomaly: {}",
        h["on_anomaly"].as_str().unwrap_or("throttle")
    );
    let state = h["status"]["state"].as_str().unwrap_or("normal");
    if state != "normal" {
        println!("status:     {state} (back to normal with `usk handle resume`)");
    }
    if let Some(a) = h["last_anomaly"].as_object() {
        println!(
            "incident:   {} → {}",
            a.get("detail").and_then(Value::as_str).unwrap_or(""),
            a.get("response").and_then(Value::as_str).unwrap_or("")
        );
    }
    println!("policy:");
    for line in h["policy_explanation"].as_str().unwrap_or("").lines() {
        println!("  {line}");
    }
    if let Some(rules) = h["remembered"].as_array().filter(|a| !a.is_empty()) {
        println!("remembered approvals (clear with `usk handle forget`):");
        for r in rules {
            println!("  {}", r.as_str().unwrap_or(""));
        }
    }
    Ok(())
}

fn handle_forget(paths: &VaultPaths, r#ref: &str, rule: Option<String>) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let r = c.post(
        &format!("/v1/handles/{ref}/forget"),
        json!({ "rule": rule }),
    )?;
    let n = r["removed"].as_u64().unwrap_or(0);
    match (n, rule) {
        (0, _) => println!("Nothing was remembered for {ref}."),
        (_, Some(rule)) => println!("Forgot \"{rule}\" for {ref}; it will ask again."),
        (n, None) => println!("Forgot {n} remembered approval(s) for {ref}; it will ask again."),
    }
    Ok(())
}

fn handle_revoke(paths: &VaultPaths, r#ref: &str) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    c.delete(&format!("/v1/handles/{ref}"))?;
    println!("Revoked {ref}. Requests with it now fail immediately.");
    Ok(())
}

fn handle_policy(
    paths: &VaultPaths,
    r#ref: &str,
    preset: Option<String>,
    file: Option<PathBuf>,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let h = c.get(&format!("/v1/handles/{ref}"))?;
    let secret = h["secret"].as_str().unwrap_or("").to_string();
    let body = match (preset, file) {
        (Some(spec), None) => json!({ "preset_policy": qualify_policy(&c, &secret, &spec)? }),
        (None, Some(f)) => {
            let p = load_policy_file(&f)?;
            json!({ "policy": serde_json::from_str::<Value>(&p.to_json()).unwrap_or(Value::Null) })
        }
        _ => return Err(CliError::general("pass --preset <policy> or --file <path>")),
    };
    let updated = c.patch(&format!("/v1/handles/{ref}"), body)?;
    println!(
        "Policy updated for {}:",
        updated["label"].as_str().unwrap_or("")
    );
    for line in updated["policy_explanation"].as_str().unwrap_or("").lines() {
        println!("  {line}");
    }
    Ok(())
}

fn env_cmd(
    paths: &VaultPaths,
    secret: &str,
    policy: Option<String>,
    label: Option<String>,
    shell: Option<Shell>,
    camouflage: bool,
    incidents: Incidents,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let label = label.unwrap_or_else(|| format!("{secret} env"));
    let mut body = json!({ "secret": secret, "label": label, "camouflage": camouflage });
    if let Some(spec) = policy {
        body["preset_policy"] = json!(qualify_policy(&c, secret, &spec)?);
    }
    incidents.apply(&mut body)?;
    let created = c.post("/v1/handles", body)?;
    let env = created["env"].as_object().cloned().unwrap_or_default();
    if env.is_empty() {
        return Err(CliError::general(format!(
            "{secret} has no provider preset; use `usk handle create {secret}` and the generic route instead"
        )));
    }
    let shell = shell.unwrap_or(if cfg!(windows) {
        Shell::Powershell
    } else {
        Shell::Sh
    });
    eprintln!("# Handle \"{label}\" created. These variables point the SDK at the local broker;");
    eprintln!("# the real key never leaves the vault. Revoke with: usk handle revoke \"{label}\"");
    for (k, v) in env {
        let v = v.as_str().unwrap_or("");
        match shell {
            Shell::Sh => println!("export {k}={v}"),
            Shell::Powershell => println!("$env:{k} = \"{v}\""),
            Shell::Cmd => println!("set {k}={v}"),
            Shell::Dotenv => println!("{k}={v}"),
        }
    }
    Ok(())
}

fn log_list(
    paths: &VaultPaths,
    kind: Option<String>,
    since: u64,
    limit: usize,
    json: bool,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let mut url = format!("/v1/audit?since={since}&limit={limit}");
    if let Some(k) = &kind {
        url.push_str(&format!("&kind={k}"));
    }
    let events = c.get(&url)?;
    let items = events.as_array().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return Ok(());
    }
    if items.is_empty() {
        println!("No events.");
        return Ok(());
    }
    for e in items {
        let ts = e["ts"].as_i64().unwrap_or(0);
        let kind = e["kind"].as_str().unwrap_or("");
        let b = &e["body"];
        let detail = match kind {
            "use" => format!(
                "{} {} {} -> {} ({} via {})",
                b["method"].as_str().unwrap_or(""),
                b["host"].as_str().unwrap_or(""),
                b["path"].as_str().unwrap_or(""),
                b["status"],
                b["secret"].as_str().unwrap_or(""),
                b["label"].as_str().unwrap_or("")
            ),
            "deny" => format!(
                "{} {} {} refused: {} ({})",
                b["method"].as_str().unwrap_or(""),
                b["host"].as_str().unwrap_or(""),
                b["path"].as_str().unwrap_or(""),
                b["reason"].as_str().unwrap_or(""),
                b["label"].as_str().unwrap_or("")
            ),
            "egress_blocked" => format!(
                "request via {} carried secret(s) {} -> blocked",
                b["label"].as_str().unwrap_or(""),
                b["leaked"]
            ),
            _ => b.to_string(),
        };
        println!(
            "{:>6}  {}  {:<16} {}",
            e["seq"],
            format_ts(ts),
            kind,
            detail
        );
    }
    Ok(())
}

fn format_ts(ms: i64) -> String {
    jiff_free_format(ms)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC without pulling a date library into the CLI.
fn jiff_free_format(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn log_verify(paths: &VaultPaths, json: bool) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    let r = c.get("/v1/audit/verify")?;
    if json {
        println!("{r}");
    } else if r["ok"].as_bool() == Some(true) {
        println!("Audit log intact: {} events, chain verified.", r["rows"]);
    } else {
        println!(
            "AUDIT LOG TAMPERED: first broken sequence {} (contiguous: {})",
            r["first_broken"], r["contiguous"]
        );
    }
    if r["ok"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err(CliError::with_code(
            4,
            "audit_tampered",
            "audit chain verification failed",
        ))
    }
}

#[derive(Subcommand)]
enum McpAction {
    /// Register a client and write its MCP config (restart the client afterwards).
    Install {
        /// claude-code, claude-desktop, cursor, windsurf, all, or a custom name.
        client: String,
        /// Write configs under this directory instead of the real home (tests).
        #[arg(long, hide = true)]
        home: Option<PathBuf>,
    },
    /// Forget a client (its token stops working).
    Remove {
        /// Client name.
        client: String,
    },
    /// List registered clients.
    Clients,
}

fn approvals_list(paths: &VaultPaths, json_out: bool) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    let list = c.get("/v1/approvals")?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&list).unwrap_or_default()
        );
        return Ok(());
    }
    let items = list.as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("Nothing is waiting for approval.");
        return Ok(());
    }
    for p in items {
        let what = if p["kind"] == "access" {
            format!("access request: {}", p["scope"].as_str().unwrap_or(""))
        } else {
            format!(
                "{} {}{} ({})",
                p["method"].as_str().unwrap_or(""),
                p["host"].as_str().unwrap_or(""),
                p["path"].as_str().unwrap_or(""),
                p["scope"].as_str().unwrap_or("")
            )
        };
        println!(
            "{}  {} wants to use {} via \"{}\": {}  [{}s left]\n    usk approve {}   |   usk deny {}",
            p["id"].as_str().unwrap_or(""),
            p["caller"].as_str().unwrap_or(""),
            p["secret"].as_str().unwrap_or(""),
            p["label"].as_str().unwrap_or(""),
            what,
            p["seconds_left"],
            p["id"].as_str().unwrap_or(""),
            p["id"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn approvals_decide(
    paths: &VaultPaths,
    id: &str,
    allow: bool,
    remember: bool,
) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    let r = c.post(
        &format!("/v1/approvals/{id}"),
        json!({ "decision": if allow { "allow" } else { "deny" }, "remember": remember }),
    )?;
    println!(
        "{} {} via \"{}\"{}",
        if allow { "Approved" } else { "Denied" },
        r["secret"].as_str().unwrap_or(""),
        r["label"].as_str().unwrap_or(""),
        if allow && remember {
            " (remembered for this rule; clear with `usk handle forget`)"
        } else {
            ""
        }
    );
    Ok(())
}

#[derive(Subcommand)]
enum GuardAction {
    /// Report which lines look like secrets and which can become handles.
    Scan {
        /// Path to the .env file.
        #[arg(default_value = ".env")]
        path: PathBuf,
    },
    /// Move secrets into the vault and rewrite the file with handles.
    Fix {
        /// Path to the .env file.
        #[arg(default_value = ".env")]
        path: PathBuf,
        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Set flags and metadata on a secret.
    Set {
        /// Secret name.
        name: String,
        /// Allow `usk run` to inject this secret into a process environment.
        #[arg(long)]
        allow_injection: Option<bool>,
        /// Exclude this value from response scrubbing (for false positives).
        #[arg(long)]
        no_scrub: Option<bool>,
        /// Replace the notes.
        #[arg(long)]
        notes: Option<String>,
        /// Replace the tags; repeatable.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Replace the allowed hosts; repeatable.
        #[arg(long = "upstream")]
        upstreams: Vec<String>,
    },
}

fn secret_set(
    paths: &VaultPaths,
    name: &str,
    allow_injection: Option<bool>,
    no_scrub: Option<bool>,
    notes: Option<String>,
    tags: Vec<String>,
    upstreams: Vec<String>,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let mut body = serde_json::Map::new();
    if let Some(a) = allow_injection {
        body.insert("allow_injection".into(), json!(a));
    }
    if let Some(n) = no_scrub {
        body.insert("no_scrub".into(), json!(n));
    }
    if let Some(n) = notes {
        body.insert("notes".into(), json!(n));
    }
    if !tags.is_empty() {
        body.insert("tags".into(), json!(tags));
    }
    if !upstreams.is_empty() {
        body.insert("upstreams".into(), json!(upstreams));
    }
    if body.is_empty() {
        return Err(CliError::general(
            "nothing to change; pass --allow-injection, --no-scrub, --notes, --tag or --upstream",
        ));
    }
    let m = c.patch(&format!("/v1/secrets/{name}"), Value::Object(body))?;
    println!(
        "{}: injection {}, scrubbing {}, upstreams {}",
        m["name"].as_str().unwrap_or(name),
        if m["allow_injection"].as_bool().unwrap_or(false) {
            "allowed"
        } else {
            "off"
        },
        if m["no_scrub"].as_bool().unwrap_or(false) {
            "off"
        } else {
            "on"
        },
        m["upstreams"]
            .as_array()
            .map(|a| a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default()
    );
    if allow_injection == Some(true) {
        println!(
            "Note: programs started with `usk run --with VAR={name}` will see the real value."
        );
    }
    Ok(())
}

fn presets(json: bool) -> Result<(), CliError> {
    let all: Vec<_> = unseenkey_core::presets::all().collect();
    if json {
        let v: Vec<Value> = all
            .iter()
            .map(|p| {
                json!({
                    "id": p.id, "display": p.display, "upstreams": p.upstreams, "docs": p.docs,
                    "policies": p.policies.iter().map(|pp| json!({"id": pp.id, "display": pp.display, "recommended": pp.recommended})).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(());
    }
    for p in all {
        println!(
            "{:<12} {:<16} {}",
            p.id,
            p.display,
            if p.upstreams.is_empty() {
                "(any locked host)".to_string()
            } else {
                p.upstreams.join(", ")
            }
        );
        for pp in &p.policies {
            println!(
                "    {}:{:<12} {}{}",
                p.id,
                pp.id,
                pp.display,
                if pp.recommended {
                    "  (recommended)"
                } else {
                    ""
                }
            );
        }
    }
    println!("\nExplain one with: usk policy explain --preset <provider>:<policy>");
    Ok(())
}

fn policy_explain(
    preset: Option<String>,
    file: Option<PathBuf>,
    json: bool,
) -> Result<(), CliError> {
    let policy = match (preset, file) {
        (Some(spec), None) => unseenkey_core::presets::policy_ref(&spec)
            .map_err(|e| CliError::general(e.to_string()))?,
        (None, Some(f)) => load_policy_file(&f)?,
        _ => {
            return Err(CliError::general(
                "pass --preset provider:policy or --file path",
            ))
        }
    };
    let text = unseenkey_core::policy::explain(&policy);
    if json {
        println!(
            "{}",
            json!({ "explanation": text, "policy": serde_json::from_str::<Value>(&policy.to_json()).unwrap_or(Value::Null) })
        );
    } else {
        println!("{text}");
    }
    Ok(())
}

fn policy_check(file: &Path) -> Result<(), CliError> {
    let policy = load_policy_file(file)?;
    println!("ok: {} valid", file.display());
    println!("{}", unseenkey_core::policy::explain(&policy));
    Ok(())
}

fn doctor(paths: &VaultPaths) -> Result<(), CliError> {
    let mut problems = 0;
    let mut check = |ok: bool, label: &str, hint: &str| {
        if ok {
            println!("ok    {label}");
        } else {
            problems += 1;
            println!("FAIL  {label}\n      {hint}");
        }
    };
    check(
        paths.vault.exists(),
        &format!("vault file {}", paths.vault.display()),
        "run `usk init`",
    );
    let cfg = unseenkey_daemon::config::load(&paths.config);
    check(
        cfg.is_ok(),
        &format!("config {}", paths.config.display()),
        &cfg.err().map(|e| e.to_string()).unwrap_or_default(),
    );
    let daemon = Client::try_connect(paths);
    let running = daemon.is_some();
    check(
        running || !paths.addr.exists(),
        "daemon runtime files",
        "stale daemon.addr/daemon.token found; delete them or run `usk daemon stop`",
    );
    if let Some(c) = &daemon {
        let s = c.get("/v1/status").unwrap_or(Value::Null);
        let ver = s["version"].as_str().unwrap_or("?");
        check(
            ver == env!("CARGO_PKG_VERSION"),
            &format!(
                "daemon version {ver} matches CLI {}",
                env!("CARGO_PKG_VERSION")
            ),
            "run `usk daemon stop`; it restarts with the new version on next use",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&paths.token)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            check(
                mode == 0o600,
                &format!("token file permissions {mode:o}"),
                "chmod 600 daemon.token",
            );
        }
    } else {
        println!("info  daemon not running (starts on first use)");
    }
    if std::env::var_os("USK_VAULT").is_some() {
        println!(
            "info  USK_VAULT is set; commands use {}",
            paths.vault.display()
        );
    }
    if problems == 0 {
        println!("All checks passed.");
        Ok(())
    } else {
        Err(CliError::general(format!("{problems} problem(s) found")))
    }
}
