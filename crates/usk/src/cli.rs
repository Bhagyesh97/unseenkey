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
        /// Read the value from a file, such as a Google service account's JSON key.
        #[arg(long, conflicts_with = "stdin")]
        file: Option<std::path::PathBuf>,
        /// Scope a service account's or OAuth client's tokens get; repeatable.
        /// Short names work: `webmasters.readonly`.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Do not send the one read-only request that checks the key works.
        #[arg(long)]
        no_test: bool,
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
    /// Change the password. Needs the current one.
    Passwd {
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
    /// How careful the access Unseenkey hands out by itself is: show it, or
    /// set `relaxed`, `balanced` (default) or `strict`.
    Care {
        /// The level to set.
        level: Option<String>,
    },
    /// Group secrets by the code folder that uses them; agents started in a
    /// project's folder see only its secrets.
    Project {
        #[command(subcommand)]
        action: crate::project::ProjectAction,
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
        /// Start at this sequence number, instead of showing the newest events.
        #[arg(long)]
        since: Option<u64>,
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
    /// Restart the daemon with this version. The vault locks; requests under way get a few seconds.
    Restart,
    /// Show whether the daemon is running.
    Status,
}

/// Stop the daemon and wait until it is really gone: a command run right after
/// must not find the old one still answering.
fn stop_daemon(paths: &VaultPaths) -> Result<(), CliError> {
    match Client::try_connect(paths) {
        Some(c) => {
            // The daemon answers first and exits ~200 ms later, so a dropped
            // connection is fine.
            let posted = c.post("/v1/shutdown", json!({}));
            let gone = daemon::wait_until(std::time::Duration::from_secs(12), || {
                (Client::try_connect(paths).is_none() && !paths.addr.exists()).then_some(())
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
    // Providers the owner added as `<vault dir>/presets/<id>.toml`.
    let (_, problems) = unseenkey_core::presets::load_user_dir(&paths.presets);
    for p in problems {
        eprintln!("warning: user preset skipped: {p}");
    }
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
            file,
            scopes,
            no_test,
        } => add(
            &paths,
            name,
            r#type,
            provider,
            upstreams,
            tags,
            notes,
            stdin,
            file,
            scopes,
            !no_test,
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
        Command::Passwd { profile: p } => passwd(&paths, profile(p)),
        Command::Status => status(&paths, cli.json),
        Command::Doctor => doctor(&paths),
        Command::Presets => presets(cli.json),
        Command::Run { with, command } => crate::run::run(&paths, with, command),
        Command::Approvals => approvals_list(&paths, cli.json),
        Command::Approve { id, remember } => approvals_decide(&paths, &id, true, remember),
        Command::Deny { id } => approvals_decide(&paths, &id, false, false),
        Command::Mcp { client, action } => match (client, action) {
            (Some(c), None) => crate::mcp::bridge(&paths, &c),
            (
                _,
                Some(McpAction::Install {
                    client,
                    home,
                    new_vault,
                }),
            ) => crate::mcp::install(&paths, client.as_deref(), home.as_deref(), new_vault),
            (_, Some(McpAction::Remove { client })) => crate::mcp::remove(&paths, &client),
            (_, Some(McpAction::Clients)) => crate::mcp::clients(&paths, cli.json),
            (None, None) => Err(CliError::general(
                "usage: usk mcp install [claude-code|claude-desktop|cursor|windsurf|all], usk mcp clients, usk mcp remove <client>, or usk mcp --client <name> (stdio bridge)",
            )),
        },
        Command::Project { action } => crate::project::run(&paths, action, cli.json),
        Command::Care { level } => care(&paths, level.as_deref()),
        Command::Guard { action } => match action {
            GuardAction::Scan { path } => crate::guard::scan(&path, cli.json).map(|_| ()),
            GuardAction::Fix {
                path,
                dry_run,
                project,
            } => match project {
                None => crate::guard::fix(&paths, &path, dry_run),
                Some(p) => {
                    let c = Client::connect(&paths, true)?;
                    c.ensure_unlocked()?;
                    let id = crate::project::project_id(&c, &p)?;
                    crate::guard::fix_for(&paths, &path, dry_run, Some(&id))
                }
            },
        },
        Command::Secret { action } => match action {
            SecretAction::Replace { name, stdin } => secret_replace(&paths, &name, stdin),
            SecretAction::Test { name } => secret_test(&paths, &name, cli.json),
            SecretAction::Set {
                name,
                allow_injection,
                no_scrub,
                notes,
                tags,
                upstreams,
                provider,
                scopes,
                username,
            } => secret_set(
                &paths,
                &name,
                allow_injection,
                no_scrub,
                notes,
                tags,
                upstreams,
                provider,
                scopes,
                username,
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
                project,
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
                    project,
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
                project: None,
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
                crate::client::skip_version_warning();
                stop_daemon(&paths)
            }
            DaemonAction::Restart => {
                crate::client::skip_version_warning();
                let this = env!("CARGO_PKG_VERSION");
                if let Some(c) = Client::try_connect(&paths) {
                    let status = c.get("/v1/status")?;
                    let running = status["version"].as_str().unwrap_or("");
                    if crate::client::daemon_is_newer(running, this) {
                        return Err(CliError::general(format!(
                            "the running service is version {running}, newer than this usk ({this}). Restarting from here would replace it with the older version and its older bugs. Use the newer usk instead."
                        )));
                    }
                }
                stop_daemon(&paths)?;
                let c = Client::connect(&paths, true)?;
                let status = c.get("/v1/status")?;
                let running = status["version"].as_str().unwrap_or("?");
                if running == this {
                    println!("Daemon restarted (version {running}).");
                } else {
                    println!("The service running now is version {running}, not {this}: something else started it. Close what uses an old copy of usk, or run `usk mcp install` to update its config.");
                }
                if uio::is_tty() {
                    c.ensure_unlocked()?;
                    println!("Unlocked.");
                } else {
                    println!("The vault is locked; unlock it with `usk unlock`.");
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
    make_vault(paths, profile).map(|_| ())
}

/// Make a vault with the default settings, for a command that sets up the
/// rest as well, and give back the password so it need not ask again.
pub fn create_vault(paths: &VaultPaths) -> Result<unseenkey_core::crypto::SecretBytes, CliError> {
    make_vault(paths, Argon2Profile::DESKTOP)
}

/// `usk add <name>`, with everything left to its prompts and detection.
pub fn add_first_key(paths: &VaultPaths, name: String) -> Result<(), CliError> {
    add(
        paths,
        name,
        None,
        None,
        Vec::new(),
        Vec::new(),
        None,
        false,
        None,
        Vec::new(),
        true,
    )
}

fn make_vault(
    paths: &VaultPaths,
    profile: Argon2Profile,
) -> Result<unseenkey_core::crypto::SecretBytes, CliError> {
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
    Ok(pw)
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
    file: Option<std::path::PathBuf>,
    scopes: Vec<String>,
    test: bool,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    // An OAuth client is four values; ask for each. (Piped with --stdin, the
    // JSON your OAuth tooling wrote is taken apart by the daemon instead.)
    if kind == Some(SecretKind::Oauth2Client) && !stdin && file.is_none() {
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
        // A bare scope is short for a Google URL only when this is Google.
        let scope = if token_url.contains("googleapis.com") || token_url.contains("google.com") {
            unseenkey_core::providers::google_scopes(&scopes)
        } else {
            unseenkey_core::providers::plain_scopes(&scopes)
        };
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
        if !scope.is_empty() {
            fields.insert("scope".into(), json!(scope));
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
    // A key in two parts: ask for each by the provider's own words.
    let named_pair = provider
        .as_deref()
        .map_or_else(
            || unseenkey_core::presets::guess_by_name(&name),
            unseenkey_core::presets::get,
        )
        .filter(|p| p.pair_labels().is_some());
    let value = if let Some(path) = &file {
        let bytes =
            zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| {
                CliError::general(format!("could not read {}: {e}", path.display()))
            })?);
        unseenkey_core::crypto::SecretBytes::from_slice(&bytes)
    } else if stdin {
        uio::read_secret_rest()?
    } else {
        let what = named_pair
            .and_then(|p| p.pair_labels())
            .map_or("Value", |(user, _)| user);
        uio::read_secret_line(&format!("{what} for {name} (hidden): "))?
    };
    if value.is_empty() {
        return Err(CliError::general("empty value"));
    }
    let value_str = std::str::from_utf8(value.expose())
        .map_err(|_| CliError::general("value must be UTF-8 text; use import for binary"))?;
    // A pasted token often carries a trailing space or tab; a multi-line value
    // (a PEM key) is kept exactly as given.
    let value_str = if value_str.contains('\n') {
        value_str
    } else {
        value_str.trim_end()
    };
    // An AWS access key id on its own is half a credential: ask for the rest.
    // (Both halves can also be given at once: two lines, a ~/.aws/credentials
    // section or `aws sts` JSON; the daemon takes those apart.)
    let mut fields = serde_json::Map::new();
    let is_google = provider.as_deref() == Some("gcp")
        || name.to_ascii_lowercase().contains("google")
        || value_str.contains("service_account")
        || value_str.contains("authorized_user")
        || value_str.contains("googleusercontent.com")
        || value_str.contains("googleapis.com");
    let scope = if is_google {
        unseenkey_core::providers::google_scopes(&scopes)
    } else {
        unseenkey_core::providers::plain_scopes(&scopes)
    };
    if !scope.is_empty() {
        fields.insert("scope".into(), json!(scope));
    }
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
    // The first part of a pair on its own: ask for the rest. (Both can also be
    // given at once as `first:second` or two lines; the daemon takes those apart.)
    let pair = named_pair
        .or_else(|| {
            unseenkey_core::providers::detect(value_str.as_bytes())
                .and_then(|d| unseenkey_core::presets::get(d.provider))
                .filter(|p| p.pair_labels().is_some())
        })
        .or_else(|| {
            unseenkey_core::presets::detect_by_prefix(value_str)
                .filter(|p| p.pair_labels().is_some())
        })
        .filter(|_| {
            !stdin
                && file.is_none()
                && !fields.contains_key("access_key_id")
                && unseenkey_core::providers::split_pair(value_str).is_none()
        });
    let second_part;
    let value_str = if let Some(p) = pair {
        let (_, secret_label) = p.pair_labels().unwrap_or(("", "Password"));
        second_part = uio::read_secret_line(&format!("{secret_label} (hidden): "))?;
        if second_part.is_empty() {
            return Err(CliError::general(format!(
                "{} keys come in two parts; the {secret_label} is needed as well",
                p.display
            )));
        }
        fields.insert("username".into(), json!(value_str.trim()));
        provider = provider.or_else(|| Some(p.id.clone()));
        std::str::from_utf8(second_part.expose())
            .map_err(|_| CliError::general("value must be UTF-8 text"))?
            .trim()
    } else {
        value_str
    };
    // A provider with a host per customer: the key goes nowhere without it.
    let tenant = provider
        .as_deref()
        .map_or_else(
            || unseenkey_core::presets::guess_by_name(&name),
            unseenkey_core::presets::get,
        )
        .or_else(|| unseenkey_core::presets::detect_by_prefix(value_str))
        .and_then(|p| p.tenant.as_ref());
    let upstreams = match tenant {
        Some(t) if upstreams.is_empty() && !stdin && file.is_none() && uio::is_tty() => {
            let host = uio::read_line(&format!("{} (like {}): ", t.label, t.example))?;
            if host.is_empty() {
                upstreams
            } else {
                vec![host]
            }
        }
        _ => upstreams,
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
        if d["how"].as_str() == Some("name") {
            println!(
                "Provider: {} (from the name; pass --provider to choose another)",
                d["display"].as_str().unwrap_or("?")
            );
        } else {
            println!("Detected: {}{suffix}", d["display"].as_str().unwrap_or("?"));
        }
    }
    let ups: Vec<&str> = created["upstreams"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(example) = created["needs_host"].as_str() {
        println!(
            "Not usable yet: anyone can have a host under {}, so this key goes nowhere until you name yours: `usk secret set {} --upstream {example}`",
            ups.join(", "),
            created["name"].as_str().unwrap_or("")
        );
    } else if ups.is_empty() {
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
    if let Some(path) = &file {
        println!(
            "The vault has its own copy now. Delete {} once nothing reads it.",
            path.display()
        );
    }
    // USK_NO_KEY_TEST: scripts and test suites that store made-up keys.
    let test = test && std::env::var_os("USK_NO_KEY_TEST").is_none();
    if test && created["provider"].is_string() {
        let id = created["id"].as_str().unwrap_or("");
        print_test(&c.post(&format!("/v1/secrets/{id}/test"), json!({}))?);
    } else if created["provider"].is_null() {
        println!("No provider: choose one with `usk secret set {} --provider <id>` (`usk presets` lists them) so the broker knows how to send it.", created["name"].as_str().unwrap_or(""));
    }
    Ok(())
}

/// One line for a key test result.
fn print_test(t: &Value) {
    let msg = t["message"].as_str().unwrap_or("");
    match (t["tested"].as_bool(), t["ok"].as_bool()) {
        (Some(true), Some(true)) => println!("Tested: works. {msg}"),
        // A message that names a command has already said what to do.
        (Some(true), Some(false)) if msg.contains("`usk ") => println!("Tested: REFUSED. {msg}"),
        (Some(true), Some(false)) => {
            println!("Tested: REFUSED. {msg} Replace it with `usk secret replace <name>`.")
        }
        (Some(true), None) => println!("Tested: unclear. {msg}"),
        _ => println!("Not tested: {msg}"),
    }
}

fn secret_test(paths: &VaultPaths, name: &str, json_out: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let t = c.post(&format!("/v1/secrets/{name}/test"), json!({}))?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&t).unwrap_or_default());
    } else {
        print_test(&t);
    }
    if t["ok"].as_bool() == Some(false) {
        return Err(CliError::with_code(
            1,
            "refused",
            "the provider refused the key",
        ));
    }
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
    c.ensure_owner()?;
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
    let out = c.delete(&format!("/v1/secrets/{name}"))?;
    match out["handles_revoked"].as_u64().unwrap_or(0) {
        0 => println!("Deleted {name}."),
        1 => println!("Deleted {name}; its handle was revoked."),
        n => println!("Deleted {name}; its {n} handles were revoked."),
    }
    Ok(())
}

fn import(paths: &VaultPaths, env_path: &Path, all: bool, dry_run: bool) -> Result<(), CliError> {
    let text = std::fs::read_to_string(env_path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", env_path.display())))?;
    let entries = parse_dotenv(&text);
    let (usernames, joined) = unseenkey_core::import::paired_usernames(&entries);
    let own_hosts = unseenkey_core::import::own_hosts(&entries);
    let candidates: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let account_id = std::str::from_utf8(e.value.expose())
                .is_ok_and(unseenkey_core::providers::is_bare_sid);
            (all || (e.looks_secret && !account_id)) && !joined.contains(&e.key)
        })
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
        let username = usernames.get(&e.key);
        let fields = username.map_or_else(|| json!({}), |u| json!({ "username": u }));
        let body = json!({
            "name": name,
            "type": if username.is_some() { "basic_auth" } else { e.detection.map(|d| d.kind.as_str()).unwrap_or("note") },
            "value": value,
            "fields": fields,
            "upstreams": own_hosts.get(&e.key).map_or_else(Vec::new, |h| vec![h.clone()]),
            "tags": ["imported"],
            "notes": format!("imported from {} ({})", env_path.display(), e.key),
        });
        match c.post("/v1/secrets", body) {
            Ok(created) => {
                added += 1;
                match own_hosts.get(&e.key) {
                    Some(host) => println!("added {name}, locked to {host}"),
                    None => println!("added {name}"),
                }
                if let Some(example) = created["needs_host"].as_str() {
                    println!("  not usable yet: name its host with `usk secret set {name} --upstream {example}`");
                }
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

fn passwd(paths: &VaultPaths, profile: Argon2Profile) -> Result<(), CliError> {
    let storage =
        SqliteStorage::open(&paths.vault).map_err(|e| CliError::general(e.to_string()))?;
    let mut v = Vault::open(storage, SystemClock).map_err(map_vault_err)?;
    let current = uio::read_secret_line("Current password: ")?;
    v.unlock_with_password(&current).map_err(map_vault_err)?;
    let pw = uio::read_secret_line("New password: ")?;
    if pw.len() < 12 {
        return Err(CliError::general("password must be at least 12 characters"));
    }
    if pw == current {
        return Err(CliError::general("that is the current password"));
    }
    if uio::is_tty() {
        let again = uio::read_secret_line("Repeat new password: ")?;
        if again != pw {
            return Err(CliError::general("passwords do not match"));
        }
    }
    // The daemon must not hold an unlocked copy while the header changes. It
    // may have changed the header during the prompts (a device unlock added).
    if let Some(c) = Client::try_connect(paths) {
        c.post("/v1/lock", json!({}))?;
    }
    v.reload_header().map_err(map_vault_err)?;
    v.change_password(&pw, profile).map_err(map_vault_err)?;
    println!("Password changed, and the vault is locked. The recovery phrase still works.");
    println!("A copy of the vault file made before now still opens with the old password.");
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
        /// The project the handle is for; its requests count toward the
        /// project's daily limit.
        #[arg(long)]
        project: Option<String>,
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
    /// Project name or id (sent as is; the daemon resolves either).
    project: Option<String>,
}

impl Incidents {
    /// Add the settings to a `POST /v1/handles` body.
    fn apply(&self, body: &mut Value) -> Result<(), CliError> {
        if let Some(p) = &self.project {
            body["project"] = json!(p);
        }
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
    // A policy of one's own is the owner's call; the care-level default is not.
    if body.get("preset_policy").is_some() || body.get("policy").is_some() {
        c.ensure_owner()?;
    }
    let created = c.post("/v1/handles", body)?;
    print_handle_created(&created, json);
    Ok(())
}

fn handle_resume(paths: &VaultPaths, r#ref: &str) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    c.ensure_owner()?;
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
    c.ensure_owner()?;
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
        c.ensure_owner()?;
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
    since: Option<u64>,
    limit: usize,
    json: bool,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let mut url = match since {
        Some(since) => format!("/v1/audit?since={since}&limit={limit}"),
        None => format!("/v1/audit?latest=true&limit={limit}"),
    };
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
    if since.is_none() && items.len() == limit && items[0]["seq"].as_u64().is_some_and(|s| s > 1) {
        let same_kind = kind
            .as_deref()
            .map(|k| format!(" --kind {k}"))
            .unwrap_or_default();
        println!(
            "The newest {} events. Older ones: usk log --since 1{same_kind}",
            items.len()
        );
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
    let head = r["head"]["state"].as_str().unwrap_or("");
    if json {
        println!("{r}");
    } else if r["ok"].as_bool() == Some(true) {
        match head {
            "verified" => println!(
                "Audit log intact: {} events, chain and keyed head verified.",
                r["rows"]
            ),
            "missing" => println!(
                "Audit log intact: {} events, chain verified. No keyed head yet (one is written with the next event), so a log cut short would not show here.",
                r["rows"]
            ),
            _ => println!(
                "Audit log intact: {} events, chain verified. Unlock the vault to also check the keyed head (a log cut short would not show here).",
                r["rows"]
            ),
        }
    } else if r["first_broken"].is_null() {
        match head {
            "forged" => println!(
                "AUDIT LOG TAMPERED: the chain is consistent but its keyed head was rewritten without the vault key"
            ),
            _ => println!(
                "AUDIT LOG TAMPERED: the chain is consistent but ends at event {} where the keyed head says {} (rows removed or rewritten after that point)",
                r["head"]["last_seq"], r["head"]["head_seq"]
            ),
        }
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
    /// Connect your AI tools: finds the ones on this computer, and on a terminal
    /// also makes the vault if there is none. Safe to run again.
    Install {
        /// claude-code, claude-desktop, cursor, windsurf, all, or a custom name.
        /// Leave it out to connect every tool found.
        client: Option<String>,
        /// Make a vault if there is none, even when not on a terminal (the password comes from stdin).
        #[arg(long)]
        new_vault: bool,
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
    let c = unlocked(paths)?;
    // The answer is the owner's: a tool that holds the session token could
    // otherwise approve its own request.
    c.ensure_owner()?;
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
        /// Put the moved secrets in this project (see `usk project protect`).
        #[arg(long)]
        project: Option<String>,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Check a stored key works: one read-only request to its provider.
    Test {
        /// Secret name.
        name: String,
    },
    /// Replace a secret's value (a new or rotated key). Handles keep working.
    Replace {
        /// Secret name.
        name: String,
        /// Read the new value from standard input instead of prompting.
        #[arg(long)]
        stdin: bool,
    },
    /// Set flags and metadata on a secret (never the value: see `replace`).
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
        /// Change the provider preset (brings its hosts unless --upstream is given).
        #[arg(long)]
        provider: Option<String>,
        /// Replace the scopes of a service account's or OAuth client's tokens;
        /// repeatable. Short names work: `webmasters.readonly`.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Set the other part of a key in two parts: Twilio's Account SID,
        /// Razorpay's key ID.
        #[arg(long)]
        username: Option<String>,
    },
}

fn care(paths: &VaultPaths, level: Option<&str>) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let explain = |l: &str| {
        match l {
        "relaxed" => "anything goes; deletes and money out (refunds, payouts, transfers) ask you first",
        "strict" => "each provider's cautious default, often read only; best for keys you share",
        _ => "anything goes except deletes, money out and key, billing or account changes, which ask you first",
    }
    };
    match level {
        None => {
            let l = c.get("/v1/status")?["care"]
                .as_str()
                .unwrap_or("balanced")
                .to_string();
            println!("Care: {l}: {}.", explain(&l));
            println!("Change it with `usk care relaxed|balanced|strict`. Allowed websites, scrubbing and the log apply at every level.");
        }
        Some(l) => {
            c.ensure_owner()?;
            let r = c.patch("/v1/settings", json!({ "care": l }))?;
            let l = r["care"].as_str().unwrap_or(l).to_string();
            println!("Care is now {l}: {}.", explain(&l));
            let n = r["handles_updated"].as_u64().unwrap_or(0);
            if n > 0 {
                println!("Updated {n} access {} Unseenkey had handed out; access you set up yourself is unchanged.", if n == 1 { "entry" } else { "entries" });
            }
        }
    }
    Ok(())
}

fn secret_replace(paths: &VaultPaths, name: &str, stdin: bool) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let meta = c.get(&format!("/v1/secrets/{name}"))?;
    if matches!(
        meta["kind"].as_str(),
        Some("aws_credentials" | "oauth2_client" | "gcp_service_account")
    ) {
        return Err(CliError::general(format!(
            "{name} holds several values; remove it with `usk rm {name}` and add it again"
        )));
    }
    let value = if stdin {
        uio::read_secret_rest()?
    } else {
        let what = meta["provider"]
            .as_str()
            .and_then(unseenkey_core::presets::get)
            .and_then(|p| p.pair_labels())
            .map_or("New value", |(_, secret)| secret);
        uio::read_secret_line(&format!("{what} for {name} (hidden): "))?
    };
    let text = std::str::from_utf8(value.expose())
        .map_err(|_| CliError::general("value must be UTF-8 text"))?;
    if text.trim().is_empty() {
        return Err(CliError::general("empty value; nothing changed"));
    }
    // Same rule as `add` and the daemon: a single-line key loses stray
    // spaces and line breaks at either end (older daemons do not do this).
    let text = if text.trim().contains('\n') {
        text
    } else {
        text.trim()
    };
    let m = c.patch(&format!("/v1/secrets/{name}"), json!({ "value": text }))?;
    println!(
        "Replaced the value of {} (now version {}). Its handles keep working with the new key.",
        m["name"].as_str().unwrap_or(name),
        m["value_version"].as_u64().unwrap_or(0)
    );
    if m["provider"].is_string() && std::env::var_os("USK_NO_KEY_TEST").is_none() {
        if let Ok(t) = c.post(&format!("/v1/secrets/{name}/test"), json!({})) {
            print_test(&t);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn secret_set(
    paths: &VaultPaths,
    name: &str,
    allow_injection: Option<bool>,
    no_scrub: Option<bool>,
    notes: Option<String>,
    tags: Vec<String>,
    upstreams: Vec<String>,
    provider: Option<String>,
    scopes: Vec<String>,
    username: Option<String>,
) -> Result<(), CliError> {
    let c = unlocked(paths)?;
    let mut body = serde_json::Map::new();
    if let Some(u) = username {
        body.insert("username".into(), json!(u));
    }
    if !scopes.is_empty() {
        // A bare scope is short for a Google URL only when this key is Google's,
        // as it is now or as this same command makes it.
        let meta = c.get(&format!("/v1/secrets/{name}"))?;
        let stored_hosts: Vec<String> = meta["upstreams"]
            .as_array()
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let hosts = if upstreams.is_empty() {
            &stored_hosts
        } else {
            &upstreams
        };
        let is_google = meta["kind"] == "gcp_service_account"
            || provider
                .as_deref()
                .map_or(meta["provider"] == "gcp", |p| p == "gcp")
            || hosts.iter().any(|h| h.contains("googleapis.com"));
        let scope = if is_google {
            unseenkey_core::providers::google_scopes(&scopes)
        } else {
            unseenkey_core::providers::plain_scopes(&scopes)
        };
        body.insert("scope".into(), json!(scope));
    }
    if let Some(p) = provider {
        body.insert("provider".into(), json!(p));
    }
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
            "nothing to change; pass --allow-injection, --no-scrub, --notes, --tag, --upstream, --scope or --username",
        ));
    }
    // Where a key may go and how it may leave the vault are the owner's to change.
    if [
        "provider",
        "allow_injection",
        "no_scrub",
        "upstreams",
        "scope",
    ]
    .iter()
    .any(|k| body.contains_key(*k))
    {
        c.ensure_owner()?;
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
                    "id": p.id, "display": p.display, "category": p.category, "upstreams": p.upstreams, "docs": p.docs,
                    "testable": p.verify.is_some(),
                    "policies": p.policies.iter().map(|pp| json!({
                        "id": pp.id, "display": pp.display, "recommended": pp.recommended,
                        "lines": p.policy(&pp.id).map(|pol| unseenkey_core::policy::explain(&pol).lines().map(str::to_string).collect::<Vec<_>>()).unwrap_or_default(),
                        "allow": pp.allow.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                        "deny": pp.deny.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                        "limits": p.policy(&pp.id).and_then(|pol| serde_json::to_value(&pol.limits).ok()).map(|v| match v {
                            Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).collect()),
                            other => other,
                        }).unwrap_or_else(|| json!({})),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(());
    }
    for p in all {
        println!(
            "{:<12} {:<16} {}{}",
            p.id,
            p.display,
            if p.upstreams.is_empty() {
                "(any locked host)".to_string()
            } else {
                p.upstreams.join(", ")
            },
            if unseenkey_core::presets::is_user_preset(&p.id) {
                "  (yours)"
            } else {
                ""
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
    // The check below says it, in its place.
    crate::client::skip_version_warning();
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
        let advice = crate::client::version_warning(ver, env!("CARGO_PKG_VERSION"))
            .map(|w| w.trim_start_matches("warning: ").to_string())
            .unwrap_or_default();
        check(
            ver == env!("CARGO_PKG_VERSION"),
            &format!(
                "daemon version {ver} matches CLI {}",
                env!("CARGO_PKG_VERSION")
            ),
            &advice,
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
