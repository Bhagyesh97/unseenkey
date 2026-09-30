//! Command definitions and handlers.

use crate::io::{self as uio, CliError, EXIT_LOCKED};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::ids::Id;
use unseenkey_core::import::parse_dotenv;
use unseenkey_core::providers;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::{NewSecret, SecretKind, SecretMeta, Vault, VaultError};

type V = Vault<SqliteStorage, SystemClock>;

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
    /// Print a secret's value once. Audited (from M1.4). Requires --yes.
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
    /// Show vault status.
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

fn default_vault_path() -> Result<PathBuf, CliError> {
    let base = if cfg!(windows) {
        dirs::config_dir().map(|d| d.join("Unseenkey"))
    } else {
        dirs::home_dir().map(|d| d.join(".unseenkey"))
    };
    base.map(|d| d.join("vault.db"))
        .ok_or_else(|| CliError::general("cannot determine the vault location; pass --vault"))
}

fn profile(p: Profile) -> Argon2Profile {
    match p {
        Profile::Desktop => Argon2Profile::DESKTOP,
        Profile::Light => Argon2Profile::LIGHT,
    }
}

fn map_err(e: VaultError) -> CliError {
    match e {
        VaultError::Locked | VaultError::WrongCredential => {
            CliError::new(EXIT_LOCKED, e.to_string())
        }
        VaultError::NoVault => CliError::general("no vault found; run `usk init` first"),
        other => CliError::general(other.to_string()),
    }
}

fn open_unlocked(path: &Path) -> Result<V, CliError> {
    let storage = SqliteStorage::open(path).map_err(|e| CliError::general(e.to_string()))?;
    let mut v = Vault::open(storage, SystemClock).map_err(map_err)?;
    let pw = uio::read_secret_line("Vault password: ")?;
    v.unlock_with_password(&pw).map_err(map_err)?;
    Ok(v)
}

pub fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(p) => p,
        None => default_vault_path()?,
    };
    match cli.command {
        Command::Init { profile: p } => init(&path, profile(p)),
        Command::Add {
            name,
            r#type,
            provider,
            upstreams,
            tags,
            notes,
            stdin,
        } => add(&path, name, r#type, provider, upstreams, tags, notes, stdin),
        Command::Ls => ls(&path, cli.json),
        Command::Show { name } => show(&path, &name, cli.json),
        Command::Reveal { name, yes, reason } => reveal(&path, &name, yes, reason),
        Command::Rm { name, yes } => rm(&path, &name, yes),
        Command::Import {
            from_env,
            all,
            dry_run,
        } => import(&path, &from_env, all, dry_run),
        Command::Recover { profile: p } => recover(&path, profile(p)),
        Command::Status => status(&path, cli.json),
    }
}

fn init(path: &Path, profile: Argon2Profile) -> Result<(), CliError> {
    if path.exists() {
        let storage = SqliteStorage::open(path).map_err(|e| CliError::general(e.to_string()))?;
        if Vault::open(storage, SystemClock).is_ok() {
            return Err(CliError::general(format!(
                "a vault already exists at {}",
                path.display()
            )));
        }
    }
    println!("Creating a vault at {}", path.display());
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
    let storage = SqliteStorage::open(path).map_err(|e| CliError::general(e.to_string()))?;
    let (v, kit) = Vault::create(storage, SystemClock, &pw, profile).map_err(map_err)?;
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
    path: &Path,
    name: String,
    kind: Option<SecretKind>,
    provider: Option<String>,
    upstreams: Vec<String>,
    tags: Vec<String>,
    notes: Option<String>,
    stdin: bool,
) -> Result<(), CliError> {
    let mut v = open_unlocked(path)?;
    let value = if stdin {
        uio::read_secret_rest()?
    } else {
        uio::read_secret_line(&format!("Value for {name} (hidden): "))?
    };
    if value.is_empty() {
        return Err(CliError::general("empty value"));
    }
    let detected = providers::detect(value.expose());
    let provider = provider.or_else(|| detected.map(|d| d.provider.to_string()));
    let kind = kind
        .or_else(|| detected.map(|d| d.kind))
        .unwrap_or(SecretKind::ApiKey);
    let upstreams = if upstreams.is_empty() {
        provider
            .as_deref()
            .and_then(providers::provider)
            .map(|d| d.upstreams.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    } else {
        upstreams
    };
    if let Some(d) = detected {
        let note = if d.note.is_empty() {
            String::new()
        } else {
            format!(" ({})", d.note)
        };
        println!("Detected: {}{note}", d.display);
    }
    let id = v
        .add(NewSecret {
            name: name.clone(),
            kind,
            value,
            fields: BTreeMap::new(),
            provider,
            upstreams: upstreams.clone(),
            tags,
            notes,
        })
        .map_err(map_err)?;
    if upstreams.is_empty() {
        println!(
            "Warning: no upstream host locked. Add one with --upstream so the broker can use it."
        );
    } else {
        println!("Upstream locked to: {}", upstreams.join(", "));
    }
    println!("Saved {name} ({id}).");
    Ok(())
}

fn meta_json(m: &SecretMeta) -> serde_json::Value {
    serde_json::json!({
        "id": m.secret_id.to_hex(),
        "name": m.name,
        "type": m.kind.as_str(),
        "provider": m.provider,
        "tags": m.tags,
        "upstreams": m.upstreams,
        "notes": m.notes,
        "created_at": m.created_at,
        "updated_at": m.updated_at,
        "value_version": m.value_version,
        "allow_injection": m.allow_injection,
    })
}

fn ls(path: &Path, json: bool) -> Result<(), CliError> {
    let v = open_unlocked(path)?;
    let list = v.list().map_err(map_err)?;
    if json {
        let arr: Vec<_> = list.iter().map(|m| meta_json(m)).collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
        return Ok(());
    }
    if list.is_empty() {
        println!("No secrets yet. Add one with `usk add <name>`.");
        return Ok(());
    }
    let (h_name, h_type, h_prov, h_up) = ("NAME", "TYPE", "PROVIDER", "UPSTREAMS");
    println!("{h_name:<28} {h_type:<18} {h_prov:<12} {h_up}");
    for m in list {
        println!(
            "{:<28} {:<18} {:<12} {}",
            m.name,
            m.kind.as_str(),
            m.provider.as_deref().unwrap_or("-"),
            if m.upstreams.is_empty() {
                "(none: not locked)".to_string()
            } else {
                m.upstreams.join(",")
            }
        );
    }
    Ok(())
}

fn show(path: &Path, name: &str, json: bool) -> Result<(), CliError> {
    let v = open_unlocked(path)?;
    let m = v.get_by_name(name).map_err(map_err)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&meta_json(m)).unwrap_or_default()
        );
        return Ok(());
    }
    println!("name:       {}", m.name);
    println!("id:         {}", m.secret_id);
    println!("type:       {}", m.kind.as_str());
    println!("provider:   {}", m.provider.as_deref().unwrap_or("-"));
    println!(
        "upstreams:  {}",
        if m.upstreams.is_empty() {
            "(none)".into()
        } else {
            m.upstreams.join(", ")
        }
    );
    println!(
        "tags:       {}",
        if m.tags.is_empty() {
            "-".into()
        } else {
            m.tags.join(", ")
        }
    );
    println!("notes:      {}", m.notes.as_deref().unwrap_or("-"));
    println!("versions:   {}", m.value_version);
    println!(
        "injection:  {}",
        if m.allow_injection { "allowed" } else { "off" }
    );
    println!(
        "value:      [hidden] use `usk reveal {} --yes` to print it once",
        m.name
    );
    Ok(())
}

fn reveal(path: &Path, name: &str, yes: bool, _reason: Option<String>) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::general(
            "reveal prints the secret to this terminal; add --yes to confirm",
        ));
    }
    let v = open_unlocked(path)?;
    let m = v.get_by_name(name).map_err(map_err)?;
    let id: Id = m.secret_id;
    let r = v.reveal(&id).map_err(map_err)?;
    // Audit event for reveals is wired in M1.4.
    match std::str::from_utf8(r.value.expose()) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("hex:{}", hex_of(r.value.expose())),
    }
    for (k, val) in &r.fields {
        match std::str::from_utf8(val.expose()) {
            Ok(s) => println!("{k}={s}"),
            Err(_) => println!("{k}=hex:{}", hex_of(val.expose())),
        }
    }
    Ok(())
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rm(path: &Path, name: &str, yes: bool) -> Result<(), CliError> {
    let mut v = open_unlocked(path)?;
    let id = v.get_by_name(name).map_err(map_err)?.secret_id;
    if !yes && uio::is_tty() && !uio::confirm(&format!("Delete {name}?"))? {
        println!("Cancelled.");
        return Ok(());
    }
    v.delete(&id).map_err(map_err)?;
    println!("Deleted {name}.");
    Ok(())
}

fn import(path: &Path, env_path: &Path, all: bool, dry_run: bool) -> Result<(), CliError> {
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
    let mut v = open_unlocked(path)?;
    let mut added = 0;
    for e in candidates {
        let name = e.key.to_lowercase().replace('_', "-");
        let d = e.detection;
        let provider = d.map(|d| d.provider.to_string());
        let upstreams = d
            .map(|d| d.upstreams.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        match v.add(NewSecret {
            name: name.clone(),
            kind: d.map(|d| d.kind).unwrap_or(SecretKind::Note),
            value: e.value,
            fields: BTreeMap::new(),
            provider,
            upstreams,
            tags: vec!["imported".into()],
            notes: Some(format!("imported from {} ({})", env_path.display(), e.key)),
        }) {
            Ok(_) => {
                added += 1;
                println!("added {name}");
            }
            Err(VaultError::NameExists(_)) => println!("skipped {name}: already exists"),
            Err(err) => return Err(map_err(err)),
        }
    }
    println!(
        "Imported {added} secret(s). Next: replace the values in {} with handles (M1.4).",
        env_path.display()
    );
    Ok(())
}

fn recover(path: &Path, profile: Argon2Profile) -> Result<(), CliError> {
    let storage = SqliteStorage::open(path).map_err(|e| CliError::general(e.to_string()))?;
    let mut v = Vault::open(storage, SystemClock).map_err(map_err)?;
    let phrase = uio::read_secret_line("Recovery phrase (24 words): ")?;
    let phrase_str = std::str::from_utf8(phrase.expose())
        .map_err(|_| CliError::general("invalid recovery phrase"))?;
    v.unlock_with_recovery(phrase_str).map_err(map_err)?;
    let pw = uio::read_secret_line("New password: ")?;
    if pw.len() < 12 {
        return Err(CliError::general("password must be at least 12 characters"));
    }
    v.change_password(&pw, profile).map_err(map_err)?;
    println!("Password changed. The recovery phrase still works; keep it safe.");
    Ok(())
}

fn status(path: &Path, json: bool) -> Result<(), CliError> {
    let exists = path.exists()
        && SqliteStorage::open(path)
            .ok()
            .and_then(|s| Vault::open(s, SystemClock).ok())
            .is_some();
    if json {
        println!(
            "{}",
            serde_json::json!({ "vault": path.display().to_string(), "exists": exists, "version": env!("CARGO_PKG_VERSION") })
        );
    } else {
        println!("vault:   {}", path.display());
        println!(
            "exists:  {}",
            if exists { "yes" } else { "no (run `usk init`)" }
        );
        println!("version: {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
