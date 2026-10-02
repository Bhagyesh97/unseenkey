//! Running and spawning the daemon from the CLI.

use crate::io::CliError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use unseenkey_daemon::{config, ServeOptions, VaultPaths};

/// Resolve listen address and idle timeout: CLI flag, then `USK_LISTEN` /
/// `USK_IDLE_LOCK_MINUTES`, then `config.toml`, then defaults.
pub fn resolve_options(
    paths: &VaultPaths,
    listen: Option<String>,
    idle: Option<u64>,
) -> Result<ServeOptions, CliError> {
    let cfg = config::load(&paths.config).map_err(|e| CliError::general(e.to_string()))?;
    let listen = listen
        .or_else(|| std::env::var("USK_LISTEN").ok())
        .unwrap_or(cfg.daemon.listen);
    let idle_lock_minutes = idle
        .or_else(|| {
            std::env::var("USK_IDLE_LOCK_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(cfg.daemon.idle_lock_minutes);
    Ok(ServeOptions {
        vault_path: paths.vault.clone(),
        listen,
        idle_lock_minutes,
        write_runtime_files: true,
        upstream_overrides: vec![],
        mcp_allow_store: cfg.mcp.allow_store,
        lock_on_sleep: cfg.daemon.lock_on_sleep,
        lock_on_session_lock: cfg.daemon.lock_on_session_lock,
    })
}

fn init_logging(paths: &VaultPaths, to_file: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("USK_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if to_file {
        let _ = std::fs::create_dir_all(&paths.logs);
        if let Ok(file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(paths.logs.join("uskd.log"))
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(unseenkey_daemon::logging::RedactingWriter::new(file))
                .try_init();
            return;
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(unseenkey_daemon::logging::RedactingWriter::new(
            std::io::stderr(),
        ))
        .try_init();
}

/// Run the daemon until Ctrl-C or `/v1/shutdown`.
pub fn run(opts: ServeOptions, paths: &VaultPaths, log_to_file: bool) -> Result<(), CliError> {
    init_logging(paths, log_to_file);
    // A detached daemon has no terminal: make panics land in the log too.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(%info, "daemon panic");
        previous(info);
    }));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::general(format!("runtime: {e}")))?;
    rt.block_on(async move {
        let running = unseenkey_daemon::serve(opts)
            .await
            .map_err(|e| CliError::general(e.to_string()))?;
        let addr = running.addr;
        tracing::info!(%addr, "uskd started");
        // Stop on Ctrl-C as well as on `POST /v1/shutdown`.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupt received"),
            _ = running.shutdown_requested() => tracing::info!("shutdown requested"),
        }
        running.shutdown().await;
        Ok(())
    })
}

/// Entry point for the `uskd` binary: `uskd [--vault PATH] [--listen ADDR] [--idle-lock-minutes N]`.
pub fn run_foreground_from_args(args: &[String]) -> Result<(), CliError> {
    let mut vault: Option<PathBuf> = std::env::var_os("USK_VAULT").map(PathBuf::from);
    let mut listen = None;
    let mut idle = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault" => {
                vault = args.get(i + 1).map(PathBuf::from);
                i += 1;
            }
            "--listen" => {
                listen = args.get(i + 1).cloned();
                i += 1;
            }
            "--idle-lock-minutes" => {
                idle = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 1;
            }
            other => return Err(CliError::general(format!("unknown argument {other}"))),
        }
        i += 1;
    }
    let vault = match vault {
        Some(v) => v,
        None => VaultPaths::default_vault_file().ok_or_else(|| {
            CliError::general("cannot determine the vault location; pass --vault")
        })?,
    };
    let paths = VaultPaths::from_vault_file(&vault);
    let opts = resolve_options(&paths, listen, idle)?;
    run(opts, &paths, false)
}

/// Spawn `usk daemon run --detached` for `paths.vault` as a background process.
pub fn spawn_detached(paths: &VaultPaths) -> Result<(), CliError> {
    let exe =
        std::env::current_exe().map_err(|e| CliError::general(format!("current exe: {e}")))?;
    let mut cmd = Command::new(exe);
    cmd.arg("--vault")
        .arg(&paths.vault)
        .args(["daemon", "run", "--detached"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    // Without this a daemon started from `usk … | other` keeps the pipe open (Windows).
    crate::platform::disable_std_handle_inheritance();
    cmd.spawn()
        .map_err(|e| CliError::general(format!("cannot start daemon: {e}")))?;
    Ok(())
}

/// Wait until `probe` succeeds or `timeout` passes.
pub fn wait_until<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(t) = probe() {
            return Some(t);
        }
        if start.elapsed() > timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Is a daemon pid file present and pointing at a live process? Best effort.
pub fn pid_file(paths: &VaultPaths) -> Option<u32> {
    std::fs::read_to_string(&paths.pid)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// The vault file for a `--vault` argument or the default location.
pub fn vault_path(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    match explicit {
        Some(p) => Ok(p),
        None => VaultPaths::default_vault_file()
            .ok_or_else(|| CliError::general("cannot determine the vault location; pass --vault")),
    }
}

/// True if `p` looks like an existing vault file.
pub fn vault_exists(p: &Path) -> bool {
    p.exists()
}
