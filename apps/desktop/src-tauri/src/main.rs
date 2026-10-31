// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `Client::connect` starts the daemon by re-running the current executable
    // as `<exe> --vault <path> daemon run --detached`. When this binary is
    // started that way it hosts the daemon instead of showing the UI, so the
    // desktop app needs no separate `usk` install.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "daemon") && args.iter().any(|a| a == "run") {
        if let Err(e) = unseenkey_desktop::run_daemon(&args) {
            eprintln!("error: {}", e.message);
            std::process::exit(1);
        }
        return;
    }
    // The MCP configs the app writes run `<exe> mcp --client <name>`.
    if args.first().map(String::as_str) == Some("mcp") {
        if let Err(e) = unseenkey_desktop::run_mcp_bridge(&args) {
            eprintln!("error: {}", e.message);
            std::process::exit(1);
        }
        return;
    }
    unseenkey_desktop::run()
}
