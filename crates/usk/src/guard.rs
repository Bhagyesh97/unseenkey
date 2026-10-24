//! `.env` guard: find real keys in a project's `.env`, move them into the vault,
//! and rewrite the file so it holds handles instead.

use crate::client::Client;
use crate::io::CliError;
use serde_json::{json, Value};
use std::path::Path;
use unseenkey_core::import::{parse_dotenv, DotenvEntry};
use unseenkey_core::presets;
use unseenkey_daemon::VaultPaths;

/// One finding.
pub struct Finding<'a> {
    /// The parsed line.
    pub entry: &'a DotenvEntry,
    /// Provider preset id, when the value can be proxied.
    pub preset: Option<&'static str>,
}

fn findings(entries: &[DotenvEntry]) -> Vec<Finding<'_>> {
    entries
        .iter()
        .filter(|e| e.looks_secret)
        .map(|e| Finding {
            entry: e,
            preset: e
                .detection
                .and_then(|d| presets::get(d.provider))
                .map(|p| p.id.as_str()),
        })
        .collect()
}

fn already_handle(e: &DotenvEntry) -> bool {
    core::str::from_utf8(e.value.expose()).is_ok_and(|s| presets::is_handle(s.trim()))
}

/// Report what the file contains. Returns the number of fixable findings.
pub fn scan(path: &Path, json: bool) -> Result<usize, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", path.display())))?;
    let entries = parse_dotenv(&text);
    let found = findings(&entries);
    let fixable = found
        .iter()
        .filter(|f| f.preset.is_some() && !already_handle(f.entry))
        .count();
    if json {
        let items: Vec<Value> = found
            .iter()
            .map(|f| {
                json!({
                    "line": f.entry.line, "key": f.entry.key,
                    "detected": f.entry.detection.map(|d| d.display),
                    "preset": f.preset, "fixable": f.preset.is_some() && !already_handle(f.entry),
                    "already_handle": already_handle(f.entry),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
        return Ok(fixable);
    }
    if found.is_empty() {
        println!("{}: nothing that looks like a secret.", path.display());
        return Ok(0);
    }
    let (h_line, h_key, h_det, h_act) = ("LINE", "KEY", "LOOKS LIKE", "ACTION");
    println!("{h_line:<6} {h_key:<32} {h_det:<26} {h_act}");
    for f in &found {
        let looks = f
            .entry
            .detection
            .map(|d| d.display.to_string())
            .unwrap_or_else(|| "secret (by name)".into());
        let action = if already_handle(f.entry) {
            "already a handle"
        } else if f.preset.is_some() {
            "move to vault, replace with handle"
        } else {
            "no provider preset: leave (use `usk run`)"
        };
        println!(
            "{:<6} {:<32} {:<26} {}",
            f.entry.line, f.entry.key, looks, action
        );
    }
    println!();
    println!(
        "{fixable} of {} can be replaced with handles. Run `usk guard fix {}` to do it.",
        found.len(),
        path.display()
    );
    Ok(fixable)
}

fn unique_name(c: &Client, base: &str) -> String {
    let mut name = base.to_string();
    let mut n = 1;
    while c.get(&format!("/v1/secrets/{name}")).is_ok() {
        n += 1;
        name = format!("{base}-{n}");
    }
    name
}

/// Move fixable secrets into the vault and rewrite the file with handles.
pub fn fix(paths: &VaultPaths, path: &Path, dry_run: bool) -> Result<(), CliError> {
    fix_for(paths, path, dry_run, None)
}

/// [`fix`], putting the moved secrets in a project (by id) and making the
/// handles for it, so they count toward its daily limit.
pub fn fix_for(
    paths: &VaultPaths,
    path: &Path,
    dry_run: bool,
    project: Option<&str>,
) -> Result<(), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", path.display())))?;
    let entries = parse_dotenv(&text);
    let found = findings(&entries);
    let todo: Vec<&Finding<'_>> = found
        .iter()
        .filter(|f| f.preset.is_some() && !already_handle(f.entry))
        .collect();
    if todo.is_empty() {
        println!("{}: nothing to fix.", path.display());
        return Ok(());
    }
    let skipped: Vec<&Finding<'_>> = found
        .iter()
        .filter(|f| f.preset.is_none() && !already_handle(f.entry))
        .collect();

    let c = Client::connect(paths, true)?;
    c.ensure_unlocked()?;

    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut appended: Vec<String> = Vec::new();
    let mut replaced_base: Vec<(String, String)> = Vec::new();
    for f in &todo {
        let e = f.entry;
        let preset_id = f.preset.unwrap_or("generic");
        let base_name = e.key.to_lowercase().replace('_', "-");
        let value = std::str::from_utf8(e.value.expose())
            .map_err(|_| CliError::general(format!("{}: value is not UTF-8", e.key)))?
            .to_string();
        if dry_run {
            println!("would move {} (line {}) into the vault as {base_name} and replace it with a handle", e.key, e.line);
            continue;
        }
        let name = unique_name(&c, &base_name);
        c.post(
            "/v1/secrets",
            json!({
                "name": name, "value": value, "provider": preset_id,
                "tags": ["env-guard"], "notes": format!("moved from {} ({})", path.display(), e.key),
            }),
        )?;
        let mut body = json!({ "secret": name, "label": format!("{name} .env") });
        if let Some(pid) = project {
            c.post(
                &format!("/v1/projects/{pid}/secrets"),
                json!({ "secret": name }),
            )?;
            body["project"] = json!(pid);
        }
        let created = c.post("/v1/handles", body)?;
        let handle = created["handle"].as_str().unwrap_or("").to_string();
        lines[e.line - 1] = format!("{}={handle}", e.key);
        // The SDK must be pointed at the broker: add or update the base-URL variable.
        if let Some(env) = created["env"].as_object() {
            for (var, val) in env {
                let val = val.as_str().unwrap_or("");
                if presets::is_handle(val) {
                    continue;
                }
                let prefix = format!("{var}=");
                if let Some(idx) = lines
                    .iter()
                    .position(|l| l.trim_start().starts_with(&prefix))
                {
                    lines[idx] = format!("{var}={val}");
                    replaced_base.push((var.clone(), val.to_string()));
                } else {
                    appended.push(format!("{var}={val}"));
                }
            }
        }
        println!(
            "moved {} -> vault secret {name}; line {} now holds a handle",
            e.key, e.line
        );
    }
    if dry_run {
        println!("Dry run: {} unchanged.", path.display());
        return Ok(());
    }
    let mut out = lines.join("\n");
    if !appended.is_empty() {
        out.push_str("\n# Added by usk guard: point the SDK at the local broker\n");
        out.push_str(&appended.join("\n"));
    }
    if text.ends_with('\n') || !appended.is_empty() {
        out.push('\n');
    }
    std::fs::write(path, out)
        .map_err(|e| CliError::general(format!("cannot write {}: {e}", path.display())))?;
    println!();
    println!(
        "Rewrote {}: {} secret(s) replaced with handles{}{}.",
        path.display(),
        todo.len(),
        if appended.is_empty() {
            ""
        } else {
            ", base-URL variables added"
        },
        if replaced_base.is_empty() {
            ""
        } else {
            ", base-URL variables updated"
        }
    );
    for f in &skipped {
        println!(
            "left {} in place (no provider preset; consider `usk run --with {}=…`)",
            f.entry.key, f.entry.key
        );
    }
    println!("If something stops working, `usk reveal <name> --yes` prints a value back; `usk log` shows every use.");
    Ok(())
}
