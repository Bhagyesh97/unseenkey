//! `usk project`: group secrets by the code folder that uses them.

use crate::client::Client;
use crate::io::{self as uio, CliError};
use clap::Subcommand;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use unseenkey_daemon::VaultPaths;

/// `usk project …`
#[derive(Subcommand)]
pub enum ProjectAction {
    /// List projects with their folders, secrets and requests today.
    Ls,
    /// Create a project for a folder (default: the current folder).
    Add {
        /// Name (default: the folder's name).
        name: Option<String>,
        /// Code folder (repeatable; default: the current folder).
        #[arg(long = "path", value_name = "DIR")]
        paths: Vec<PathBuf>,
        /// Secret to add (repeatable).
        #[arg(long = "secret", value_name = "NAME")]
        secrets: Vec<String>,
        /// Daily request limit across the project's handles: `500` or `500/day`.
        #[arg(long, value_name = "N")]
        cap: Option<String>,
    },
    /// Show a project (default: the one the current folder belongs to).
    Show {
        /// Name or id.
        project: Option<String>,
    },
    /// Add secrets to a project.
    Attach {
        /// Project name or id.
        project: String,
        /// Secret names.
        #[arg(required = true)]
        secrets: Vec<String>,
    },
    /// Take secrets out of a project (they stay in the vault).
    Detach {
        /// Project name or id.
        project: String,
        /// Secret names.
        #[arg(required = true)]
        secrets: Vec<String>,
    },
    /// Rename a project, change its folders, limit or notes.
    Set {
        /// Project name or id.
        project: String,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// Replace the folders (repeatable).
        #[arg(long = "path", value_name = "DIR")]
        paths: Vec<PathBuf>,
        /// Daily request limit: `500` or `500/day`.
        #[arg(long, value_name = "N", conflicts_with = "no_cap")]
        cap: Option<String>,
        /// Remove the daily limit.
        #[arg(long)]
        no_cap: bool,
        /// Notes (empty clears).
        #[arg(long)]
        notes: Option<String>,
    },
    /// Delete a project. Its secrets and handles stay.
    Rm {
        /// Project name or id.
        project: String,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
    },
    /// Protect a folder in one step: create its project if needed, move the
    /// real keys in its `.env` into the vault and leave handles behind.
    Protect {
        /// The code folder (default: the current folder).
        dir: Option<PathBuf>,
        /// The env file inside it.
        #[arg(long, default_value = ".env")]
        env: PathBuf,
        /// Show what would change without writing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn unlocked(paths: &VaultPaths) -> Result<Client, CliError> {
    let c = Client::connect(paths, true)?;
    c.ensure_unlocked()?;
    Ok(c)
}

/// Absolute form of a folder argument, as the daemon will compare it.
pub fn abs_dir(p: &Path) -> Result<String, CliError> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| CliError::general(format!("current folder: {e}")))?
            .join(p)
    };
    let abs = std::fs::canonicalize(&abs).unwrap_or(abs);
    let s = abs.display().to_string();
    // canonicalize on Windows yields `\\?\C:\…`; the daemon compares plain paths.
    Ok(s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s))
}

fn parse_cap(s: &str) -> Result<u64, CliError> {
    let n = s
        .trim()
        .trim_end_matches("/day")
        .trim_end_matches("/d")
        .replace(['_', ','], "");
    n.parse::<u64>().ok().filter(|n| *n > 0).ok_or_else(|| {
        CliError::general(format!(
            "--cap {s:?}: give a number of requests a day, e.g. 500"
        ))
    })
}

/// The id of a project given by name or id. Names may contain spaces, so
/// URLs always use the id.
pub fn project_id(c: &Client, r: &str) -> Result<String, CliError> {
    let list = c.get("/v1/projects")?;
    list.as_array()
        .into_iter()
        .flatten()
        .find(|p| {
            p["id"].as_str() == Some(r)
                || p["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(r.trim()))
        })
        .and_then(|p| p["id"].as_str().map(str::to_string))
        .ok_or_else(|| CliError::general(format!("no project named {r:?}; see `usk project ls`")))
}

/// The project whose folder contains `dir`, if any.
pub fn project_for_dir(c: &Client, dir: &str) -> Result<Option<Value>, CliError> {
    let enc = unseenkey_core::projects::encode_dir(dir);
    let list = c.get(&format!("/v1/projects?dir={enc}"))?;
    Ok(list.as_array().and_then(|a| a.first().cloned()))
}

fn print_project(p: &Value) {
    println!("project:   {}", p["name"].as_str().unwrap_or(""));
    for (i, path) in p["paths"].as_array().into_iter().flatten().enumerate() {
        let label = if i == 0 { "folders:  " } else { "          " };
        println!("{label} {}", path.as_str().unwrap_or(""));
    }
    if p["paths"].as_array().is_none_or(|a| a.is_empty()) {
        println!("folders:   (none: agents are never scoped to this project)");
    }
    let secrets: Vec<&str> = p["secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["name"].as_str())
        .collect();
    println!(
        "secrets:   {}",
        if secrets.is_empty() {
            "(none yet)".to_string()
        } else {
            secrets.join(", ")
        }
    );
    let today = p["requests_today"].as_u64().unwrap_or(0);
    match p["cap_per_day"].as_u64() {
        Some(cap) => println!("today:     {today} of {cap} requests"),
        None => println!("today:     {today} requests (no daily limit)"),
    }
    println!("id:        {}", p["id"].as_str().unwrap_or(""));
}

/// Run a `usk project` command.
pub fn run(paths: &VaultPaths, action: ProjectAction, json_out: bool) -> Result<(), CliError> {
    match action {
        ProjectAction::Ls => {
            let c = unlocked(paths)?;
            let list = c.get("/v1/projects")?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&list).unwrap_or_default()
                );
                return Ok(());
            }
            let items = list.as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                println!("No projects yet. In a code folder, run `usk project protect` (or `usk project add`).");
                return Ok(());
            }
            println!("{:<22} {:>7} {:>13}  FOLDER", "PROJECT", "SECRETS", "TODAY");
            for p in items {
                let today = match p["cap_per_day"].as_u64() {
                    Some(cap) => format!("{}/{cap}", p["requests_today"].as_u64().unwrap_or(0)),
                    None => p["requests_today"].as_u64().unwrap_or(0).to_string(),
                };
                println!(
                    "{:<22} {:>7} {:>13}  {}",
                    p["name"].as_str().unwrap_or(""),
                    p["secrets"].as_array().map(Vec::len).unwrap_or(0),
                    today,
                    p["paths"][0].as_str().unwrap_or("-")
                );
            }
            Ok(())
        }
        ProjectAction::Add {
            name,
            paths: dirs,
            secrets,
            cap,
        } => {
            let c = unlocked(paths)?;
            let dirs = if dirs.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                dirs
            };
            let abs: Vec<String> = dirs.iter().map(|d| abs_dir(d)).collect::<Result<_, _>>()?;
            let mut body = json!({ "paths": abs, "secrets": secrets });
            if let Some(n) = name {
                body["name"] = json!(n);
            }
            if let Some(cap) = cap {
                body["cap_per_day"] = json!(parse_cap(&cap)?);
            }
            let p = c.post("/v1/projects", body)?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            } else {
                println!("Created project {}.", p["name"].as_str().unwrap_or(""));
                print_project(&p);
                println!();
                println!("Agents started in that folder now see only this project's secrets. Add some with `usk project attach`.");
            }
            Ok(())
        }
        ProjectAction::Show { project } => {
            let c = unlocked(paths)?;
            let p = match project {
                Some(r) => c.get(&format!("/v1/projects/{}", project_id(&c, &r)?))?,
                None => {
                    let here = abs_dir(Path::new("."))?;
                    project_for_dir(&c, &here)?.ok_or_else(|| {
                        CliError::general(format!(
                            "{here} is not in any project; `usk project add` makes it one"
                        ))
                    })?
                }
            };
            if json_out {
                println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            } else {
                print_project(&p);
            }
            Ok(())
        }
        ProjectAction::Attach { project, secrets } => {
            let c = unlocked(paths)?;
            let id = project_id(&c, &project)?;
            let mut last = Value::Null;
            for s in &secrets {
                last = c.post(
                    &format!("/v1/projects/{id}/secrets"),
                    json!({ "secret": s }),
                )?;
            }
            println!(
                "{} now uses: {}.",
                last["name"].as_str().unwrap_or(&project),
                names(&last)
            );
            Ok(())
        }
        ProjectAction::Detach { project, secrets } => {
            let c = unlocked(paths)?;
            let id = project_id(&c, &project)?;
            let mut last = Value::Null;
            for s in &secrets {
                last = c.delete(&format!("/v1/projects/{id}/secrets/{s}"))?;
            }
            println!(
                "{} now uses: {}.",
                last["name"].as_str().unwrap_or(&project),
                names(&last)
            );
            Ok(())
        }
        ProjectAction::Set {
            project,
            name,
            paths: dirs,
            cap,
            no_cap,
            notes,
        } => {
            let c = unlocked(paths)?;
            let id = project_id(&c, &project)?;
            let mut body = json!({});
            if let Some(n) = name {
                body["name"] = json!(n);
            }
            if !dirs.is_empty() {
                let abs: Vec<String> = dirs.iter().map(|d| abs_dir(d)).collect::<Result<_, _>>()?;
                body["paths"] = json!(abs);
            }
            if let Some(cap) = cap {
                body["cap_per_day"] = json!(parse_cap(&cap)?);
            }
            if no_cap {
                body["cap_per_day"] = Value::Null;
            }
            if let Some(n) = notes {
                body["notes"] = json!(n);
            }
            let p = c.patch(&format!("/v1/projects/{id}"), body)?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            } else {
                print_project(&p);
            }
            Ok(())
        }
        ProjectAction::Rm { project, yes } => {
            let c = unlocked(paths)?;
            let id = project_id(&c, &project)?;
            if !yes
                && uio::is_tty()
                && !uio::confirm(&format!(
                    "Delete project {project}? Its secrets and handles stay."
                ))?
            {
                println!("Cancelled.");
                return Ok(());
            }
            c.delete(&format!("/v1/projects/{id}"))?;
            println!("Deleted project {project}. Its secrets and handles are untouched.");
            Ok(())
        }
        ProjectAction::Protect { dir, env, dry_run } => {
            let dir = dir.unwrap_or_else(|| PathBuf::from("."));
            let abs = abs_dir(&dir)?;
            let env_path = if env.is_absolute() {
                env
            } else {
                Path::new(&abs).join(env)
            };
            if !env_path.exists() {
                return Err(CliError::general(format!(
                    "{} does not exist; nothing to protect yet (add keys with `usk add` and `usk project attach`)",
                    env_path.display()
                )));
            }
            let c = unlocked(paths)?;
            let project = match project_for_dir(&c, &abs)? {
                Some(p) => p,
                None if dry_run => {
                    json!({ "name": unseenkey_core::projects::name_from_dir(&abs), "id": null })
                }
                None => {
                    let p = c.post("/v1/projects", json!({ "paths": [abs] }))?;
                    println!(
                        "Created project {} for {abs}.",
                        p["name"].as_str().unwrap_or("")
                    );
                    p
                }
            };
            let name = project["name"].as_str().unwrap_or("").to_string();
            crate::guard::fix_for(paths, &env_path, dry_run, project["id"].as_str())?;
            if !dry_run {
                println!();
                println!(
                    "Project {name} is protected. Agents started in {abs} see only its secrets."
                );
            }
            Ok(())
        }
    }
}

fn names(p: &Value) -> String {
    let n: Vec<&str> = p["secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["name"].as_str())
        .collect();
    if n.is_empty() {
        "nothing yet".into()
    } else {
        n.join(", ")
    }
}
