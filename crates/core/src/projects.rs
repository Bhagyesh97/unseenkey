//! Projects: a name, the code folders it lives in, and the secrets it uses.
//!
//! A project groups secrets the way a person thinks about them ("the keys my
//! shop app uses") and scopes agents: an MCP client started inside one of a
//! project's folders sees only that project's secrets. A secret can belong to
//! several projects. Handles may carry the project they were made for, which
//! is what a project's daily limit counts.
//!
//! The folder an MCP client reports is a claim made by a local process that
//! already holds that client's token. Scoping narrows what an honest agent
//! sees and uses; it is not a boundary against a hostile local process.

use crate::ids::Id;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// One project, as stored (encrypted) in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    /// Identity.
    pub project_id: Id,
    /// Unique, human name.
    pub name: String,
    /// Code folders, normalised with [`normalize_dir`].
    #[serde(default)]
    pub paths: Vec<String>,
    /// Secrets the project uses.
    #[serde(default)]
    pub secrets: Vec<Id>,
    /// Requests per rolling day across the project's handles; `None` = no limit.
    #[serde(default)]
    pub cap_per_day: Option<u64>,
    /// Free text.
    #[serde(default)]
    pub notes: Option<String>,
    /// Created (Unix ms).
    pub created_at: i64,
    /// Last changed (Unix ms).
    pub updated_at: i64,
}

impl ProjectRecord {
    /// Does the project use this secret?
    pub fn has_secret(&self, secret_id: &Id) -> bool {
        self.secrets.contains(secret_id)
    }

    /// Length of the longest of this project's folders that contains `dir`
    /// (already normalised), or `None` when none does.
    pub fn match_len(&self, dir: &str) -> Option<usize> {
        self.paths
            .iter()
            .filter(|p| dir_contains(p, dir))
            .map(String::len)
            .max()
    }
}

/// Normalise a folder path for storage and comparison: forward slashes, no
/// trailing slash, and lower case when it looks like a Windows path (drive
/// letter or UNC), whose file systems ignore case.
pub fn normalize_dir(path: &str) -> String {
    let mut p = path.trim().replace('\\', "/");
    while p.len() > 1 && p.ends_with('/') && !p.ends_with(":/") {
        p.pop();
    }
    let b = p.as_bytes();
    let windows =
        (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()) || p.starts_with("//");
    if windows {
        p = p.to_lowercase();
    }
    p
}

/// Is `dir` the folder `root` or somewhere inside it? Both normalised.
pub fn dir_contains(root: &str, dir: &str) -> bool {
    if root.is_empty() {
        return false;
    }
    if dir == root {
        return true;
    }
    let root = root.trim_end_matches('/');
    dir.len() > root.len() && dir.starts_with(root) && dir.as_bytes()[root.len()] == b'/'
}

/// Percent-encode a folder path for an HTTP header: everything but ASCII
/// letters, digits and `/ - _ . : ~` becomes `%XX`, so non-ASCII user
/// names and spaces survive.
pub fn encode_dir(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/-_.:~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&alloc::format!("%{b:02X}"));
        }
    }
    out
}

/// Undo [`encode_dir`]. `None` for malformed input or non-UTF-8 results.
pub fn decode_dir(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = core::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    let s = String::from_utf8(out).ok()?;
    (!s.trim().is_empty()).then_some(s)
}

/// The default project name for a folder: its last component.
pub fn name_from_dir(path: &str) -> String {
    normalize_dir(path)
        .rsplit('/')
        .find(|s| !s.is_empty() && !s.ends_with(':'))
        .map(ToString::to_string)
        .unwrap_or_else(|| "project".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_normalise_and_nest() {
        assert_eq!(normalize_dir(r"C:\Users\Me\Shop\"), "c:/users/me/shop");
        assert_eq!(normalize_dir("/home/me/shop/"), "/home/me/shop");
        assert_eq!(normalize_dir("/Home/Me"), "/Home/Me", "POSIX keeps case");
        assert_eq!(normalize_dir("C:\\"), "c:/");
        assert!(dir_contains("c:/users/me/shop", "c:/users/me/shop"));
        assert!(dir_contains("c:/users/me/shop", "c:/users/me/shop/web/src"));
        assert!(!dir_contains("c:/users/me/shop", "c:/users/me/shopping"));
        assert!(dir_contains("c:/", "c:/users"));
        assert!(!dir_contains("", "/x"));
        assert_eq!(name_from_dir(r"C:\Users\Me\My Shop"), "my shop");
        assert_eq!(name_from_dir("/srv/api/"), "api");
    }

    #[test]
    fn header_encoding_round_trips() {
        for p in [
            r"C:\Users\Bhāgyesh\My Shop",
            "/home/me/a%b",
            "/plain/path-1_2.x",
        ] {
            let e = encode_dir(p);
            assert!(e.bytes().all(|b| b.is_ascii_graphic()), "{e}");
            assert_eq!(decode_dir(&e).as_deref(), Some(p));
        }
        assert_eq!(decode_dir("%zz"), None);
        assert_eq!(decode_dir("%4"), None);
        assert_eq!(decode_dir(""), None);
    }

    #[test]
    fn the_deepest_folder_wins() {
        let p = |paths: &[&str]| ProjectRecord {
            project_id: Id::new_v7(1),
            name: "x".into(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            secrets: Vec::new(),
            cap_per_day: None,
            notes: None,
            created_at: 0,
            updated_at: 0,
        };
        let outer = p(&["/w"]);
        let inner = p(&["/w/app", "/elsewhere"]);
        assert_eq!(outer.match_len("/w/app/src"), Some(2));
        assert_eq!(inner.match_len("/w/app/src"), Some(6));
        assert_eq!(inner.match_len("/w/other"), None);
    }
}
