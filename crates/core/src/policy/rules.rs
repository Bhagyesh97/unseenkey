//! `"<METHOD|*> <path-glob>"` rules and the segment glob matcher.
//!
//! Globs work per path segment: `*` matches exactly one segment, `**` matches
//! any number (including none). Literal segments compare exactly. Query strings
//! are never part of matching. Paths are normalised by collapsing repeated
//! slashes and dropping a trailing slash.

use super::PolicyError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// HTTP method selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Any method.
    Any,
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
    /// OPTIONS
    Options,
}

impl Method {
    /// Parse `GET`, `post`, `*`, ...
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "*" => Method::Any,
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            _ => return None,
        })
    }

    /// Canonical spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Any => "*",
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }

    /// Does this selector accept a concrete method?
    pub fn matches(&self, actual: &str) -> bool {
        match self {
            Method::Any => Method::parse(actual).is_some_and(|m| m != Method::Any),
            m => Method::parse(actual) == Some(*m),
        }
    }
}

/// One glob segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Seg {
    Lit(String),
    One,
    Many,
}

/// A path pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathGlob {
    segs: Vec<Seg>,
    text: String,
}

/// Split a path into non-empty segments (no query, no trailing slash).
pub fn segments(path: &str) -> Vec<&str> {
    let p = path.split('?').next().unwrap_or("");
    p.split('/').filter(|s| !s.is_empty()).collect()
}

impl PathGlob {
    /// Parse a pattern. Must start with `/`.
    pub fn parse(pat: &str) -> Result<Self, String> {
        if !pat.starts_with('/') {
            return Err("path must start with /".into());
        }
        if pat.contains('?') || pat.contains('#') {
            return Err("path patterns cannot contain ? or #".into());
        }
        let segs: Vec<Seg> = segments(pat)
            .into_iter()
            .map(|s| match s {
                "*" => Seg::One,
                "**" => Seg::Many,
                lit => Seg::Lit(lit.to_string()),
            })
            .collect();
        let text = if segs.is_empty() {
            "/".to_string()
        } else {
            let mut t = String::new();
            for s in &segs {
                t.push('/');
                t.push_str(match s {
                    Seg::Lit(l) => l,
                    Seg::One => "*",
                    Seg::Many => "**",
                });
            }
            t
        };
        Ok(Self { segs, text })
    }

    /// Match a concrete path.
    pub fn matches(&self, path: &str) -> bool {
        let parts = segments(path);
        Self::match_from(&self.segs, &parts)
    }

    fn match_from(pat: &[Seg], parts: &[&str]) -> bool {
        match pat.split_first() {
            None => parts.is_empty(),
            Some((Seg::Many, rest)) => {
                // `**` matches zero or more segments: try every split.
                (0..=parts.len()).any(|i| Self::match_from(rest, &parts[i..]))
            }
            Some((Seg::One, rest)) => match parts.split_first() {
                Some((_, tail)) => Self::match_from(rest, tail),
                None => false,
            },
            Some((Seg::Lit(l), rest)) => match parts.split_first() {
                Some((p, tail)) if p == l => Self::match_from(rest, tail),
                _ => false,
            },
        }
    }

    /// Canonical text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// True if the pattern is `/**` (everything).
    pub fn is_everything(&self) -> bool {
        self.segs == [Seg::Many]
    }

    /// Prefix before the first wildcard, for explanations ("anything under /v1").
    pub fn literal_prefix(&self) -> String {
        let mut t = String::new();
        for s in &self.segs {
            match s {
                Seg::Lit(l) => {
                    t.push('/');
                    t.push_str(l);
                }
                _ => break,
            }
        }
        if t.is_empty() {
            "/".into()
        } else {
            t
        }
    }

    /// Does the pattern contain any wildcard?
    pub fn has_wildcard(&self) -> bool {
        self.segs.iter().any(|s| !matches!(s, Seg::Lit(_)))
    }
}

/// A `METHOD path` rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    /// Method selector.
    pub method: Method,
    /// Path pattern.
    pub path: PathGlob,
}

impl Rule {
    /// `* /**`
    pub fn any() -> Self {
        Self {
            method: Method::Any,
            path: PathGlob::parse("/**").expect("static pattern"),
        }
    }

    /// Parse `"GET /v1/**"`.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let s = s.trim();
        let mut it = s.split_whitespace();
        let (m, p) = match (it.next(), it.next(), it.next()) {
            (Some(m), Some(p), None) => (m, p),
            _ => {
                return Err(PolicyError::Rule(
                    s.into(),
                    "expected \"METHOD /path\" with exactly one space".into(),
                ))
            }
        };
        let method = Method::parse(m).ok_or_else(|| {
            PolicyError::Rule(
                s.into(),
                format!(
                    "unknown method {m:?}; use GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS or *"
                ),
            )
        })?;
        let path = PathGlob::parse(p).map_err(|e| PolicyError::Rule(s.into(), e))?;
        Ok(Self { method, path })
    }

    /// Does the rule cover this method and path?
    pub fn matches(&self, method: &str, path: &str) -> bool {
        self.method.matches(method) && self.path.matches(path)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method.as_str(), self.path.as_str())
    }
}

impl Serialize for Rule {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Rule::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(p: &str) -> PathGlob {
        PathGlob::parse(p).unwrap()
    }

    #[test]
    fn glob_semantics() {
        assert!(g("/v1/**").matches("/v1"));
        assert!(g("/v1/**").matches("/v1/"));
        assert!(g("/v1/**").matches("/v1/customers/cus_1/sources"));
        assert!(!g("/v1/**").matches("/v2/x"));
        assert!(g("/v1/*").matches("/v1/customers"));
        assert!(!g("/v1/*").matches("/v1"));
        assert!(!g("/v1/*").matches("/v1/customers/cus_1"));
        assert!(g("/v1/payment_intents/*/confirm").matches("/v1/payment_intents/pi_1/confirm"));
        assert!(!g("/v1/payment_intents/*/confirm").matches("/v1/payment_intents/confirm"));
        assert!(g("/**").matches("/"));
        assert!(g("/**").matches("/anything/at/all"));
        assert!(g("/").matches("/"));
        assert!(!g("/").matches("/x"));
        assert!(g("/a/**/z").matches("/a/z"));
        assert!(g("/a/**/z").matches("/a/b/c/z"));
        assert!(!g("/a/**/z").matches("/a/b/c"));
        // Query strings and repeated slashes are ignored.
        assert!(g("/v1/models").matches("/v1//models?x=1"));
        assert!(g("/v1/models").matches("/v1/models/"));
    }

    #[test]
    fn glob_parse_errors() {
        assert!(PathGlob::parse("v1/x").is_err());
        assert!(PathGlob::parse("/v1?x=1").is_err());
    }

    #[test]
    fn rule_parse_and_display() {
        let r = Rule::parse("post /v1/charges/").unwrap();
        assert_eq!(r.to_string(), "POST /v1/charges");
        assert!(r.matches("POST", "/v1/charges"));
        assert!(!r.matches("GET", "/v1/charges"));
        let any = Rule::parse("* /**").unwrap();
        assert!(any.matches("DELETE", "/x"));
        assert!(!any.matches("BREW", "/x"));
        assert!(Rule::parse("GET").is_err());
        assert!(Rule::parse("GET /a /b").is_err());
        assert!(Rule::parse("FETCH /a").is_err());
    }

    #[test]
    fn helpers() {
        assert!(g("/**").is_everything());
        assert!(!g("/v1/**").is_everything());
        assert_eq!(g("/v1/**").literal_prefix(), "/v1");
        assert_eq!(g("/**").literal_prefix(), "/");
        assert!(!g("/v1/models").has_wildcard());
    }
}
