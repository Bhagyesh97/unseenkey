//! Broker building blocks with no I/O: URL and host rules, header hygiene,
//! injection adapters ([`adapters`]) and the scrubber ([`scrub`]).
//!
//! The daemon composes these into the request pipeline described in
//! `docs/07-broker-and-policy.md`; keeping them here makes them unit-testable
//! and reusable by the hosted broker.

use crate::policy::eval::host_allowed;

pub mod adapters;
pub mod scrub;
pub mod sigv4;

/// Broker failures, mapped to HTTP error codes at the edge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The destination host is not allowed for this secret and policy.
    #[error("this secret may not be sent to {0}")]
    HostNotAllowed(String),
    /// Non-loopback upstream over plain HTTP.
    #[error("upstream must use https (plain http is allowed only for loopback)")]
    InsecureUpstream,
    /// Malformed upstream specification.
    #[error("invalid upstream {0:?}")]
    InvalidUpstream(String),
    /// The secret's shape does not fit the preset's auth style.
    #[error("secret is missing field {0:?} required by this provider")]
    MissingField(String),
    /// A template placeholder named a secret that does not exist or is not allowed.
    #[error("unknown or disallowed secret in placeholder {0:?}")]
    UnknownPlaceholder(String),
    /// Part of the request could not be parsed.
    #[error("malformed {0}")]
    Malformed(String),
}

impl BrokerError {
    /// Stable code for error bodies and audit.
    pub fn code(&self) -> &'static str {
        match self {
            BrokerError::HostNotAllowed(_) => "host_not_allowed",
            BrokerError::InsecureUpstream => "insecure_upstream",
            BrokerError::InvalidUpstream(_) => "invalid_upstream",
            BrokerError::MissingField(_) => "secret_shape",
            BrokerError::UnknownPlaceholder(_) => "unknown_placeholder",
            BrokerError::Malformed(_) => "malformed_request",
        }
    }
}

/// Headers that must never be copied from the caller to the upstream.
/// Hop-by-hop headers plus anything that could carry caller identity or a
/// competing credential.
pub const STRIP_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
    "expect",
    // The broker negotiates compression itself and unpacks what comes back,
    // so the scrubber sees plaintext. A caller's own choice would let the
    // provider answer in a form the scrubber cannot read.
    "accept-encoding",
    "x-usk-upstream",
    "x-usk-handle",
    "x-usk-caller",
];

/// Response headers not passed back to the caller.
pub const STRIP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "set-cookie",
    "content-length",
];

/// True for a header name in a strip list (case-insensitive).
pub fn is_stripped(name: &str, list: &[&str]) -> bool {
    list.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// A parsed upstream target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// `http` or `https`.
    pub scheme: String,
    /// Lower-case host, no port.
    pub host: String,
    /// Explicit port, if any.
    pub port: Option<u16>,
}

impl Upstream {
    /// Parse `host`, `host:port`, `https://host[:port]` or `http://host[:port]`.
    /// Plain `http` is accepted only for loopback hosts.
    pub fn parse(spec: &str) -> Result<Self, BrokerError> {
        let spec = spec.trim();
        let (scheme, rest) = match spec.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("https".to_string(), spec),
        };
        if scheme != "http" && scheme != "https" {
            return Err(BrokerError::InvalidUpstream(spec.into()));
        }
        let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
        if rest.is_empty() || rest.contains('@') || rest.contains(' ') {
            return Err(BrokerError::InvalidUpstream(spec.into()));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| BrokerError::InvalidUpstream(spec.into()))?;
                (h.trim_matches(['[', ']']).to_string(), Some(port))
            }
            _ => (rest.trim_matches(['[', ']']).to_string(), None),
        };
        let host = host.to_ascii_lowercase();
        if host.is_empty() {
            return Err(BrokerError::InvalidUpstream(spec.into()));
        }
        if scheme == "http" && !is_loopback_host(&host) {
            return Err(BrokerError::InsecureUpstream);
        }
        Ok(Self { scheme, host, port })
    }

    /// `https://host[:port]`.
    pub fn origin(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{}", self.scheme, self.host, p),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// `localhost`, `127.0.0.0/8`, `::1`.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']);
    h == "localhost" || h == "::1" || h.starts_with("127.")
}

/// The effective host allow-list: the secret's list, narrowed by the policy's
/// list when the policy has one. Every policy host must itself be covered by
/// the secret's list, otherwise the narrowing is invalid and nothing is allowed.
pub fn effective_hosts(secret_upstreams: &[String], policy_upstreams: &[String]) -> Vec<String> {
    if policy_upstreams.is_empty() {
        return secret_upstreams.to_vec();
    }
    let all_covered = policy_upstreams
        .iter()
        .all(|p| secret_upstreams.iter().any(|s| s == p) || host_allowed(secret_upstreams, p));
    if all_covered {
        policy_upstreams.to_vec()
    } else {
        Vec::new()
    }
}

/// Host-lock check (INV-2): may this secret be sent to `host`?
pub fn check_host(
    secret_upstreams: &[String],
    policy_upstreams: &[String],
    host: &str,
) -> Result<(), BrokerError> {
    let hosts = effective_hosts(secret_upstreams, policy_upstreams);
    if hosts.is_empty() || !host_allowed(&hosts, host) {
        return Err(BrokerError::HostNotAllowed(host.to_string()));
    }
    Ok(())
}

/// Split a request path-and-query into (path, query).
pub fn split_path_query(path_and_query: &str) -> (&str, Option<&str>) {
    match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_parsing() {
        let u = Upstream::parse("api.openai.com").unwrap();
        assert_eq!(
            (u.scheme.as_str(), u.host.as_str(), u.port),
            ("https", "api.openai.com", None)
        );
        assert_eq!(
            Upstream::parse("HTTPS://API.Stripe.com/v1/x?y")
                .unwrap()
                .origin(),
            "https://api.stripe.com"
        );
        assert_eq!(
            Upstream::parse("http://127.0.0.1:8080").unwrap().origin(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            Upstream::parse("http://localhost:3000/").unwrap().port,
            Some(3000)
        );
        assert_eq!(
            Upstream::parse("http://evil.example").unwrap_err(),
            BrokerError::InsecureUpstream
        );
        assert!(Upstream::parse("ftp://x").is_err());
        assert!(Upstream::parse("").is_err());
        assert!(Upstream::parse("user@host").is_err());
        assert!(Upstream::parse("host:notaport").is_err());
    }

    #[test]
    fn host_narrowing_and_lock() {
        let secret = vec!["api.stripe.com".to_string(), "*.supabase.co".to_string()];
        assert_eq!(effective_hosts(&secret, &[]), secret);
        assert_eq!(
            effective_hosts(&secret, &["api.stripe.com".to_string()]),
            vec!["api.stripe.com"]
        );
        assert_eq!(
            effective_hosts(&secret, &["abc.supabase.co".to_string()]),
            vec!["abc.supabase.co"]
        );
        assert!(
            effective_hosts(&secret, &["evil.example".to_string()]).is_empty(),
            "widening is void"
        );
        assert!(check_host(&secret, &[], "api.stripe.com").is_ok());
        assert!(check_host(&secret, &[], "xyz.supabase.co").is_ok());
        assert!(check_host(&secret, &[], "evil.example").is_err());
        assert!(check_host(&secret, &["evil.example".to_string()], "api.stripe.com").is_err());
        assert!(
            check_host(&[], &[], "api.stripe.com").is_err(),
            "no upstreams means nothing allowed"
        );
    }

    #[test]
    fn header_lists() {
        assert!(is_stripped("Authorization", STRIP_REQUEST_HEADERS));
        assert!(is_stripped("X-USK-Upstream", STRIP_REQUEST_HEADERS));
        assert!(!is_stripped("Content-Type", STRIP_REQUEST_HEADERS));
        assert!(is_stripped("Set-Cookie", STRIP_RESPONSE_HEADERS));
        assert_eq!(split_path_query("/v1/x?a=1"), ("/v1/x", Some("a=1")));
        assert_eq!(split_path_query("/v1/x"), ("/v1/x", None));
    }
}
