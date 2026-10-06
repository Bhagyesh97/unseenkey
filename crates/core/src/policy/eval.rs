//! Pure policy evaluation.

use super::{ApprovalMode, Policy, Rule};

/// What is being attempted.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// HTTP method as sent.
    pub method: &'a str,
    /// Path without query string.
    pub path: &'a str,
    /// Destination host (no port).
    pub host: &'a str,
    /// Request body length, if known.
    pub body_len: Option<u64>,
    /// Caller id (`mcp:cursor`, `device:…`), if the transport authenticated one.
    pub caller: Option<&'a str>,
}

/// Counters the broker maintains per handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Requests in the last 60 s, not counting this one.
    pub last_minute: u32,
    /// Requests in the last 24 h, not counting this one.
    pub last_day: u32,
    /// Requests ever, not counting this one.
    pub total: u64,
}

/// Why a request was denied. Stable codes for audit and error bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// `expires_at` has passed.
    Expired,
    /// Caller not in `callers`.
    CallerNotAllowed,
    /// Host not in `upstreams`.
    HostNotAllowed,
    /// Body larger than `limits.max_body_bytes`.
    BodyTooLarge,
    /// Outside every schedule window.
    OutsideSchedule,
    /// A `deny` rule matched.
    DeniedByRule(Rule),
    /// No `allow` rule matched.
    NoMatchingRule,
    /// `requests_per_minute` reached.
    RateLimitedMinute,
    /// `requests_per_day` reached.
    RateLimitedDay,
    /// `requests_total` reached.
    TotalLimitReached,
}

impl DenyReason {
    /// Machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::Expired => "expired",
            DenyReason::CallerNotAllowed => "caller_not_allowed",
            DenyReason::HostNotAllowed => "host_not_allowed",
            DenyReason::BodyTooLarge => "body_too_large",
            DenyReason::OutsideSchedule => "outside_schedule",
            DenyReason::DeniedByRule(_) => "policy_denied",
            DenyReason::NoMatchingRule => "policy_denied",
            DenyReason::RateLimitedMinute | DenyReason::RateLimitedDay => "rate_limited",
            DenyReason::TotalLimitReached => "total_limit_reached",
        }
    }

    /// Human text for the caller. Never reveals the full policy.
    pub fn message(&self) -> String {
        match self {
            DenyReason::Expired => "this access has expired".into(),
            DenyReason::CallerNotAllowed => "this caller may not use this handle".into(),
            DenyReason::HostNotAllowed => "this secret may not be sent to that host".into(),
            DenyReason::BodyTooLarge => "request body exceeds the allowed size".into(),
            DenyReason::OutsideSchedule => "outside the allowed hours".into(),
            DenyReason::DeniedByRule(r) => format!("not allowed by policy (rule: {r})"),
            DenyReason::NoMatchingRule => "not allowed by policy".into(),
            DenyReason::RateLimitedMinute => "too many requests this minute".into(),
            DenyReason::RateLimitedDay => "too many requests today".into(),
            DenyReason::TotalLimitReached => "the total request allowance is used up".into(),
        }
    }
}

/// What approval is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalScope {
    /// Approve this single request.
    ThisRequest,
    /// Approve this (method, allow-rule) pair once; the broker caches it.
    FirstUse(Rule),
    /// Approve because a listed path matched.
    Path(Rule),
}

/// The verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Proceed. Carries the allow rule that matched, for the audit log.
    Allow(Rule),
    /// Refuse.
    Deny(DenyReason),
    /// Ask the owner; carries the matched allow rule and the scope.
    NeedsApproval {
        /// Rule that would allow it.
        rule: Rule,
        /// What to ask for.
        scope: ApprovalScope,
    },
}

impl Decision {
    /// True for `Allow`.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

/// Evaluate `policy` for `req` at `now` given `usage`. Order of checks:
/// expiry, caller, host, body size, schedule, deny rules, allow rules, limits,
/// approval. Deny always wins; nothing here has side effects.
pub fn evaluate(policy: &Policy, req: &Request<'_>, now_unix_ms: i64, usage: Usage) -> Decision {
    if let Some(exp) = policy.expires_at {
        if now_unix_ms >= exp.0 {
            return Decision::Deny(DenyReason::Expired);
        }
    }
    if !policy.callers.is_empty() {
        match req.caller {
            Some(c) if policy.callers.iter().any(|a| a == c) => {}
            _ => return Decision::Deny(DenyReason::CallerNotAllowed),
        }
    }
    if !policy.upstreams.is_empty() && !host_allowed(&policy.upstreams, req.host) {
        return Decision::Deny(DenyReason::HostNotAllowed);
    }
    if let (Some(max), Some(len)) = (policy.limits.max_body_bytes, req.body_len) {
        if len > max {
            return Decision::Deny(DenyReason::BodyTooLarge);
        }
    }
    if let Some(s) = &policy.schedule {
        if !s.permits(now_unix_ms) {
            return Decision::Deny(DenyReason::OutsideSchedule);
        }
    }
    if let Some(d) = policy.deny.iter().find(|r| r.matches(req.method, req.path)) {
        return Decision::Deny(DenyReason::DeniedByRule(d.clone()));
    }
    let Some(rule) = policy
        .allow
        .iter()
        .find(|r| r.matches(req.method, req.path))
        .cloned()
    else {
        return Decision::Deny(DenyReason::NoMatchingRule);
    };
    if let Some(m) = policy.limits.requests_per_minute {
        if usage.last_minute >= m {
            return Decision::Deny(DenyReason::RateLimitedMinute);
        }
    }
    if let Some(d) = policy.limits.requests_per_day {
        if usage.last_day >= d {
            return Decision::Deny(DenyReason::RateLimitedDay);
        }
    }
    if let Some(t) = policy.limits.requests_total {
        if usage.total >= t {
            return Decision::Deny(DenyReason::TotalLimitReached);
        }
    }
    match policy.approval.mode {
        ApprovalMode::None => Decision::Allow(rule),
        ApprovalMode::EveryUse => Decision::NeedsApproval {
            rule,
            scope: ApprovalScope::ThisRequest,
        },
        ApprovalMode::FirstUse => {
            let scope = ApprovalScope::FirstUse(rule.clone());
            Decision::NeedsApproval { rule, scope }
        }
        ApprovalMode::Paths => {
            match policy
                .approval
                .paths
                .iter()
                .find(|p| p.matches(req.method, req.path))
            {
                Some(p) => Decision::NeedsApproval {
                    rule,
                    scope: ApprovalScope::Path(p.clone()),
                },
                None => Decision::Allow(rule),
            }
        }
    }
}

/// Host allow-list check, case-insensitive. A pattern is an exact host name
/// or contains `*` labels: a leading `*.` stands for one or more labels
/// (`*.example.com` covers `a.example.com` and `a.b.example.com`, never the
/// apex); a `*` label anywhere else stands for exactly one label
/// (`s3.*.amazonaws.com`).
pub fn host_allowed(allowed: &[String], host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let h_labels: Vec<&str> = h.split('.').collect();
    if h_labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    allowed.iter().any(|a| {
        let a = a.trim_end_matches('.').to_ascii_lowercase();
        if !a.contains('*') {
            return h == a;
        }
        let labels: Vec<&str> = a.split('.').collect();
        let (leading, rest) = match labels.split_first() {
            Some((&"*", rest)) => (true, rest),
            _ => (false, &labels[..]),
        };
        if rest.is_empty() {
            return false;
        }
        let fits = if leading {
            h_labels.len() > rest.len()
        } else {
            h_labels.len() == rest.len()
        };
        fits && rest
            .iter()
            .zip(&h_labels[h_labels.len() - rest.len()..])
            .all(|(pattern, label)| *pattern == "*" || pattern == label)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns_with_inner_wildcards() {
        let a = |p: &[&str], h: &str| {
            host_allowed(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>(), h)
        };
        // Unchanged behaviour.
        assert!(a(&["api.stripe.com"], "API.Stripe.com."));
        assert!(a(&["*.supabase.co"], "abc.supabase.co"));
        assert!(a(&["*.supabase.co"], "a.b.supabase.co"));
        assert!(!a(&["*.supabase.co"], "supabase.co"));
        assert!(!a(&["*.supabase.co"], "evilsupabase.co"));
        // A `*` label in the middle is exactly one label.
        assert!(a(&["s3.*.amazonaws.com"], "s3.us-east-1.amazonaws.com"));
        assert!(!a(&["s3.*.amazonaws.com"], "s3.amazonaws.com"));
        assert!(!a(&["s3.*.amazonaws.com"], "s3.a.b.amazonaws.com"));
        assert!(!a(
            &["s3.*.amazonaws.com"],
            "dynamodb.us-east-1.amazonaws.com"
        ));
        assert!(!a(
            &["s3.*.amazonaws.com"],
            "s3.us-east-1.amazonaws.com.evil.example"
        ));
        // Leading and inner together.
        assert!(a(
            &["*.s3.*.amazonaws.com"],
            "bucket.s3.eu-west-1.amazonaws.com"
        ));
        assert!(!a(&["*.s3.*.amazonaws.com"], "s3.eu-west-1.amazonaws.com"));
        // Degenerate patterns allow nothing.
        assert!(!a(&["*"], "example.com"));
        assert!(!a(&["*."], "example.com"));
        assert!(!a(&["a*.example.com"], "ab.example.com"));
        assert!(!a(&["*.example.com"], "a..example.com"));
    }
    use crate::policy::schedule::Window;
    use crate::policy::{Approval, Instant, Limits, Schedule};

    fn policy(toml: &str) -> Policy {
        Policy::from_toml(toml).unwrap()
    }

    fn req<'a>(method: &'a str, path: &'a str) -> Request<'a> {
        Request {
            method,
            path,
            host: "api.stripe.com",
            body_len: Some(100),
            caller: Some("mcp:cursor"),
        }
    }

    const NOW: i64 = 1_800_000_000_000; // 2027-01-15T08:00:00Z

    #[test]
    fn empty_policy_denies_everything() {
        let p = Policy::default();
        assert_eq!(
            evaluate(&p, &req("GET", "/"), NOW, Usage::default()),
            Decision::Deny(DenyReason::NoMatchingRule)
        );
    }

    #[test]
    fn allow_and_deny_precedence() {
        let p = policy(
            "allow = [\"GET /v1/**\", \"POST /v1/payment_intents\"]\ndeny = [\"* /v1/payouts/**\", \"GET /v1/secrets\"]",
        );
        assert!(evaluate(&p, &req("GET", "/v1/customers"), NOW, Usage::default()).is_allow());
        assert!(evaluate(
            &p,
            &req("POST", "/v1/payment_intents"),
            NOW,
            Usage::default()
        )
        .is_allow());
        assert_eq!(
            evaluate(&p, &req("POST", "/v1/refunds"), NOW, Usage::default()),
            Decision::Deny(DenyReason::NoMatchingRule)
        );
        match evaluate(&p, &req("GET", "/v1/payouts/po_1"), NOW, Usage::default()) {
            Decision::Deny(DenyReason::DeniedByRule(r)) => {
                assert_eq!(r.to_string(), "* /v1/payouts/**")
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            evaluate(&p, &req("GET", "/v1/secrets"), NOW, Usage::default()),
            Decision::Deny(DenyReason::DeniedByRule(_))
        ));
        // The matched allow rule is reported.
        match evaluate(&p, &req("GET", "/v1/x"), NOW, Usage::default()) {
            Decision::Allow(r) => assert_eq!(r.to_string(), "GET /v1/**"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn expiry_caller_host_body_schedule_order() {
        let mut p = policy(
            "allow = [\"* /**\"]\nupstreams = [\"api.stripe.com\"]\ncallers = [\"mcp:cursor\"]",
        );
        p.limits = Limits {
            max_body_bytes: Some(10),
            ..Limits::default()
        };
        // Body too large.
        assert_eq!(
            evaluate(&p, &req("GET", "/"), NOW, Usage::default()),
            Decision::Deny(DenyReason::BodyTooLarge)
        );
        let small = Request {
            body_len: Some(5),
            ..req("GET", "/")
        };
        assert!(evaluate(&p, &small, NOW, Usage::default()).is_allow());
        // Unknown body length is not a size violation.
        let unknown = Request {
            body_len: None,
            ..req("GET", "/")
        };
        assert!(evaluate(&p, &unknown, NOW, Usage::default()).is_allow());
        // Wrong host.
        let other_host = Request {
            host: "evil.example",
            ..small
        };
        assert_eq!(
            evaluate(&p, &other_host, NOW, Usage::default()),
            Decision::Deny(DenyReason::HostNotAllowed)
        );
        // Wrong caller, and no caller at all.
        let other_caller = Request {
            caller: Some("mcp:other"),
            ..small
        };
        assert_eq!(
            evaluate(&p, &other_caller, NOW, Usage::default()),
            Decision::Deny(DenyReason::CallerNotAllowed)
        );
        let no_caller = Request {
            caller: None,
            ..small
        };
        assert_eq!(
            evaluate(&p, &no_caller, NOW, Usage::default()),
            Decision::Deny(DenyReason::CallerNotAllowed)
        );
        // Expired beats everything.
        p.expires_at = Some(Instant(NOW));
        assert_eq!(
            evaluate(&p, &small, NOW, Usage::default()),
            Decision::Deny(DenyReason::Expired)
        );
        p.expires_at = Some(Instant(NOW + 1));
        assert!(evaluate(&p, &small, NOW, Usage::default()).is_allow());
        p.expires_at = None;
        // Schedule: NOW is Friday 08:00 UTC.
        p.schedule = Some(Schedule {
            timezone: "UTC".into(),
            allowed: vec![Window::parse("Mon-Fri 09:00-17:00").unwrap()],
        });
        assert_eq!(
            evaluate(&p, &small, NOW, Usage::default()),
            Decision::Deny(DenyReason::OutsideSchedule)
        );
        assert!(evaluate(&p, &small, NOW + 3_600_000, Usage::default()).is_allow());
    }

    #[test]
    fn limits() {
        let p = policy("allow = [\"* /**\"]\n[limits]\nrequests_per_minute = 2\nrequests_per_day = 5\nrequests_total = 10");
        let r = req("GET", "/");
        assert!(evaluate(
            &p,
            &r,
            NOW,
            Usage {
                last_minute: 1,
                last_day: 1,
                total: 1
            }
        )
        .is_allow());
        assert_eq!(
            evaluate(
                &p,
                &r,
                NOW,
                Usage {
                    last_minute: 2,
                    last_day: 2,
                    total: 2
                }
            ),
            Decision::Deny(DenyReason::RateLimitedMinute)
        );
        assert_eq!(
            evaluate(
                &p,
                &r,
                NOW,
                Usage {
                    last_minute: 0,
                    last_day: 5,
                    total: 5
                }
            ),
            Decision::Deny(DenyReason::RateLimitedDay)
        );
        assert_eq!(
            evaluate(
                &p,
                &r,
                NOW,
                Usage {
                    last_minute: 0,
                    last_day: 0,
                    total: 10
                }
            ),
            Decision::Deny(DenyReason::TotalLimitReached)
        );
        // Limits apply only to otherwise-allowed requests: a denied path is still "policy_denied".
        let p2 = policy("allow = [\"GET /a\"]\n[limits]\nrequests_per_minute = 0");
        assert_eq!(
            evaluate(&p2, &req("GET", "/b"), NOW, Usage::default()),
            Decision::Deny(DenyReason::NoMatchingRule)
        );
    }

    #[test]
    fn approval_modes() {
        let mut p = policy("allow = [\"* /v1/**\"]");
        p.approval = Approval {
            mode: ApprovalMode::EveryUse,
            ..Approval::default()
        };
        assert!(matches!(
            evaluate(&p, &req("GET", "/v1/x"), NOW, Usage::default()),
            Decision::NeedsApproval {
                scope: ApprovalScope::ThisRequest,
                ..
            }
        ));
        p.approval.mode = ApprovalMode::FirstUse;
        match evaluate(&p, &req("GET", "/v1/x"), NOW, Usage::default()) {
            Decision::NeedsApproval {
                scope: ApprovalScope::FirstUse(r),
                ..
            } => {
                assert_eq!(r.to_string(), "* /v1/**")
            }
            other => panic!("{other:?}"),
        }
        p.approval.mode = ApprovalMode::Paths;
        p.approval.paths = vec![Rule::parse("POST /v1/transfers/**").unwrap()];
        assert!(evaluate(&p, &req("GET", "/v1/x"), NOW, Usage::default()).is_allow());
        assert!(matches!(
            evaluate(
                &p,
                &req("POST", "/v1/transfers/tr_1"),
                NOW,
                Usage::default()
            ),
            Decision::NeedsApproval {
                scope: ApprovalScope::Path(_),
                ..
            }
        ));
        // Denied paths never reach approval.
        p.deny = vec![Rule::parse("POST /v1/transfers/**").unwrap()];
        assert!(matches!(
            evaluate(
                &p,
                &req("POST", "/v1/transfers/tr_1"),
                NOW,
                Usage::default()
            ),
            Decision::Deny(DenyReason::DeniedByRule(_))
        ));
    }

    #[test]
    fn host_wildcards() {
        let a = vec!["api.stripe.com".to_string(), "*.supabase.co".to_string()];
        assert!(host_allowed(&a, "API.STRIPE.COM"));
        assert!(host_allowed(&a, "api.stripe.com."));
        assert!(!host_allowed(&a, "stripe.com"));
        assert!(!host_allowed(&a, "evil-api.stripe.com"));
        assert!(host_allowed(&a, "abc.supabase.co"));
        assert!(host_allowed(&a, "a.b.supabase.co"));
        assert!(!host_allowed(&a, "supabase.co"));
        assert!(!host_allowed(&a, "notsupabase.co"));
        assert!(!host_allowed(&a, "supabase.co.evil.example"));
    }

    #[test]
    fn deny_reason_codes_and_messages_have_no_policy_dump() {
        let r = DenyReason::DeniedByRule(Rule::parse("POST /v1/refunds").unwrap());
        assert_eq!(r.code(), "policy_denied");
        assert!(r.message().contains("POST /v1/refunds"));
        assert_eq!(DenyReason::RateLimitedDay.code(), "rate_limited");
    }
}
