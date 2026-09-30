//! Plain-English rendering of a policy, so an owner can confirm what they grant.

use super::{ApprovalMode, Method, Policy, Rule};

fn method_words(m: Method) -> &'static str {
    match m {
        Method::Any => "do anything",
        Method::Get => "read",
        Method::Head => "check",
        Method::Post => "create or send",
        Method::Put => "replace",
        Method::Patch => "update",
        Method::Delete => "delete",
        Method::Options => "probe",
    }
}

/// `GET /v1/**` → "read anything under /v1"; `POST /v1/charges` → "create or send at /v1/charges".
pub fn describe_rule(r: &Rule) -> String {
    let verb = method_words(r.method);
    if r.path.is_everything() {
        return match r.method {
            Method::Any => "do anything".into(),
            _ => format!("{verb} anything"),
        };
    }
    let prefix = r.path.literal_prefix();
    match (r.method, r.path.has_wildcard()) {
        (Method::Any, true) => format!("do anything under {prefix}"),
        (Method::Any, false) => format!("do anything at {}", r.path.as_str()),
        (_, true) => format!("{verb} anything under {prefix}"),
        (_, false) => format!("{verb} at {}", r.path.as_str()),
    }
}

fn join_list(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        n => format!("{}, and {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn date_words(ms: i64) -> String {
    match jiff::Timestamp::from_millisecond(ms) {
        Ok(ts) => {
            let z = ts.to_zoned(jiff::tz::TimeZone::UTC);
            format!("{} {} {} (UTC)", z.day(), month_name(z.month()), z.year())
        }
        Err(_) => "an invalid date".into(),
    }
}

fn month_name(m: i8) -> &'static str {
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .get((m - 1).max(0) as usize)
    .copied()
    .unwrap_or("?")
}

/// Render the policy as short sentences, one per line.
pub fn explain(p: &Policy) -> String {
    let mut lines: Vec<String> = Vec::new();

    if p.allow.is_empty() {
        lines.push("Cannot do anything (no allow rules).".into());
    } else {
        let items: Vec<String> = p.allow.iter().map(describe_rule).collect();
        lines.push(format!("Can {}.", join_list(&items)));
    }
    if !p.deny.is_empty() {
        let items: Vec<String> = p.deny.iter().map(describe_rule).collect();
        lines.push(format!("Cannot {}.", join_list(&items)));
    }
    if !p.upstreams.is_empty() {
        lines.push(format!("Only to {}.", join_list(&p.upstreams)));
    }

    let mut caps: Vec<String> = Vec::new();
    if let Some(m) = p.limits.requests_per_minute {
        caps.push(format!("{} requests per minute", thousands(m as u64)));
    }
    if let Some(d) = p.limits.requests_per_day {
        caps.push(format!("{} per day", thousands(d as u64)));
    }
    if let Some(t) = p.limits.requests_total {
        caps.push(format!("{} in total", thousands(t)));
    }
    if !caps.is_empty() {
        lines.push(format!("At most {}.", join_list(&caps)));
    }
    if let Some(b) = p.limits.max_body_bytes {
        lines.push(format!(
            "Requests larger than {} are refused.",
            bytes_words(b)
        ));
    }
    if let Some(s) = &p.schedule {
        let windows: Vec<String> = s.allowed.iter().map(|w| w.describe()).collect();
        lines.push(format!("Only {} ({}).", join_list(&windows), s.timezone));
    }
    match p.expires_at {
        Some(e) => lines.push(format!("Expires {}.", date_words(e.0))),
        None => lines.push("Never expires.".into()),
    }
    match p.approval.mode {
        ApprovalMode::None => {}
        ApprovalMode::EveryUse => lines.push("Every use needs your approval.".into()),
        ApprovalMode::FirstUse => {
            lines.push("The first use of each kind of request needs your approval.".into())
        }
        ApprovalMode::Paths => {
            let items: Vec<String> = p.approval.paths.iter().map(describe_rule).collect();
            lines.push(format!("Needs your approval to {}.", join_list(&items)));
        }
    }
    if !p.callers.is_empty() {
        lines.push(format!("Usable only by {}.", join_list(&p.callers)));
    }
    if p.injection {
        lines.push(
            "May be injected as an environment variable (the program will see the value).".into(),
        );
    }
    if !p.mcp {
        lines.push("Hidden from AI agents (MCP).".into());
    }
    if let Some(n) = &p.notes {
        if !n.trim().is_empty() {
            lines.push(format!("Note: {}", n.trim()));
        }
    }
    lines.join("\n")
}

fn bytes_words(b: u64) -> String {
    if b >= 1 << 20 && b % (1 << 20) == 0 {
        format!("{} MiB", b >> 20)
    } else if b >= 1 << 10 && b % (1 << 10) == 0 {
        format!("{} KiB", b >> 10)
    } else {
        format!("{} bytes", thousands(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_rules() {
        let d = |s: &str| describe_rule(&Rule::parse(s).unwrap());
        assert_eq!(d("GET /v1/**"), "read anything under /v1");
        assert_eq!(
            d("POST /v1/payment_intents"),
            "create or send at /v1/payment_intents"
        );
        assert_eq!(d("* /**"), "do anything");
        assert_eq!(d("DELETE /**"), "delete anything");
        assert_eq!(d("* /v1/payouts/**"), "do anything under /v1/payouts");
        assert_eq!(
            d("POST /v1/payment_intents/*/confirm"),
            "create or send anything under /v1/payment_intents"
        );
    }

    #[test]
    fn full_explanation() {
        let p = Policy::from_toml(
            r#"
upstreams = ["api.stripe.com"]
allow = ["GET /v1/**", "POST /v1/payment_intents"]
deny = ["POST /v1/refunds"]
expires_at = "2026-12-31T00:00:00Z"
callers = ["mcp:cursor"]
[limits]
requests_per_minute = 120
requests_per_day = 5000
max_body_bytes = 1048576
[schedule]
timezone = "Asia/Kolkata"
allowed = ["Mon-Fri 09:00-19:00"]
[approval]
mode = "paths"
paths = ["POST /v1/transfers/**"]
"#,
        )
        .unwrap();
        let text = explain(&p);
        let expected = "\
Can read anything under /v1 and create or send at /v1/payment_intents.
Cannot create or send at /v1/refunds.
Only to api.stripe.com.
At most 120 requests per minute and 5,000 per day.
Requests larger than 1 MiB are refused.
Only Mon–Fri 09:00–19:00 (Asia/Kolkata).
Expires 31 Dec 2026 (UTC).
Needs your approval to create or send anything under /v1/transfers.
Usable only by mcp:cursor.";
        assert_eq!(text, expected);
    }

    #[test]
    fn empty_policy_explains_denial() {
        let text = explain(&Policy::default());
        assert!(text.starts_with("Cannot do anything"));
        assert!(text.contains("Never expires."));
    }

    #[test]
    fn helpers() {
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(bytes_words(2048), "2 KiB");
        assert_eq!(bytes_words(1500), "1,500 bytes");
        assert_eq!(
            join_list(&["a".into(), "b".into(), "c".into()]),
            "a, b, and c"
        );
    }
}
