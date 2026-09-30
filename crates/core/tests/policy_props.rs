//! Property tests for the policy engine: never panics, deny wins, defaults deny.

use proptest::prelude::*;
use unseenkey_core::policy::{evaluate, Decision, DenyReason, Policy, Request, Rule, Usage};

fn seg() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        Just("**".to_string()),
        "[a-z_]{1,8}".prop_map(|s| s),
        "[a-z]{1,4}_[0-9]{1,3}".prop_map(|s| s),
    ]
}

fn pattern() -> impl Strategy<Value = String> {
    prop::collection::vec(seg(), 0..5).prop_map(|v| {
        if v.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", v.join("/"))
        }
    })
}

fn method() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "*",
    ])
}

fn rule() -> impl Strategy<Value = Rule> {
    (method(), pattern()).prop_map(|(m, p)| Rule::parse(&format!("{m} {p}")).unwrap())
}

fn concrete_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z_0-9]{1,8}", 0..6).prop_map(|v| format!("/{}", v.join("/")))
}

fn actual_method() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "BREW",
    ])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn evaluate_never_panics(
        allow in prop::collection::vec(rule(), 0..6),
        deny in prop::collection::vec(rule(), 0..6),
        m in actual_method(),
        path in concrete_path(),
        now in any::<i64>(),
        minute in any::<u32>(),
        total in any::<u64>(),
    ) {
        let p = Policy { allow, deny, ..Policy::default() };
        let req = Request { method: m, path: &path, host: "h", body_len: None, caller: None };
        let _ = evaluate(&p, &req, now, Usage { last_minute: minute, last_day: 0, total });
    }

    #[test]
    fn deny_rule_always_wins(
        allow in prop::collection::vec(rule(), 1..6),
        deny in prop::collection::vec(rule(), 1..6),
        m in actual_method(),
        path in concrete_path(),
    ) {
        let p = Policy { allow: allow.clone(), deny: deny.clone(), ..Policy::default() };
        let req = Request { method: m, path: &path, host: "h", body_len: None, caller: None };
        let d = evaluate(&p, &req, 0, Usage::default());
        let denied_by_rule = deny.iter().any(|r| r.matches(m, &path));
        let allowed_by_rule = allow.iter().any(|r| r.matches(m, &path));
        match d {
            Decision::Allow(_) => prop_assert!(!denied_by_rule && allowed_by_rule),
            Decision::Deny(DenyReason::DeniedByRule(_)) => prop_assert!(denied_by_rule),
            Decision::Deny(DenyReason::NoMatchingRule) => prop_assert!(!denied_by_rule && !allowed_by_rule),
            other => prop_assert!(false, "unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_methods_never_match(path in concrete_path(), pat in pattern()) {
        let r = Rule::parse(&format!("* {pat}")).unwrap();
        prop_assert!(!r.matches("BREW", &path));
        prop_assert!(!r.matches("", &path));
    }

    #[test]
    fn everything_pattern_matches_all_paths(path in concrete_path(), m in method()) {
        let r = Rule::parse(&format!("{m} /**")).unwrap();
        let concrete = if m == "*" { "GET" } else { m };
        prop_assert!(r.matches(concrete, &path));
    }

    #[test]
    fn rule_display_round_trips(r in rule()) {
        let again = Rule::parse(&r.to_string()).unwrap();
        prop_assert_eq!(again, r);
    }

    #[test]
    fn policy_toml_json_round_trip(
        allow in prop::collection::vec(rule(), 0..4),
        deny in prop::collection::vec(rule(), 0..4),
        rpm in prop::option::of(1u32..10_000),
        injection in any::<bool>(),
    ) {
        let mut p = Policy { allow, deny, injection, ..Policy::default() };
        p.limits.requests_per_minute = rpm;
        let t = Policy::from_toml(&p.to_toml()).unwrap();
        prop_assert_eq!(&t, &p);
        let j = Policy::from_json(&p.to_json()).unwrap();
        prop_assert_eq!(&j, &p);
    }

    #[test]
    fn garbage_text_never_panics_and_never_allows(text in "[ -~\\n]{0,200}") {
        if let Ok(p) = Policy::from_toml(&text) {
            // Whatever parsed, an empty allow list denies.
            if p.allow.is_empty() {
                let req = Request { method: "GET", path: "/", host: "h", body_len: None, caller: None };
                prop_assert!(matches!(evaluate(&p, &req, 0, Usage::default()), Decision::Deny(_)));
            }
        }
        let _ = Policy::from_json(&text);
    }
}
