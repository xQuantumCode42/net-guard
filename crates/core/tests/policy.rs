use netguard_core::*;
fn rule(target: Target, action: Action) -> Rule {
    Rule {
        id: "r1".into(),
        name: "test".into(),
        target,
        action,
        enabled: true,
        program: None,
        protocol: None,
        port: None,
        expires_at: None,
        source: None,
    }
}
fn flow(ip: &str, host: Option<&str>) -> Flow {
    Flow {
        remote_ip: ip.parse().unwrap(),
        remote_port: 443,
        protocol: 6,
        program: None,
        pid: Some(12),
        hostname: host.map(str::to_string),
        observed_at: 100,
        state: "observed".into(),
    }
}
#[test]
fn blocks_ipv4_and_ipv6_networks_but_not_neighbors() {
    for (cidr, inside, outside) in [
        ("192.0.2.0/24", "192.0.2.7", "192.0.3.7"),
        ("2001:db8::/32", "2001:db8::42", "2001:db9::42"),
    ] {
        let p = Policy {
            rules: vec![rule(Target::Network(cidr.parse().unwrap()), Action::Block)],
            ..Default::default()
        };
        assert_eq!(p.evaluate(&flow(inside, None), 100).action, Action::Block);
        assert_eq!(p.evaluate(&flow(outside, None), 100).action, Action::Allow);
    }
}
#[test]
fn ordered_exception_expires_at_boundary() {
    let mut allow = rule(Target::Ip("192.0.2.7".parse().unwrap()), Action::Allow);
    allow.id = "temporary".into();
    allow.expires_at = Some(101);
    let p = Policy {
        rules: vec![allow, rule(Target::Any, Action::Block)],
        ..Default::default()
    };
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", None), 100).rule_id.as_deref(),
        Some("temporary")
    );
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", None), 101).action,
        Action::Block
    );
}
#[test]
fn domain_matches_label_boundaries_and_idna() {
    let p = Policy {
        rules: vec![rule(
            Target::Subdomains("EXAMPLE.com.".into()),
            Action::Block,
        )],
        ..Default::default()
    };
    for host in ["example.com", "sub.example.com", "EXAMPLE.COM."] {
        assert_eq!(
            p.evaluate(&flow("192.0.2.7", Some(host)), 100).action,
            Action::Block
        );
    }
    for host in [None, Some("notexample.com"), Some("example.com.evil.test")] {
        assert_eq!(
            p.evaluate(&flow("192.0.2.7", host), 100).action,
            Action::Allow
        );
    }
    let p = Policy {
        rules: vec![rule(Target::Domain("bücher.example".into()), Action::Block)],
        ..Default::default()
    };
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", Some("xn--bcher-kva.example")), 100)
            .action,
        Action::Block
    );
}
#[test]
fn unknown_hostname_cannot_bypass_ip_block() {
    let mut allow = rule(Target::Domain("safe.example".into()), Action::Allow);
    allow.id = "allow".into();
    let p = Policy {
        rules: vec![allow, rule(Target::Any, Action::Block)],
        ..Default::default()
    };
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", None), 100).action,
        Action::Block
    );
}
#[test]
fn scoped_rule_requires_program_protocol_and_port() {
    let mut r = rule(Target::Any, Action::Block);
    r.program = Some("/usr/bin/curl".into());
    r.protocol = Some(6);
    r.port = Some(443);
    let p = Policy {
        rules: vec![r],
        ..Default::default()
    };
    let mut f = flow("192.0.2.7", None);
    assert_eq!(p.evaluate(&f, 100).action, Action::Allow);
    f.program = Some("/usr/bin/curl".into());
    assert_eq!(p.evaluate(&f, 100).action, Action::Block);
    f.remote_port = 80;
    assert_eq!(p.evaluate(&f, 100).action, Action::Allow);
}
#[test]
fn malformed_and_duplicate_rules_are_rejected() {
    for host in [
        "",
        "https://example.com/path",
        "a..example",
        "*.example.com",
        "192.0.2.1",
        "example.com:443",
    ] {
        let p = Policy {
            rules: vec![rule(Target::Domain(host.into()), Action::Block)],
            ..Default::default()
        };
        assert!(p.validate().is_err(), "must reject {host}");
    }
    let r = rule(Target::Any, Action::Block);
    assert!(Policy {
        rules: vec![r.clone(), r],
        ..Default::default()
    }
    .validate()
    .is_err());
}
#[test]
fn persistent_feed_exclusion_does_not_hide_manual_rule() {
    let mut feed = rule(Target::Any, Action::Block);
    feed.id = "feed:1".into();
    feed.source = Some("drop".into());
    let mut p = Policy {
        rules: vec![feed],
        exclusions: vec!["feed:1".into()],
    };
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", None), 100).action,
        Action::Allow
    );
    p.rules.push(rule(Target::Any, Action::Ask));
    assert_eq!(
        p.evaluate(&flow("192.0.2.7", None), 100).action,
        Action::Ask
    );
}
