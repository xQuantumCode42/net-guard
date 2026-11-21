use netguard_core::{feed::parse_drop, store::Store, *};
#[test]
fn drop_jsonl_keeps_networks_and_deduplicates() {
    let rules = parse_drop("{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\"}\n{\"cidr\":\"2001:db8::/32\"}\n{\"cidr\":\"192.0.2.0/24\"}\n{\"type\":\"metadata\",\"timestamp\":100}").unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].action, Action::Block);
    assert_eq!(rules[0].source.as_deref(), Some("spamhaus_drop"));
}
#[test]
fn corrupt_or_global_feed_is_rejected_atomically() {
    for input in [
        "",
        "<html>error</html>",
        "{\"cidr\":\"0.0.0.0/0\"}",
        "{\"cidr\":\"192.0.2.0/24\"}\nBAD",
        "{\"cidr\":\"::/0\"}",
    ] {
        assert!(parse_drop(input).is_err());
    }
}
#[test]
fn policy_survives_reopen_and_invalid_save_preserves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let rules = parse_drop("{\"cidr\":\"192.0.2.0/24\"}").unwrap();
    let p = Policy {
        exclusions: vec![rules[0].id.clone()],
        rules,
    };
    {
        let s = Store::open(&path).unwrap();
        s.save_policy(&p).unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.load_policy().unwrap().rules.len(), 1);
    assert_eq!(s.load_policy().unwrap().exclusions, p.exclusions);
    let mut invalid = p.clone();
    invalid.rules.push(invalid.rules[0].clone());
    assert!(s.save_policy(&invalid).is_err());
    assert_eq!(s.load_policy().unwrap().rules.len(), 1);
}
