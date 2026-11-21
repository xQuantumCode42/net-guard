#![cfg(windows)]
use netguard_core::*;
use netguard_platform::Backend;
use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

#[test]
#[ignore = "requires administrator; scoped to this test executable and its own loopback listener"]
fn wfp_blocks_own_loopback_connection_and_releases_on_drop() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    let baseline = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    drop(baseline);
    let policy = Policy {
        rules: vec![Rule {
            id: "native-test".into(),
            name: "NetGuard isolated loopback test".into(),
            target: Target::Ip(addr.ip()),
            action: Action::Block,
            enabled: true,
            program: Some(std::env::current_exe().unwrap().to_string_lossy().into()),
            protocol: Some(6),
            port: Some(addr.port()),
            expires_at: None,
            source: None,
        }],
        ..Default::default()
    };
    let mut backend =
        Backend::new().expect("Administrator token required for native WFP integration test");
    assert_eq!(backend.apply(&policy).unwrap().applied, 1);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_err(),
        "matching connection must be blocked"
    );
    drop(backend);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok(),
        "dynamic rules must be removed when engine closes"
    );
}
