//! The real recovery supervisor recreates a driver using captured file settings.
use super::*;
use octra_node_runtime::consensus_driver::GraceConfig;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn initial_and_recovered_driver_keep_the_same_captured_proposal_grace() {
    let values = crate::network_profile::parse_env(
        b"OCTRA_BFT_PROPOSAL_BUILD_GRACE_MS=0\nOCTRA_BFT_PROPOSAL_VERIFY_GRACE_MS=300000\n",
    )
    .unwrap();
    let profile = crate::network_profile::Profile::new(values).unwrap();
    let grace = GraceConfig::capture(|name| profile.settings.get(name).map(<[u8]>::to_vec));
    let mut fixture = Box::pin(Fixture::with_grace(grace)).await;
    assert_eq!(fixture.initial.grace_config(), grace);
    assert_eq!((grace.build_ms(), grace.verify_ms()), (0, 300_000));
    fixture
        .wait(|| fixture.initial.wake().is_err() && fixture.authority.driver().unwrap().is_none())
        .await;
    fixture.matching_roots(3);
    fixture
        .wait(|| {
            matches!(fixture.node.status(), crate::Status::Serving(_))
                && fixture
                    .authority
                    .driver()
                    .unwrap()
                    .is_some_and(|driver| driver.status().borrow().started)
        })
        .await;
    let recreated = fixture.authority.driver().unwrap().unwrap();
    assert_eq!(recreated.grace_config(), grace);
    assert!(fixture.initial.wake().is_err());
    super::assert_history_unchanged(&fixture).await;
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}
