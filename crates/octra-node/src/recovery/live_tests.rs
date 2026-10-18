//! Full recovery supervisor with the real native host and signed TCP root peers.
//! Funding and peer claims are local fixtures; no public-chain qualification.
mod fixture;
mod grace;
mod http_prefix;
mod liveness;
mod vpn;
use fixture::{Fixture, EXTENSION, WAIT};
use octra_exex::{CheckpointStore, CommittedEpochSource, Sequence};
use octravpn_node::admission::SessionAuthority;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn configured_three_peer_attestation_refuses_two_matching_roots() {
    let mut fixture = Box::pin(Fixture::with_health(
        true,
        octra_node_protocol::consensus::health::Config {
            state_attest_min_peers: 3,
            ..octra_node_protocol::consensus::health::Config::default()
        },
    ))
    .await;
    let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
    let admission = fixture.node.vpn_authority(fixture.vpn.settlement.clone());
    fixture
        .wait(|| fixture.initial.wake().is_err() && fixture.authority.driver().unwrap().is_none())
        .await;
    let counts = fixture.query_counts();
    fixture.matching_roots(2);
    fixture
        .wait(|| {
            assert!(matches!(fixture.node.status(), crate::Status::Suspended(_)));
            assert!(fixture.authority.driver().unwrap().is_none());
            fixture
                .query_counts()
                .iter()
                .zip(&counts)
                .all(|(current, before)| *current >= before + 2)
        })
        .await;
    assert_eq!(fixture.swarm.peers().len(), 3);
    assert!(fixture.node.snapshot().is_err());
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .is_err());
    assert_eq!(http.get(&fixture.page).send().await.unwrap().status(), 503);
    assert!(fixture
        .journal
        .max_round(
            fixture.node.store.chain().chain_id.as_bytes(),
            &fixture.address,
            2,
        )
        .unwrap()
        .is_none());
    assert!(fixture.initial.wake().is_err());
    assert_eq!(fixture.node.head().await.unwrap(), fixture.head);

    fixture.matching_roots(3);
    fixture
        .wait(|| {
            matches!(fixture.node.status(), crate::Status::Serving(_))
                && fixture.authority.driver().unwrap().is_some_and(|driver| {
                    driver.status().borrow().started && driver.status().borrow().voting
                })
        })
        .await;
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap()
        .live());
    circle_document(&http, &fixture).await;
    assert_history_unchanged(&fixture).await;
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn one_epoch_soft_lag_first_admission_precedes_unavailable_successor() {
    // These peers attest our genuine current root while claiming one newer
    // epoch. They hold no epoch2 record or certificate. This tests the initial
    // native soft-lag admission, not stable service with unavailable catch-up.
    let mut fixture = Box::pin(Fixture::soft_lag(true)).await;
    fixture
        .wait(|| {
            matches!(fixture.node.status(), crate::Status::Serving(_))
                && fixture.authority.driver().unwrap().is_some()
        })
        .await;
    assert!(!fixture.node.root_quarantined());
    assert!(fixture.initial.wake().is_err());
    for peer in &fixture.peers {
        assert_eq!(
            octra_node_runtime::epoch_roots::Host::state(&peer.authority)
                .await
                .unwrap()
                .head,
            2
        );
        assert_eq!(
            octra_node_runtime::epoch_roots::Host::root(&peer.authority, 1)
                .await
                .unwrap(),
            Some(fixture.head.cursor.state_root.0.to_vec())
        );
        assert!(matches!(
            octra_node_runtime::finality_queries::Host::lookup(&peer.authority, 2, 1)
                .await
                .unwrap(),
            octra_node_runtime::finality_queries::Range::NotFound
        ));
    }
    let admission = fixture.node.vpn_authority(fixture.vpn.settlement.clone());
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap()
        .live());
    assert_history_unchanged(&fixture).await;
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn failed_catchup_requires_consensus_recovery_and_hard_causes_survive_live_probes() {
    let mut fixture = Box::pin(Fixture::new(true)).await;
    let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
    let admission = fixture.node.vpn_authority(fixture.vpn.settlement.clone());
    fixture
        .wait(|| fixture.initial.wake().is_err() && fixture.authority.driver().unwrap().is_none())
        .await;
    // Signed current-root replies establish the native fault-tolerant target,
    // but these peers deliberately have no successor data. Lag2 uses soft
    // recovery without first installing a different quarantine cause.
    for peer in &fixture.peers {
        *peer.authority.advertised_head.lock().unwrap() = Some(3);
    }
    fixture.roots(Some(fixture.head.cursor.state_root.0));
    fixture
        .wait(|| matches!(fixture.node.status(), crate::Status::Suspended(ref reason) if reason.starts_with("catchup_failed:")))
        .await;
    assert!(fixture.node.root_quarantined());
    assert!(fixture.authority.driver().unwrap().is_none());
    assert_history_unchanged(&fixture).await;

    // Withdraw the old target. Two of four validators satisfy the independent
    // distinct-peer count, but cannot supply the three-signature consensus
    // proof required to recover a failed catch-up at the unchanged head.
    fixture.matching_roots(2);
    for peer in &fixture.peers {
        *peer.authority.advertised_head.lock().unwrap() = Some(1);
    }
    let counts = fixture.query_counts();
    fixture
        .wait(|| {
            assert!(fixture.node.root_quarantined());
            assert!(matches!(fixture.node.status(), crate::Status::Suspended(ref reason) if reason.starts_with("catchup_failed:")));
            assert!(fixture.authority.driver().unwrap().is_none());
            fixture.query_counts().iter().zip(&counts).all(|(now, before)| *now >= before + 2)
        })
        .await;
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .is_err());
    assert_eq!(http.get(&fixture.page).send().await.unwrap().status(), 503);
    assert!(fixture
        .journal
        .max_round(
            fixture.node.store.chain().chain_id.as_bytes(),
            &fixture.address,
            2
        )
        .unwrap()
        .is_none());

    fixture.matching_roots(3);
    fixture
        .wait(|| {
            !fixture.node.root_quarantined()
                && matches!(fixture.node.status(), crate::Status::Serving(_))
                && fixture.authority.driver().unwrap().is_some_and(|driver| {
                    driver.status().borrow().started && driver.status().borrow().voting
                })
        })
        .await;
    // Recovery without any epoch3 data proves the obsolete desired target was
    // cleared when the actual catch-up attempt failed.
    let permit = admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap();
    assert!(permit.live());
    circle_document(&http, &fixture).await;
    assert_history_unchanged(&fixture).await;

    let hard = "local_state_root_mismatch_at_head_1";
    assert!(fixture
        .node
        .quarantine_root_at(&fixture.head, hard)
        .await
        .unwrap());
    for peer in &fixture.peers {
        *peer.authority.advertised_head.lock().unwrap() = Some(8);
    }
    fixture
        .wait(|| fixture.authority.driver().unwrap().is_none())
        .await;
    let votes = fixture.vote_journal();
    let counts = fixture.query_counts();
    fixture
        .wait(|| {
            assert_eq!(fixture.node.status(), crate::Status::Suspended(hard.into()));
            fixture
                .query_counts()
                .iter()
                .zip(&counts)
                .all(|(now, before)| *now >= before + 2)
        })
        .await;
    // The supervisor has attempted lag7 quarantine. Later failure and in-sync
    // matching-root probes must retain the original hard cause as well.
    for peer in &fixture.peers {
        *peer.authority.advertised_head.lock().unwrap() = Some(1);
    }
    let counts = fixture.query_counts();
    fixture
        .wait(|| {
            assert_eq!(fixture.node.status(), crate::Status::Suspended(hard.into()));
            assert!(fixture.authority.driver().unwrap().is_none());
            fixture
                .query_counts()
                .iter()
                .zip(&counts)
                .all(|(now, before)| *now >= before + 2)
        })
        .await;
    assert!(!permit.live());
    assert!(!fixture.node.resume().await.unwrap());
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .is_err());
    assert_eq!(http.get(&fixture.page).send().await.unwrap().status(), 503);
    assert_eq!(fixture.vote_journal(), votes);
    assert_history_unchanged(&fixture).await;
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn canonical_forward_recovery_needs_new_publication_fresh_ticket_and_recoverable_cause() {
    let mut fixture = Box::pin(Fixture::new(false)).await;
    fixture.roots(Some(fixture.head.cursor.state_root.0));
    fixture
        .wait(|| matches!(fixture.node.status(), crate::Status::Serving(_)))
        .await;
    let (certificate, execution) = fixture.successor().await;
    fixture.tasks.stop().await;
    let start = fixture.node.head().await.unwrap();
    assert!(fixture
        .node
        .quarantine_root_at(&start, "catchup_failed:unavailable")
        .await
        .unwrap());
    let stale = fixture.node.root_quarantine_ticket();
    assert!(fixture
        .node
        .quarantine_root_at(&start, "lag_2")
        .await
        .unwrap());
    let ticket = fixture.node.root_quarantine_ticket();
    assert!(!fixture
        .node
        .complete_catchup_at(&start, &start, &ticket)
        .await
        .unwrap());
    let committed = fixture
        .node
        .publish(&start, &certificate, execution)
        .await
        .unwrap()
        .head;
    assert_eq!(
        committed.cursor.sequence,
        Sequence(start.cursor.sequence.0 + 1)
    );
    assert!(fixture.node.root_quarantined());
    assert!(!fixture
        .node
        .complete_catchup_at(&start, &committed, &stale)
        .await
        .unwrap());
    assert!(!fixture
        .node
        .complete_catchup_at(&start, &start, &ticket)
        .await
        .unwrap());
    let mut forged_start = start.clone();
    forged_start.cursor.state_root.0[0] ^= 1;
    assert!(!fixture
        .node
        .complete_catchup_at(&forged_start, &committed, &ticket)
        .await
        .unwrap());
    assert!(fixture
        .node
        .complete_catchup_at(&start, &committed, &ticket)
        .await
        .unwrap());
    assert!(!fixture.node.root_quarantined());
    assert!(
        fixture.node.snapshot().is_err(),
        "recovery evidence must not resume services itself"
    );
    let inactive = fixture.node.root_quarantine_ticket();
    assert!(fixture
        .node
        .complete_catchup_at(&start, &committed, &inactive)
        .await
        .unwrap());

    assert!(fixture
        .node
        .quarantine_root_at(&committed, "local_state_root_mismatch_at_head_2")
        .await
        .unwrap());
    assert!(!fixture
        .node
        .complete_catchup_at(&start, &committed, &ticket)
        .await
        .unwrap());
    let current = fixture.node.root_quarantine_ticket();
    assert!(!fixture
        .node
        .complete_catchup_at(&start, &committed, &current)
        .await
        .unwrap());
    assert!(fixture.node.root_quarantined());
    fixture
        .wait(|| fixture.epochs.lock().unwrap().len() == 2)
        .await;
    fixture.wait_checkpoint(committed.cursor).await;
    assert_eq!(
        fixture
            .checkpoints
            .load(fixture.node.store.chain(), EXTENSION)
            .await
            .unwrap(),
        Some(committed.cursor)
    );
    assert_eq!(
        fixture
            .node
            .publisher
            .record(start.cursor.sequence)
            .await
            .unwrap(),
        fixture.baseline
    );
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn verified_service_catchup_self_attests_without_successor_root_replies() {
    let mut fixture = Box::pin(Fixture::new(false)).await;
    fixture.roots(Some(fixture.head.cursor.state_root.0));
    fixture
        .wait(|| matches!(fixture.node.status(), crate::Status::Serving(_)))
        .await;
    let record = fixture.successor_record().await;
    assert_eq!(record.epoch_id, 2);
    assert!(fixture
        .node
        .quarantine_root_at(&fixture.head, "catchup_failed:fixture")
        .await
        .unwrap());
    for peer in &fixture.peers {
        peer.authority
            .withheld_root_epochs
            .lock()
            .unwrap()
            .insert(2);
        peer.authority
            .ranges
            .lock()
            .unwrap()
            .insert(2, record.clone());
        assert!(
            octra_node_runtime::epoch_roots::Host::root(&peer.authority, 2)
                .await
                .unwrap()
                .is_none()
        );
    }
    fixture.wait(|| matches!(fixture.node.status(), crate::Status::Serving(ref head) if head.cursor.epoch.0 == 2)).await;
    let committed = fixture.node.head().await.unwrap();
    assert_eq!(committed.cursor.sequence, Sequence(2));
    assert_eq!(committed.cursor.state_root.0.as_slice(), record.state_root);
    assert!(!fixture.node.root_quarantined());
    assert_eq!(
        fixture.node.publisher.record(Sequence(2)).await.unwrap(),
        record
    );
    fixture
        .wait(|| fixture.epochs.lock().unwrap().len() == 2)
        .await;
    fixture.wait_checkpoint(committed.cursor).await;
    assert_eq!(
        fixture
            .checkpoints
            .load(fixture.node.store.chain(), EXTENSION)
            .await
            .unwrap(),
        Some(committed.cursor)
    );
    let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
    assert_eq!(
        http.get(format!("{}/", fixture.browser))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(fixture
        .node
        .vpn_authority(fixture.vpn.settlement.clone())
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap()
        .live());
    for peer in &fixture.peers {
        assert!(
            octra_node_runtime::epoch_roots::Host::root(&peer.authority, 2)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!peer.authority.range_requests.lock().unwrap().is_empty());
    }
    assert_eq!(
        fixture.node.publisher.record(Sequence(1)).await.unwrap(),
        fixture.baseline
    );
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}

async fn assert_history_unchanged(fixture: &Fixture) {
    assert_eq!(fixture.node.head().await.unwrap(), fixture.head);
    assert_eq!(
        fixture
            .node
            .publisher
            .record(fixture.head.cursor.sequence)
            .await
            .unwrap(),
        fixture.baseline
    );
    assert_eq!(
        fixture
            .checkpoints
            .load(fixture.node.store.chain(), EXTENSION)
            .await
            .unwrap(),
        Some(fixture.head.cursor)
    );
    assert_eq!(fixture.epochs.lock().unwrap().len(), 1);
    assert!(fixture
        .node
        .store
        .source()
        .load(Sequence(2))
        .await
        .unwrap()
        .is_none());
}

async fn circle_document(http: &reqwest::Client, fixture: &Fixture) -> String {
    let shell = http
        .get(&fixture.page)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    let frame = shell
        .split_once("<iframe id=\"circle-content\"")
        .unwrap_or_else(|| panic!("Circle shell lacks its content frame: {shell}"))
        .1;
    let path = frame
        .split_once("src=\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();
    let document = reqwest::Url::parse(&fixture.page)
        .unwrap()
        .join(path)
        .unwrap()
        .to_string();
    assert_eq!(document, fixture.page.replacen("/view/", "/document/", 1));
    let response = http.get(&document).send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "canonical Circle document failed: {body}");
    assert!(
        body.contains("<body>Recovery Circle</body>"),
        "canonical Circle content missing from {document}: {body}"
    );
    document
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn connected_supervisor_requires_attestation_quarantines_conflict_and_recovers() {
    for voting in [false, true] {
        let mut fixture = Box::pin(Fixture::new(voting)).await;
        let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
        let admission = fixture.node.vpn_authority(fixture.vpn.settlement.clone());
        for peer in &fixture.peers {
            let state = octra_node_runtime::epoch_roots::Host::state(&peer.authority)
                .await
                .unwrap();
            assert_eq!(state.head, 1);
            assert!(
                octra_node_runtime::epoch_roots::Host::root(&peer.authority, 1)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        // A second root query proves the initial missing-root probe finished;
        // merely accepting TCP connections must not admit or start voting.
        fixture
            .wait(|| fixture.query_counts().iter().all(|count| *count >= 2))
            .await;
        assert!(matches!(fixture.node.status(), crate::Status::Suspended(_)));
        assert!(fixture.node.snapshot().is_err());
        assert!(admission
            .authorize(&fixture.vpn.request, &fixture.vpn.domain)
            .await
            .is_err());
        assert_eq!(
            http.get(format!("{}/", fixture.browser))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert!(fixture
            .journal
            .max_round(
                fixture.node.store.chain().chain_id.as_bytes(),
                &fixture.address,
                2
            )
            .unwrap()
            .is_none());
        assert!(
            fixture.initial.wake().is_err(),
            "unattested initial generation survived"
        );

        fixture.roots(Some(fixture.head.cursor.state_root.0));
        fixture
            .wait(|| {
                matches!(fixture.node.status(), crate::Status::Serving(_))
                    && (!voting
                        || fixture.authority.driver().unwrap().is_some_and(|driver| {
                            driver.status().borrow().started && driver.status().borrow().voting
                        }))
            })
            .await;
        let first_generation = fixture.authority.driver().unwrap();
        if voting {
            assert!(first_generation.is_some());
        } else {
            assert!(first_generation.is_none());
        }
        let permit = admission
            .authorize(&fixture.vpn.request, &fixture.vpn.domain)
            .await
            .unwrap()
            .unwrap();
        assert!(permit.live());
        assert_eq!(
            http.get(format!("{}/", fixture.browser))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let document = circle_document(&http, &fixture).await;

        // A single authenticated exaggerated head cannot displace the honest
        // current-head replies or repeatedly tear down healthy admission.
        let counts = fixture.query_counts();
        fixture.lie_about_head();
        fixture
            .wait(|| {
                assert!(
                    permit.live(),
                    "lone higher-head signer revoked healthy admission"
                );
                assert!(!fixture.node.root_quarantined());
                if let Some(driver) = &first_generation {
                    assert!(
                        driver.diagnostics().unwrap().is_some(),
                        "lone hint stopped the voting generation"
                    );
                }
                fixture
                    .query_counts()
                    .iter()
                    .zip(&counts)
                    .all(|(current, before)| *current >= before + 2)
            })
            .await;
        assert_eq!(fixture.node.head().await.unwrap(), fixture.head);

        fixture.roots(Some([0x88; 32]));
        fixture
            .wait(|| {
                fixture.node.root_quarantined() && fixture.authority.driver().unwrap().is_none()
            })
            .await;
        assert!(matches!(fixture.node.status(), crate::Status::Suspended(_)));
        assert!(!permit.live());
        assert!(admission
            .authorize(&fixture.vpn.request, &fixture.vpn.domain)
            .await
            .is_err());
        assert_eq!(
            http.get(format!("{}/", fixture.browser))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(http.get(&fixture.page).send().await.unwrap().status(), 503);
        assert_eq!(http.get(&document).send().await.unwrap().status(), 503);
        if let Some(driver) = &first_generation {
            assert!(
                driver.wake().is_err(),
                "quarantined voting task remained live"
            );
        }
        let signed_before = fixture
            .journal
            .max_round(
                fixture.node.store.chain().chain_id.as_bytes(),
                &fixture.address,
                2,
            )
            .unwrap();
        let vote_journal = fixture.vote_journal();
        let counts = fixture.query_counts();
        fixture
            .wait(|| {
                assert!(fixture.node.root_quarantined());
                assert!(fixture.authority.driver().unwrap().is_none());
                fixture
                    .query_counts()
                    .iter()
                    .zip(&counts)
                    .all(|(current, before)| *current > *before)
            })
            .await;
        assert_eq!(
            fixture
                .journal
                .max_round(
                    fixture.node.store.chain().chain_id.as_bytes(),
                    &fixture.address,
                    2
                )
                .unwrap(),
            signed_before,
            "quarantine signed more votes"
        );
        assert_eq!(
            fixture.vote_journal(),
            vote_journal,
            "quarantine changed durable vote statements"
        );
        assert!(!fixture.node.resume().await.unwrap());
        assert_eq!(fixture.node.head().await.unwrap(), fixture.head);

        fixture.roots(Some(fixture.head.cursor.state_root.0));
        fixture
            .wait(|| {
                !fixture.node.root_quarantined()
                    && matches!(fixture.node.status(), crate::Status::Serving(_))
                    && (!voting
                        || fixture.authority.driver().unwrap().is_some_and(|driver| {
                            driver.status().borrow().started && driver.status().borrow().voting
                        }))
            })
            .await;
        assert!(!permit.live(), "recovery revived a captured permit");
        assert!(admission
            .authorize(&fixture.vpn.request, &fixture.vpn.domain)
            .await
            .unwrap()
            .unwrap()
            .live());
        assert_eq!(
            http.get(format!("{}/", fixture.browser))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(circle_document(&http, &fixture).await, document);
        assert_eq!(
            fixture
                .node
                .publisher
                .record(fixture.head.cursor.sequence)
                .await
                .unwrap(),
            fixture.baseline
        );
        assert_eq!(
            fixture
                .checkpoints
                .load(fixture.node.store.chain(), EXTENSION)
                .await
                .unwrap(),
            Some(fixture.head.cursor)
        );
        assert_eq!(fixture.epochs.lock().unwrap().len(), 1);
        assert!(fixture
            .node
            .store
            .source()
            .load(Sequence(2))
            .await
            .unwrap()
            .is_none());
        assert_eq!(fixture.swarm.peers().len(), 3);
        fixture.tasks.stop().await;
        fixture.node.shutdown().await.unwrap();
        assert_eq!(fixture.node.head().await.unwrap(), fixture.head);
    }
}
