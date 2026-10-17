use super::{assert_history_unchanged, circle_document, Fixture, WAIT};
use octravpn_node::admission::SessionAuthority;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn automatic_health_realigns_the_live_native_actor_without_republishing_state() {
    let started = tokio::time::Instant::now();
    let (mut fixture, clock) = Box::pin(Fixture::liveness()).await;
    fixture
        .wait(|| {
            matches!(fixture.node.status(), crate::Status::Serving(_))
                && fixture.authority.driver().unwrap().is_some_and(|driver| {
                    let status = driver.status();
                    let status = status.borrow();
                    status.started && status.voting && status.height == 2 && !status.finalized
                })
        })
        .await;
    let driver = fixture.authority.driver().unwrap().unwrap();
    assert!(fixture.initial.wake().is_err());
    let http = reqwest::Client::builder().timeout(WAIT).build().unwrap();
    let admission = fixture.node.vpn_authority(fixture.vpn.settlement.clone());
    let permit = admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap();
    assert!(permit.live());
    let document = circle_document(&http, &fixture).await;

    // Only recovery::Service queues health samples. Two fresh reads seed a
    // stable native state at 0 after the actual voting actor has started; the
    // test never calls Handle::poll_health or supplies synthetic role flags.
    clock.set(0);
    let samples = clock.reads();
    fixture.wait(|| clock.reads() >= samples + 2).await;
    let before = driver.status().borrow().clone();
    assert!(before.started && before.voting && !before.finalized);
    assert_eq!(before.height, 2);
    assert_eq!(before.round, 0);
    assert!(!fixture.node.root_quarantined());
    assert_eq!(fixture.journal.floor().unwrap(), Some(1));
    assert_history_unchanged(&fixture).await;

    let samples = clock.reads();
    clock.set(151);
    fixture
        .wait(|| {
            let status = driver.status();
            let status = status.borrow();
            clock.reads() > samples
                && status.started
                && status.voting
                && status.height == before.height
                && status.round == before.round + 1
                && !status.finalized
        })
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "the real 120s consensus timer could have advanced this round"
    );
    // The old handle still reaches a live actor: a supervisor replacement
    // closes its input channel, even if its last watch value looks healthy.
    driver.wake().unwrap();
    assert!(fixture.authority.driver().unwrap().is_some_and(|active| {
        let status = active.status();
        let status = status.borrow();
        status.started && status.voting && status.height == 2 && status.round == before.round + 1
    }));
    assert_eq!(fixture.journal.floor().unwrap(), Some(1));
    assert!(!fixture.node.root_quarantined());
    assert_eq!(fixture.node.snapshot().unwrap().head(), &fixture.head);
    assert_history_unchanged(&fixture).await;
    assert!(permit.live());
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .unwrap()
        .unwrap()
        .live());
    assert_eq!(circle_document(&http, &fixture).await, document);

    // A real Node root gate revokes both services and the supervisor-owned
    // voting actor. Matching signed peers cannot clear this hard cause, and
    // a later wall-clock jump cannot create a replacement or rewind history.
    let hard = "local_state_root_mismatch_at_head_1";
    assert!(fixture
        .node
        .quarantine_root_at(&fixture.head, hard)
        .await
        .unwrap());
    assert!(!permit.live());
    fixture
        .wait(|| fixture.authority.driver().unwrap().is_none() && driver.wake().is_err())
        .await;
    let votes = fixture.vote_journal();
    let samples = clock.reads();
    let queries = fixture.query_counts();
    clock.set(1000);
    fixture
        .wait(|| {
            assert_eq!(fixture.node.status(), crate::Status::Suspended(hard.into()));
            assert!(fixture.node.root_quarantined());
            assert!(fixture.authority.driver().unwrap().is_none());
            fixture
                .query_counts()
                .iter()
                .zip(&queries)
                .all(|(now, before)| *now >= before + 2)
        })
        .await;
    assert_eq!(clock.reads(), samples);
    assert_eq!(fixture.vote_journal(), votes);
    assert_eq!(fixture.journal.floor().unwrap(), Some(1));
    assert!(fixture.node.snapshot().is_err());
    assert!(!fixture.node.resume().await.unwrap());
    assert!(admission
        .authorize(&fixture.vpn.request, &fixture.vpn.domain)
        .await
        .is_err());
    assert_eq!(http.get(&fixture.page).send().await.unwrap().status(), 503);
    assert_eq!(http.get(&document).send().await.unwrap().status(), 503);
    assert_history_unchanged(&fixture).await;
    fixture.tasks.stop().await;
    fixture.node.shutdown().await.unwrap();
}
