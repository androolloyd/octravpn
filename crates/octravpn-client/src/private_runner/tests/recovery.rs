use super::*;
use std::time::Duration;

async fn fixture(code: u16) -> (Arc<Publisher>, Tls, Local, tempfile::TempDir) {
    let (mut plan, key, operator) = crate::payments::private::tests::plan();
    let publisher = Arc::new(Publisher::new(plan.clone(), operator, true));
    publisher.http_status.store(code, Ordering::SeqCst);
    let tls = Tls::serve(publisher.clone(), &mut plan).await;
    let root = tempfile::tempdir().unwrap();
    let local = Local::new(
        Options {
            plan,
            journal: root.path().join("private"),
            receipt_key: key,
            interface_name: "private-test0".into(),
            mode: OpenMode::Create,
        },
        None,
        1280,
    )
    .await
    .unwrap();
    (publisher, tls, local, root)
}

async fn calls(publisher: &Publisher, minimum: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while publisher.calls.load(Ordering::SeqCst) < minimum {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn temporary_status_recovers_the_exact_connection_without_new_capacity() {
    let (publisher, tls, local, _root) = fixture(503).await;
    let opening = tokio::spawn(local.connect());
    calls(&publisher, 1).await;
    assert!(!opening.is_finished());
    publisher.http_status.store(200, Ordering::SeqCst);
    let prepared = tokio::time::timeout(Duration::from_secs(3), opening)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(prepared.connect.request.sequence, 1);
    let Prepared {
        control,
        connect,
        plan,
        journal,
        status,
        ..
    } = prepared;
    let expected = serde_json::to_vec(&connect).unwrap();
    let before = publisher.calls.load(Ordering::SeqCst);
    publisher.http_status.store(503, Ordering::SeqCst);
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(monitor::run(
        control,
        connect,
        plan,
        journal.clone(),
        status,
        stopped,
    ));
    calls(&publisher, before + 1).await;
    assert!(!worker.is_finished());
    publisher.http_status.store(200, Ordering::SeqCst);
    calls(&publisher, before + 2).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(publisher
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r == &expected));
    assert_eq!(
        journal
            .with(|j| Ok(j.authorized_totals().to_vec()))
            .await
            .unwrap(),
        [128]
    );
    drop(journal);
    tls.close().await;
}

#[tokio::test]
async fn errors_and_repeated_old_status_cannot_renew_the_original_deadline() {
    for response in [503, 200] {
        let (publisher, tls, local, _root) = fixture(200).await;
        let Prepared {
            control,
            connect,
            plan,
            journal,
            mut status,
            ..
        } = local.connect().await.unwrap();
        // Model an observation already near its original 120s deadline.
        status.freshness.deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        publisher.http_status.store(response, Ordering::SeqCst);
        let (_stop, stopped) = watch::channel(false);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            monitor::run(control, connect, plan, journal, status, stopped),
        )
        .await
        .expect("old status or failure extended the deadline")
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("canonical clock stopped advancing"));
        assert!(publisher.calls.load(Ordering::SeqCst) >= 2);
        tls.close().await;
    }
}

#[tokio::test]
async fn an_authentication_refusal_is_not_retried() {
    let (publisher, tls, local, _root) = fixture(403).await;
    let error = local.connect().await.err().unwrap();
    assert!(!PrivateControl::retryable(&error));
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
    tls.close().await;
}
