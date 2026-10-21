use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Journal {
    book: tokio::sync::Mutex<()>,
    checks: AtomicUsize,
    revoke: AtomicBool,
}
impl Journal {
    fn new() -> Self {
        Self {
            book: tokio::sync::Mutex::new(()),
            checks: AtomicUsize::new(0),
            revoke: AtomicBool::new(false),
        }
    }
}
#[async_trait::async_trait]
impl super::super::funded::Journal for Journal {
    async fn check(&self) -> Result<()> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let _transaction = self.book.lock().await;
        ensure!(!self.revoke.load(Ordering::SeqCst), "route revoked");
        Ok(())
    }
    async fn network(&self) -> Result<Option<crate::PrivateRouteNetwork>> {
        unreachable!()
    }
    async fn armed(&self, _: &crate::PrivateRouteNetwork) -> Result<()> {
        unreachable!()
    }
    async fn released(&self) -> Result<()> {
        unreachable!()
    }
}

#[tokio::test(start_paused = true)]
async fn journal_check_cannot_stop_polling_the_opener_that_holds_its_book() {
    let journal = Journal::new();
    let mut workers = tokio::task::JoinSet::<(usize, Result<()>)>::new();
    let opened = async {
        let transaction = journal.book.lock().await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(journal.checks.load(Ordering::SeqCst) >= 2);
        drop(transaction);
        Ok(17)
    };
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        guarded_open(opened, &mut workers, &journal, None),
    )
    .await
    .expect("journal monitor blocked the future holding its connection")
    .unwrap();
    assert_eq!(result, 17);
    assert!(journal.book.try_lock().is_ok());
}

#[tokio::test(start_paused = true)]
async fn completion_cannot_overtake_a_queued_revocation_check() {
    let journal = Journal::new();
    let mut workers = tokio::task::JoinSet::<(usize, Result<()>)>::new();
    let opened = async {
        let transaction = journal.book.lock().await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(journal.checks.load(Ordering::SeqCst) >= 2);
        journal.revoke.store(true, Ordering::SeqCst);
        drop(transaction);
        Ok(17)
    };
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        guarded_open(opened, &mut workers, &journal, None),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("route revoked"));
    assert!(journal.book.try_lock().is_ok());
}

#[tokio::test(start_paused = true)]
async fn revoked_guard_cancels_opening_and_existing_worker_failure_wins() {
    let journal = Journal::new();
    let mut workers = tokio::task::JoinSet::<(usize, Result<()>)>::new();
    let opened = async {
        journal.revoke.store(true, Ordering::SeqCst);
        std::future::pending::<Result<()>>().await
    };
    assert!(guarded_open(opened, &mut workers, &journal, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("route revoked"));

    workers.spawn(async { (0, Err(anyhow::anyhow!("existing carrier stopped"))) });
    tokio::task::yield_now().await;
    let polled = AtomicBool::new(false);
    let opened = async {
        polled.store(true, Ordering::SeqCst);
        Ok(())
    };
    let error = guarded_open(opened, &mut workers, &journal, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("paid route hop 0 failed"));
    assert!(!polled.load(Ordering::SeqCst));
}
