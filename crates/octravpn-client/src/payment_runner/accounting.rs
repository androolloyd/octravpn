//! Track actual blocking journal work, rather than its cancellable async wait.
use crate::payments::Journal;
use anyhow::{ensure, Context, Result};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone)]
pub(super) struct Accounting {
    inner: Arc<Mutex<Journal>>,
    activity: watch::Sender<usize>,
}

struct InFlight(watch::Sender<usize>);
impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|active| *active -= 1);
    }
}

impl Accounting {
    pub(super) fn new(journal: Journal) -> Self {
        let (activity, _) = watch::channel(0);
        Self {
            inner: Arc::new(Mutex::new(journal)),
            activity,
        }
    }

    pub(super) async fn with<R, F>(&self, operation: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Journal) -> Result<R> + Send + 'static,
    {
        let mut registered = false;
        self.activity.send_modify(|active| {
            if let Some(next) = active.checked_add(1) {
                *active = next;
                registered = true;
            }
        });
        ensure!(registered, "payment journal operation count exhausted");
        let in_flight = InFlight(self.activity.clone());
        let journal = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            // Declaring the owned journal after this guard makes both its lock
            // and its Arc drop before the idle notification, including unwind.
            let _in_flight = in_flight;
            let owned_journal = journal;
            let outcome = operation(&mut owned_journal.lock());
            drop(owned_journal);
            outcome
        })
        .await
        .context("payment journal worker failed")?
    }

    /// The owner must first stop producers. This waits for already registered
    /// work, including workers whose async JoinHandle wait has been cancelled;
    /// it does not prevent a future caller from starting another operation.
    pub(super) async fn wait_idle(&self) -> Result<()> {
        let mut activity = self.activity.subscribe();
        activity
            .wait_for(|active| *active == 0)
            .await
            .map(|_| ())
            .context("payment journal activity channel closed")
    }

    #[cfg(test)]
    pub(super) fn lock(&self) -> parking_lot::MutexGuard<'_, Journal> {
        self.inner.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::OpenMode;
    use octravpn_core::{
        payments::{Deployment, PlanBinding, Tariff, TrafficClass},
        Address, KeyPair,
    };
    use std::time::Duration;

    fn journal(path: &std::path::Path) -> Journal {
        let key = Arc::new(KeyPair::from_secret_bytes(&[31; 32]));
        let tariff = Tariff::new(
            Address::from_pubkey(&[11; 32]),
            vec![TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: 1,
            }],
            vec![],
        )
        .unwrap();
        Journal::open(
            path,
            PlanBinding {
                deployment: Deployment {
                    domain: "ab".repeat(32),
                    program: Address::from_pubkey(&[2; 32]),
                },
                payer: Address::from_pubkey(&key.public.0),
                generation: 1,
                plan: 8,
                offer: 4,
                manifest_hash: tariff.hash_hex().unwrap(),
            },
            tariff,
            1000,
            key,
            OpenMode::Create,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn cancelling_the_async_wait_does_not_hide_running_journal_work() {
        let root = tempfile::tempdir().unwrap();
        let accounting = Accounting::new(journal(&root.path().join("journal")));
        let (entered, running) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let caller = {
            let accounting = accounting.clone();
            tokio::spawn(async move {
                accounting
                    .with(move |journal| {
                        let _ = entered.send(());
                        held.recv().context("fixture release closed")?;
                        journal.connect([42; 32])?;
                        Ok(())
                    })
                    .await
            })
        };
        running.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(*accounting.activity.borrow(), 1);
        let mut idle = {
            let accounting = accounting.clone();
            tokio::spawn(async move { accounting.wait_idle().await })
        };
        assert!(tokio::time::timeout(Duration::from_millis(25), &mut idle)
            .await
            .is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), idle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // The operation finished its fsync and released the journal owner even
        // though its original async caller never observed the result.
        assert_eq!(Arc::strong_count(&accounting.inner), 1);
        assert_eq!(
            accounting
                .lock()
                .connect([42; 32])
                .unwrap()
                .request
                .sequence,
            2
        );
    }
}
