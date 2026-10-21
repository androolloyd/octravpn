//! Open an existing spending index only after fresh canonical service resumes.
use crate::vpn::payments::shielded::{index::Index, Pool};
use anyhow::{ensure, Context, Result};
use octravpn_core::sealed::Key;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::OnceCell;

#[derive(Clone)]
pub struct Handle(Arc<Inner>);
struct Inner {
    source: Arc<Pool>,
    ready: OnceCell<Arc<Index>>,
    saved: Option<(PathBuf, Key)>,
}

#[cfg(test)]
pub(crate) async fn qualification<A: crate::Host>(
    node: &crate::Node<A>,
    path: PathBuf,
    key: Key,
    source: Arc<Pool>,
    expected: &octra_private_payments_experimental::pool::PoolIndex,
) {
    let deferred = Handle::resume(path, key, source).unwrap();
    node.suspend("deferred index resumes only after fresh canonical publication");
    {
        let reopening = deferred.get();
        tokio::pin!(reopening);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut reopening)
                .await
                .is_err()
        );
        assert!(deferred.opened().is_none());
        assert!(node.resume().await.unwrap());
        let index = tokio::time::timeout(Duration::from_secs(5), reopening)
            .await
            .unwrap()
            .unwrap();
        assert!(index.sync(128).await.unwrap().complete);
        assert_eq!(
            index.view().await.unwrap().index().roots(),
            expected.roots()
        );
    }
    deferred.close().await;
}
impl Handle {
    pub fn ready(index: Arc<Index>, source: Arc<Pool>) -> Result<Self> {
        ensure!(
            index.belongs_to(&source),
            "private index has another custody source"
        );
        Ok(Self(Arc::new(Inner {
            source,
            ready: OnceCell::new_with(Some(index)),
            saved: None,
        })))
    }
    pub(in crate::vpn::payments::shielded) fn opened(&self) -> Option<Arc<Index>> {
        self.0.ready.get().cloned()
    }
    pub(in crate::vpn::payments::shielded) async fn close(self) {
        // Shared owners keep their existing index. The final owner can close
        // its SQL worker before releasing the directory lease.
        if let Some(index) = Arc::into_inner(self.0)
            .and_then(|inner| inner.ready.into_inner())
            .and_then(Arc::into_inner)
        {
            index.close().await;
        }
    }
    /// Resume only: opening an index can never create a new empty baseline.
    pub fn resume(path: PathBuf, key: Key, source: Arc<Pool>) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        Ok(Self(Arc::new(Inner {
            source,
            ready: OnceCell::new(),
            saved: Some((path, key)),
        })))
    }
    pub(in crate::vpn::payments::shielded) fn belongs_to(&self, source: &Pool) -> bool {
        self.0.source.same_custody(source)
    }
    pub(in crate::vpn::payments::shielded) async fn get(&self) -> Result<Arc<Index>> {
        if let Some(index) = self.0.ready.get() {
            return Ok(index.clone());
        }
        let source = &self.0.source;
        let mut updates = source.directory.shared.1.subscribe();
        loop {
            // Publication can be revoked during the disk/history reads in
            // resume(), even after a fresh capture. Retry that whole attempt;
            // OnceCell retains only a successfully authenticated index.
            let resumed = self
                .0
                .ready
                .get_or_try_init(|| async {
                    crate::SnapshotLease::capture(source.directory.shared.clone())?
                        .with_current(crate::vpn::payments::PLAN_MAX_AGE, || Ok(()))?;
                    let (path, key) = self
                        .0
                        .saved
                        .as_ref()
                        .context("private index resume source missing")?;
                    Ok::<_, anyhow::Error>(Arc::new(
                        Index::resume(path, key.clone(), source.clone()).await?,
                    ))
                })
                .await;
            match resumed {
                Ok(index) => return Ok(index.clone()),
                Err(error) if !error.is::<crate::published::Unavailable>() => return Err(error),
                Err(_) => {}
            }
            tokio::select! {
                result=updates.changed()=>result.context("private node stopped before index resume")?,
                ()=tokio::time::sleep(Duration::from_millis(250))=>{},
            }
        }
    }
}
