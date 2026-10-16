//! Short facade capabilities. Signed local history never becomes BFT authority.
use super::Node;
use anyhow::{ensure, Result};
use octra_node_protocol::{
    registration_rpc::{self, PublicKey, Removal},
    rpc::Fault,
    state::Account,
    transaction::Transaction,
};
use octra_node_runtime::{account_store, canonical::Head, staging::Pool};
use std::sync::{atomic::Ordering, Arc};
/// A trusted serving adapter revokes current leases synchronously before COMMIT.
/// Callbacks may not block or re-enter the producer. Notification runs after the
/// owned operation lease is released, even if its original caller was cancelled.
pub(super) struct Notification {
    pub head: Head,
    pub hook: Arc<dyn PublicationHook>,
}
pub trait PublicationHook: Send + Sync {
    fn revoke(&self);
    fn committed(&self, head: &Head);
}
impl Node {
    /// Captured executor/configuration, never a second reconstructed profile.
    pub fn native_metrics(&self) -> Result<Vec<u8>> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(memory.failed.is_none(), "Single requires restart");
        Ok(memory.stats.to_json()?)
    }
    pub fn legacy_status(&self) -> Result<crate::LegacyStatus> {
        self.legacy_status_at(
            &self
                .store
                .cached_head()
                .ok_or_else(|| anyhow::anyhow!("Single cached head missing"))?,
        )
    }
    pub fn legacy_status_at(&self, head: &Head) -> Result<crate::LegacyStatus> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(memory.failed.is_none(), "Single requires restart");
        ensure!(
            &memory.legacy_head == head,
            "Single legacy observation head differs"
        );
        Ok(crate::LegacyStatus {
            epoch: memory.legacy_tree.epoch_id.get(),
            roots: memory.legacy_tree.root_count().get(),
        })
    }
    pub fn executor(&self) -> &crate::executor::Native {
        &self.native
    }
    pub fn settings(&self) -> &super::Settings {
        &self.settings
    }

    pub async fn set_publication_hook(&self, hook: Arc<dyn PublicationHook>) -> Result<()> {
        let _operation = self.operations.lock().await;
        ensure!(!self.stopped.load(Ordering::Acquire), "Single node stopped");
        // Installation never grants serving provenance: the adapter starts
        // suspended and captures/audits a committed view independently.
        let mut slot = self
            .hook
            .lock()
            .map_err(|_| anyhow::anyhow!("Single publication hook poisoned"))?;
        ensure!(slot.is_none(), "Single publication hook already installed");
        *slot = Some(hook);
        Ok(())
    }
    pub(super) fn revoke_publication(&self) -> Option<Arc<dyn PublicationHook>> {
        let installed = self
            .hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(hook) = installed.as_ref() {
            hook.revoke();
        }
        installed.clone()
    }
    pub(super) fn take_notification(&self) -> Option<Notification> {
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notification
            .take()
    }
    pub(super) fn flush_notification(&self, notification: Option<Notification>) {
        // Serialize against terminal shutdown revocation, not a producer lease.
        let _hook = self
            .hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.stopped.load(Ordering::Acquire) {
            if let Some(notification) = notification {
                notification.hook.committed(&notification.head);
            }
        }
    }
    pub fn inspect_pool<T>(&self, f: impl FnOnce(&Pool) -> T) -> Result<T> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(memory.failed.is_none(), "Single requires restart");
        Ok(f(&memory.queue.pool))
    }
    /// Native registration lives in the volatile Ledger view, only for an
    /// existing account. The accepted queue normalizes inline public keys, so
    /// restart never needs to persist this uncommitted overlay separately.
    pub async fn register_public_key(self: &Arc<Self>, request: PublicKey) -> Result<()> {
        self.owned("octra-single-register", move |node| {
            Box::pin(async move {
                ensure!(
                    octra_node_protocol::transaction::address_from_public_key(request.public_key())
                        == request.address(),
                    "Single registration key differs from address"
                );
                let decoded = octra_node_protocol::native_base64::decode(request.public_key())?;
                ensure!(
                    octra_node_protocol::network::public_key_safe(&decoded),
                    "Single registration key unsafe"
                );
                let (_, state) = node.store.snapshot().await?;
                if account_store::load(&state, request.address())?.is_some() {
                    let mut memory = node
                        .memory
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
                    ensure!(memory.failed.is_none(), "Single requires restart");
                    memory
                        .registered
                        .insert(request.address().to_vec(), request.public_key().to_vec());
                }
                Ok(())
            })
        })
        .await
    }
    /// Apply only to native Ledger-based account/auth routes. Canonical proofs,
    /// assets and funding queries must keep using the committed Store reader.
    pub fn account_for_read(
        &self,
        address: &[u8],
        mut committed: Option<Account>,
    ) -> Result<Option<Account>> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(memory.failed.is_none(), "Single requires restart");
        if let (Some(account), Some(key)) = (committed.as_mut(), memory.registered.get(address)) {
            account.public_key = Some(key.clone());
        }
        Ok(committed)
    }
    pub fn registered_key(&self, address: &[u8]) -> Result<Option<Vec<u8>>> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(memory.failed.is_none(), "Single requires restart");
        Ok(memory.registered.get(address).cloned())
    }
    /// Move the operator wallet lease into the owned admission worker before
    /// canonical account/nonce capture; caller cancellation cannot release it.
    pub async fn submit_operator(
        self: &Arc<Self>,
        tx: Transaction,
        now: f64,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<Vec<u8>> {
        self.owned("octra-single-operator", move |node| {
            Box::pin(async move {
                let _wallet = wallet;
                node.submit_inner(tx, now).await
            })
        })
        .await
    }
    pub async fn remove(self: &Arc<Self>, request: Removal) -> std::result::Result<Vec<u8>, Fault> {
        let result = self
            .owned("octra-single-remove", move |node| {
                Box::pin(async move {
                    let (head, _) = node.store.snapshot().await?;
                    let (mut candidate, revision) = {
                        let memory = node
                            .memory
                            .lock()
                            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
                        ensure!(memory.failed.is_none(), "Single requires restart");
                        (memory.queue.clone(), memory.revision)
                    };
                    let tx = candidate.pool.find(&request.hash).ok_or_else(|| {
                        anyhow::Error::new(RemovalFault(registration_rpc::staging_missing()))
                    })?;
                    request
                        .authorize(&tx.from)
                        .map_err(|error| anyhow::Error::new(RemovalFault(error)))?;
                    candidate
                        .pool
                        .remove_processed(std::slice::from_ref(&request.hash));
                    candidate.retire(&request.hash);
                    node.memory
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?
                        .failed = Some(
                        "Single removal publication in progress; restart if interrupted".into(),
                    );
                    let revision = node
                        .store
                        .save_queue(&head, revision, candidate.encode()?)
                        .await?;
                    let mut memory = node
                        .memory
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
                    memory.queue = candidate;
                    memory.revision = revision;
                    memory.failed = None;
                    let hash = std::str::from_utf8(&request.hash)?;
                    memory.inputs.remove(hash);
                    node.jobs.cancel(hash);
                    Ok(request.response())
                })
            })
            .await;
        result.map_err(|error| match error.downcast::<RemovalFault>() {
            Ok(error) => error.0,
            Err(error) => {
                Fault::new(110, b"backend unavailable").string_data(error.to_string().as_bytes())
            }
        })
    }
}
#[derive(Debug)]
struct RemovalFault(Fault);
impl std::fmt::Display for RemovalFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Single staging request refused")
    }
}
impl std::error::Error for RemovalFault {}
