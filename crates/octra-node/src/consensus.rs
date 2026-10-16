//! Canonical publication for the live validator driver. Execution stays staged;
//! only a verified canonical transaction advances ExEx and application services.
use crate::{import::Executor, Host, Node, Status};
use octra_exex::Sequence;
use octra_node_protocol::consensus::{codec::Wire, Error, Finalize, ValidatorSet};
use octra_node_runtime::{
    bundle_queries::{Bundles, Host as BundleHost},
    consensus_driver::Publication,
};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc,
};
use tokio::sync::Mutex;

/// The driver owns the active canonical writer. Stop it before catch-up or
/// replacing this adapter; create a fresh adapter from the recovered head.
pub struct Canonical<A: Host, B: BundleHost, E: Executor> {
    node: Arc<Node<A>>,
    bundles: Bundles<B>,
    executor: E,
    timeout: f64,
    head: AtomicI64,
    restore_services: AtomicBool,
    importing: Mutex<()>,
    pending: Option<Arc<crate::executor::Pending>>,
}
impl<A: Host, B: BundleHost, E: Executor> Canonical<A, B, E> {
    pub async fn new(
        node: Arc<Node<A>>,
        bundles: Bundles<B>,
        executor: E,
        timeout: f64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            timeout.is_finite() && timeout > 0. && timeout <= 300.,
            "invalid consensus bundle timeout"
        );
        let head = i64::try_from(node.head().await?.cursor.epoch.0)?;
        Ok(Self {
            node,
            bundles,
            executor,
            timeout,
            head: AtomicI64::new(head),
            restore_services: AtomicBool::new(false),
            importing: Mutex::new(()),
            pending: None,
        })
    }
    /// Share the proposal queue with canonical publication. Durable confirmed
    /// transactions and recorded refusals retire only after authenticated commit.
    pub fn with_pending(mut self, pending: Arc<crate::executor::Pending>) -> Self {
        self.pending = Some(pending);
        self
    }
    async fn publish(&self, finalized: &Finalize) -> anyhow::Result<()> {
        let wire = finalized.encode()?;
        let head = self.node.head().await?;
        if finalized.epoch_id > 0 && head.cursor.epoch.0 == u64::try_from(finalized.epoch_id)? {
            // The previous callback may have been interrupted after the SQL
            // commit. Authenticate the retry using retained parent history and
            // compare the committed proposal, not a particular signer subset.
            let parent = self
                .node
                .store
                .retained_head(Sequence(
                    head.cursor
                        .sequence
                        .0
                        .checked_sub(1)
                        .ok_or_else(|| anyhow::anyhow!("cannot republish snapshot floor"))?,
                ))
                .await?;
            let verified = self
                .node
                .publisher
                .verify_certificate(&parent, &wire)
                .await?;
            let committed = self.node.publisher.record(head.cursor.sequence).await?;
            let proof = committed
                .finality
                .ok_or_else(|| anyhow::anyhow!("committed finality missing"))?;
            anyhow::ensure!(
                proof.finalize.proposal_id == verified.proposal_id
                    && proof.finalize.header == verified.header,
                "conflicting finalized retry"
            );
        } else {
            anyhow::ensure!(
                self.node
                    .import_finalized(&wire, &self.bundles, &self.executor, self.timeout)
                    .await?
                    .is_some(),
                "finalized bundle unavailable"
            );
        }
        if let Some(pending) = &self.pending {
            let sequence = self
                .node
                .store
                .sequence_for_epoch(u64::try_from(finalized.epoch_id)?)
                .await?
                .ok_or_else(|| anyhow::anyhow!("committed epoch unavailable"))?;
            let record = self.node.publisher.record(sequence).await?;
            let cursor = self.node.store.retained_head(sequence).await?.cursor;
            let pending = pending.clone();
            tokio::task::spawn_blocking(move || pending.committed(&record, cursor)).await??;
        }
        self.head.store(finalized.epoch_id, Ordering::Release);
        Ok(())
    }
}
#[async_trait::async_trait]
impl<A: Host, B: BundleHost, E: Executor + 'static> Publication for Canonical<A, B, E> {
    fn head_epoch(&self) -> i64 {
        self.head.load(Ordering::Acquire)
    }
    async fn finalized(
        &self,
        _validators: &ValidatorSet,
        finalized: &Finalize,
    ) -> Result<(), Error> {
        let _operation = self.importing.lock().await;
        let serving = matches!(self.node.status(), Status::Serving(_));
        if let Err(reason) = self.publish(finalized).await {
            if serving {
                self.restore_services.store(true, Ordering::Release);
            }
            self.node.suspend("canonical consensus publication failed");
            return Err(reason.to_string().into());
        }
        // A view/configuration failure leaves services suspended but cannot
        // turn an already durable canonical commit into a failed publication.
        if self.restore_services.swap(false, Ordering::AcqRel) {
            let _ = self.node.resume().await;
        }
        Ok(())
    }
    fn stopped(&self) {
        self.restore_services.store(false, Ordering::Release);
        self.node.suspend("consensus driver stopped");
    }
}
