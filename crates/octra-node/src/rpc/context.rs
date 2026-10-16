//! Service capabilities independent of a validator-history type. The BFT
//! adapter delegates to the existing host; no RPC acquires a canonical writer.
use super::{http, Native, Pending, Submission};
use crate::{import::Executor as _, Committed, Host, LegacyStatus, Node, Status};
use anyhow::Result;
use async_trait::async_trait;
use octra_exex::{ChainIdentity, Sequence};
use octra_node_protocol::{
    consensus::{CatchupEpochRecord, ParentCommit},
    native_json::{Document, Value},
    registration_rpc,
    rpc::Fault,
    transaction::Transaction,
};
use octra_node_runtime::{
    admission,
    canonical::{self, Head, ProgramRecords, Reader},
    finality,
    staging::{DropRecord, Pool},
};
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[async_trait]
pub(crate) trait ReadNode: Send + Sync {
    fn snapshot(&self) -> Result<Committed>;
    async fn head(&self) -> Result<Head>;
    fn reader(&self) -> Reader;
    fn chain(&self) -> &ChainIdentity;
    fn cached_head(&self) -> Option<Head>;
    fn status(&self) -> Status;
    fn legacy_status(&self) -> Result<LegacyStatus>;
    fn legacy_status_at(&self, head: &Head) -> Result<LegacyStatus>;
    fn native_metrics(&self) -> Result<Vec<u8>>;
    fn program_records(&self) -> ProgramRecords;
    async fn vm_receipt(
        &self,
        head: &Head,
        hash: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, canonical::Error>;
}

/// This capability is deliberately distinct from a committed tree. A local
/// journal must never implement it by manufacturing a quorum certificate.
#[async_trait]
pub(crate) trait BftHistory: Send + Sync {
    fn checkpoint_parent(&self) -> Option<ParentCommit>;
    async fn readiness(&self, data: &Path, public_key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn record(
        &self,
        sequence: Sequence,
    ) -> std::result::Result<CatchupEpochRecord, finality::Error>;
    async fn record_bounded(
        &self,
        sequence: Sequence,
        maximum: usize,
    ) -> std::result::Result<Option<CatchupEpochRecord>, finality::Error>;
}

#[async_trait]
pub(crate) trait Intake: Send + Sync {
    async fn submit_native(
        &self,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, admission::Error>;
    async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()>;
    async fn submit_operator(
        &self,
        tx: Transaction,
        now: f64,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<()>;
    async fn remove(
        &self,
        request: registration_rpc::Removal,
    ) -> std::result::Result<Vec<u8>, Fault>;
    async fn register_public_key(
        &self,
        doc: Arc<Document>,
        params: Value,
    ) -> std::result::Result<Vec<u8>, Fault>;
    fn peer_count(&self) -> usize;
}

/// Read-only access to the real bounded staging pool. Mutation remains an
/// authenticated owned intake operation, never a callback through this handle.
#[derive(Clone)]
pub(crate) struct Queue(Arc<Pending>);
impl Queue {
    pub(crate) fn inspect<T>(&self, read: impl FnOnce(&Pool) -> T) -> Result<T> {
        self.0.inspect(read)
    }
    pub(crate) fn transactions(&self) -> Result<Vec<Transaction>> {
        self.0.transactions()
    }
    pub(crate) fn dropped(&self, hash: &[u8]) -> Result<Option<DropRecord>> {
        self.0.dropped(hash)
    }
    pub(crate) fn drops(&self, address: &[u8]) -> Result<Vec<DropRecord>> {
        self.0.drops(address)
    }
}

pub(crate) struct Context {
    pub(crate) node: Arc<dyn ReadNode>,
    pub(crate) finality: Arc<dyn BftHistory>,
    intake: Arc<dyn Intake>,
    pub(crate) executor: Native,
    pub(crate) pending: Queue,
    pub(crate) address: Vec<u8>,
    pub(crate) compute: Option<octra_node_runtime::compute_service::Service>,
    pub(crate) vpn_program: Option<String>,
    pub(crate) status: Option<Arc<octra_node_runtime::status_read::Service>>,
    pub(crate) tokens: Option<octra_node_runtime::token_rpc::Actor>,
    pub(crate) history_epoch_limit: i64,
    pub(crate) fees: octra_node_protocol::submit_rpc::Fees,
    pub(crate) http: Arc<http::Service>,
}
impl Context {
    pub(crate) async fn submit_native(
        &self,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, admission::Error> {
        self.intake.submit_native(tx).await
    }
    pub(crate) async fn submit(&self, tx: Transaction) -> Result<Vec<u8>> {
        self.submit_native(tx).await.map_err(anyhow::Error::new)
    }
    pub(crate) async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()> {
        self.intake.announce(hash, except).await
    }
    pub(crate) async fn submit_operator(
        &self,
        tx: Transaction,
        now: f64,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<()> {
        self.intake.submit_operator(tx, now, wallet).await
    }
    pub(crate) async fn remove(
        &self,
        request: registration_rpc::Removal,
    ) -> std::result::Result<Vec<u8>, Fault> {
        self.intake.remove(request).await
    }
    pub(crate) async fn register_public_key(
        &self,
        doc: Arc<Document>,
        params: Value,
    ) -> std::result::Result<Vec<u8>, Fault> {
        self.intake.register_public_key(doc, params).await
    }
    pub(crate) fn peer_count(&self) -> usize {
        self.intake.peer_count()
    }
}
impl<A: Host> Submission<A> {
    pub(crate) fn context(self: Arc<Self>) -> Arc<Context> {
        let read = Arc::new(BftNode(self.node.clone()));
        Arc::new(Context {
            node: read.clone(),
            finality: read,
            intake: self.clone(),
            executor: self.executor.clone(),
            pending: Queue(self.pending.clone()),
            address: self.address.clone(),
            compute: self.compute.clone(),
            vpn_program: self.vpn_program.clone(),
            status: self.status.clone(),
            tokens: self.tokens.clone(),
            history_epoch_limit: self.history_epoch_limit,
            fees: self.fees.clone(),
            http: self.http.clone(),
        })
    }
}
struct BftNode<A: Host>(Arc<Node<A>>);
#[async_trait]
impl<A: Host> ReadNode for BftNode<A> {
    fn snapshot(&self) -> Result<Committed> {
        self.0.snapshot()
    }
    async fn head(&self) -> Result<Head> {
        self.0.head().await
    }
    fn reader(&self) -> Reader {
        self.0.store.reader()
    }
    fn chain(&self) -> &ChainIdentity {
        self.0.store.chain()
    }
    fn cached_head(&self) -> Option<Head> {
        self.0.store.cached_head()
    }
    fn status(&self) -> Status {
        self.0.status()
    }
    fn legacy_status(&self) -> Result<LegacyStatus> {
        self.0.legacy_status()
    }
    fn legacy_status_at(&self, head: &Head) -> Result<LegacyStatus> {
        self.0.legacy_status_at(head)
    }
    fn native_metrics(&self) -> Result<Vec<u8>> {
        self.0.native_metrics()
    }
    fn program_records(&self) -> ProgramRecords {
        self.0.store.program_records()
    }
    async fn vm_receipt(
        &self,
        head: &Head,
        hash: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, canonical::Error> {
        self.0.store.vm_receipt(head, hash).await
    }
}
#[async_trait]
impl<A: Host> BftHistory for BftNode<A> {
    async fn readiness(&self, data: &Path, public_key: &[u8]) -> Result<Option<Vec<u8>>> {
        crate::consensus_join::read_verified(data, self.0.as_ref(), public_key).await
    }
    fn checkpoint_parent(&self) -> Option<ParentCommit> {
        self.0.store.checkpoint_parent()
    }
    async fn record(
        &self,
        sequence: Sequence,
    ) -> std::result::Result<CatchupEpochRecord, finality::Error> {
        self.0.publisher.record(sequence).await
    }
    async fn record_bounded(
        &self,
        sequence: Sequence,
        maximum: usize,
    ) -> std::result::Result<Option<CatchupEpochRecord>, finality::Error> {
        self.0.publisher.record_bounded(sequence, maximum).await
    }
}
#[async_trait]
impl<A: Host> Intake for Submission<A> {
    async fn submit_native(
        &self,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, admission::Error> {
        Self::submit_native(self, tx).await
    }
    async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()> {
        Self::announce(self, hash, except).await
    }
    async fn register_public_key(
        &self,
        doc: Arc<Document>,
        params: Value,
    ) -> std::result::Result<Vec<u8>, Fault> {
        Ok(registration_rpc::public_key_bft(&doc, &params))
    }
    async fn submit_operator(
        &self,
        tx: Transaction,
        now: f64,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<()> {
        let admission = Arc::new(
            self.node
                .admission_capture(&self.executor.graph(), self.policy, &self.address, now)
                .await?,
        );
        // Native's owned worker retains this same wallet lease through durable
        // staging even if the service caller or this adapter future is lost.
        let hash = self
            .executor
            .submit_operator(admission, &self.pending, tx, wallet)
            .await?;
        let _ = Self::announce(self, hash, None).await;
        (self.staging_notify)();
        Ok(())
    }

    fn peer_count(&self) -> usize {
        self.swarm.peers().len()
    }
    async fn remove(
        &self,
        request: registration_rpc::Removal,
    ) -> std::result::Result<Vec<u8>, Fault> {
        let unavailable = |_| Fault::new(110, b"service unavailable");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(unavailable)?
            .as_secs_f64();
        let admission = self
            .node
            .admission_capture(&self.executor.graph(), self.policy, &self.address, now)
            .await
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        let pending = self.pending.clone();
        let response = self
            .executor
            .read(move || {
                pending
                    .remove_authorized(admission.draft(), &request)
                    .map_err(|_| Fault::new(110, b"service unavailable"))??;
                Ok(request.response())
            })
            .await?;
        (self.staging_notify)();
        Ok(response)
    }
}
