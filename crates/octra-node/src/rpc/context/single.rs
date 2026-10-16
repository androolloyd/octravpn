//! Actual local Single capabilities. Signed local records authenticate these
//! archive reads; none implements BftHistory or supplies a quorum certificate.
use super::{http, Committed, Context, EpochData, Intake, LegacyStatus, Queue, ReadNode, Status};
use crate::single::facade::Facade;
use anyhow::Result;
use async_trait::async_trait;
use octra_exex::{ChainIdentity, CommittedEpochSource};
use octra_node_protocol::{
    epoch_journal::Summary,
    epoch_page,
    native_json::{Document, Value},
    registration_rpc,
    rpc::Fault,
    transaction::Transaction,
};
use octra_node_runtime::{
    admission,
    canonical::{self, single::Record, Head, ProgramRecords, Reader},
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
fn local_error(error: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(error.to_string())
}
pub(crate) struct Options {
    pub(crate) status: Arc<octra_node_runtime::status_read::Service>,
    pub(crate) http: Arc<http::Service>,
    pub(crate) fees: octra_node_protocol::submit_rpc::Fees,
    pub(crate) vpn_program: Option<String>,
}
impl Context {
    pub(crate) fn single(facade: Arc<Facade>, options: Options) -> Arc<Self> {
        let node = facade.node().clone();
        Arc::new(Self {
            node: facade.clone(),
            single: Some(node.clone()),
            finality: None,
            intake: facade,
            executor: node.executor().clone(),
            pending: Queue::Single(node.clone()),
            address: node.settings().wallet_address.clone(),
            compute: None,
            vpn_program: options.vpn_program,
            status: Some(options.status),
            tokens: Some(octra_node_runtime::token_rpc::Actor::new()),
            history_epoch_limit: 100,
            fees: options.fees,
            http: options.http,
        })
    }
}
#[async_trait]
impl ReadNode for Facade {
    fn snapshot(&self) -> Result<Committed> {
        self.snapshot()
    }
    async fn head(&self) -> Result<Head> {
        Ok(self.snapshot()?.head().clone())
    }
    fn reader(&self) -> Reader {
        self.node().store().reader()
    }
    fn chain(&self) -> &ChainIdentity {
        self.node().store().chain()
    }
    fn cached_head(&self) -> Option<Head> {
        self.snapshot().ok().map(|view| view.head().clone())
    }
    fn status(&self) -> Status {
        self.status()
    }
    fn legacy_status(&self) -> Result<LegacyStatus> {
        self.node().legacy_status()
    }
    fn legacy_status_at(&self, head: &Head) -> Result<LegacyStatus> {
        self.node().legacy_status_at(head)
    }
    fn native_metrics(&self) -> Result<Vec<u8>> {
        self.node().native_metrics()
    }
    fn program_records(&self) -> ProgramRecords {
        self.node().store().program_records()
    }
    fn account_for_read(
        &self,
        address: &[u8],
        committed: Option<octra_node_protocol::state::Account>,
    ) -> Result<Option<octra_node_protocol::state::Account>> {
        self.node().account_for_read(address, committed)
    }
    async fn vm_receipt(
        &self,
        head: &Head,
        hash: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, canonical::Error> {
        self.node().store().vm_receipt(head, hash).await
    }
    async fn epoch_data(&self, head: &Head) -> Result<EpochData> {
        let record = self.node().store().record(head.cursor.sequence).await?;
        anyhow::ensure!(record.head == *head, "local epoch head differs");
        let epoch = self
            .node()
            .store()
            .source()
            .load(head.cursor.sequence)
            .await?
            .ok_or_else(|| anyhow::anyhow!("local epoch events missing"))?;
        Ok(EpochData {
            hashes: epoch
                .events
                .iter()
                .map(|tx| tx.hash.as_bytes().to_vec())
                .collect(),
            outcomes: record.outcomes,
        })
    }
    async fn epoch_summary(&self, prefix: &Head, epoch: i64) -> Result<Option<Vec<u8>>> {
        let Some(record) = self.epoch_record(prefix, epoch).await? else {
            return Ok(None);
        };
        summary(&record)?.encode().map(Some).map_err(local_error)
    }
    async fn epoch_page_row(
        &self,
        prefix: &Head,
        epoch: i64,
    ) -> Result<Option<(epoch_page::Row, usize)>> {
        let Some(record) = self.epoch_record(prefix, epoch).await? else {
            return Ok(None);
        };
        let row = epoch_page::Row {
            epoch,
            root: hex::encode(record.head.cursor.state_root.0).into_bytes(),
            previous: hex::encode(record.parent.cursor.state_root.0).into_bytes(),
            tx_start: record
                .parent
                .txid_hi
                .checked_add(1)
                .ok_or_else(|| local_error("local epoch transaction index exhausted"))?,
            tx_count: record.head.txid_hi - record.parent.txid_hi,
            time: record.observation.finalized_at,
        };
        row.encode()
            .map_err(|fault| local_error(String::from_utf8_lossy(&fault.message)))?;
        // The local policy binds these exact fallback settings. Reconstruct the
        // native full-set reward attribution; this is not BFT membership proof.
        let members = self.node().settings().validators(epoch);
        let proposer = octra_node_protocol::single::proposer(
            epoch,
            &members
                .iter()
                .map(|(address, _)| address.clone())
                .collect::<Vec<_>>(),
            self.node().settings().fee_recipient.as_deref(),
            None,
        )
        .map_err(local_error)?;
        anyhow::ensure!(
            proposer.address == record.proposer,
            "local epoch proposer differs from captured policy"
        );
        let source = octra_node_protocol::consensus::reward_attribution::to_source(
            &octra_node_protocol::consensus::reward_attribution::full_set(
                &record.proposer,
                &members,
            ),
        )
        .map_err(local_error)?;
        let bytes = summary(&record)?
            .header(
                &row.previous,
                row.tx_start,
                &proposer.address,
                proposer.commit_round,
                &source,
            )
            .map_err(local_error)?
            .len();
        Ok(Some((row, bytes)))
    }
}
impl Facade {
    async fn epoch_record(&self, prefix: &Head, epoch: i64) -> Result<Option<Record>> {
        let store = self.node().store();
        let reader = store.reader();
        if reader.head_at(prefix.cursor.sequence).await? != *prefix {
            return Err(local_error("local epoch prefix differs"));
        }
        let Ok(epoch) = u64::try_from(epoch) else {
            return Ok(None);
        };
        if epoch == 0 || epoch > prefix.cursor.epoch.0 {
            return Ok(None);
        }
        let Some(head) = reader.head_for_epoch_opt(epoch).await? else {
            return Ok(None);
        };
        let record = store.record(head.cursor.sequence).await?;
        if record.head != head {
            return Err(local_error("local epoch record head differs"));
        }
        Ok(Some(record))
    }
}
// Own the encoded roots alongside the borrowed projection fields.
fn summary(record: &Record) -> Result<OwnedSummary<'_>> {
    let epoch = i64::try_from(record.head.cursor.epoch.0).map_err(local_error)?;
    Ok(OwnedSummary {
        record,
        epoch,
        root: hex::encode(record.head.cursor.state_root.0).into_bytes(),
    })
}
struct OwnedSummary<'a> {
    record: &'a Record,
    epoch: i64,
    root: Vec<u8>,
}
impl OwnedSummary<'_> {
    fn projection(&self) -> Summary<'_> {
        Summary {
            epoch: self.epoch,
            state_root: &self.root,
            parent_commit: &self.record.legacy_digest,
            tx_count: self.record.head.txid_hi - self.record.parent.txid_hi,
            finalized_by: &self.record.proposer,
            observation: &self.record.observation,
        }
    }
    fn encode(&self) -> std::result::Result<Vec<u8>, String> {
        self.projection().encode()
    }
    fn header(
        &self,
        previous: &[u8],
        start: i64,
        creator: &[u8],
        round: i64,
        source: &octra_node_protocol::consensus::RewardSource,
    ) -> std::result::Result<Vec<u8>, String> {
        self.projection()
            .header(previous, start, creator, round, source)
    }
}
#[async_trait]
impl Intake for Facade {
    async fn submit_native(
        &self,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, admission::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| admission::Error::Unavailable(e.to_string()))?
            .as_secs_f64();
        self.node().submit(tx, now).await.map_err(|error| {
            match error.downcast::<admission::Error>() {
                Ok(error) => error,
                Err(error) => admission::Error::Unavailable(error.to_string()),
            }
        })
    }
    async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()> {
        self.announce(hash, except).await
    }
    async fn submit_operator(
        &self,
        tx: Transaction,
        now: f64,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<()> {
        let hash = self.node().submit_operator(tx, now, wallet).await?;
        let _ = self.announce(hash, None).await;
        Ok(())
    }
    async fn remove(
        &self,
        request: registration_rpc::Removal,
    ) -> std::result::Result<Vec<u8>, Fault> {
        self.node().remove(request).await
    }
    async fn register_public_key(
        &self,
        doc: Arc<Document>,
        params: Value,
    ) -> std::result::Result<Vec<u8>, Fault> {
        let request = registration_rpc::PublicKey::parse(&doc, &params)?;
        let response = request.response();
        self.node()
            .register_public_key(request)
            .await
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        Ok(response)
    }
    fn peer_count(&self) -> usize {
        self.peer_count()
    }
}
