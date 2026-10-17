//! Sequential finalized import from authenticated peers. The execution host
//! owns historical rules and staged ledger execution; publication rechecks the
//! certificate against its effects before advancing any service or ExEx.
use crate::{Host, Node, Publication};
use anyhow::{Context, Result};
use octra_node_protocol::consensus::{
    engine, hash, CatchupEpochRecord, EpochHeader, Finalize, RewardSource,
};
use octra_node_runtime::{
    bundle_queries::{Bundles, Host as BundleHost},
    canonical::Head,
    consensus_bundle::{self, RawBundle, Replay, Rules},
    execution_rules::Bound,
    finality::ExecutedEpoch,
    state_batch::StateBatch,
};

pub struct Execution<'a> {
    pub parent: &'a Head,
    pub state: StateBatch,
    pub finalized: &'a Finalize,
    pub reward_source: Option<&'a RewardSource>,
    pub bundle: Replay,
    pub rules: Bound,
}

#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    /// Captured trusted startup configuration, including the ready-config hash.
    fn graph(&self) -> octra_node_protocol::rules::Graph;
    fn rules(&self, parent: &Head, header: &EpochHeader, context: &Bound) -> Result<Rules>;
    /// Return staged effects only. Unsupported operations must fail without
    /// side effects; this callback cannot publish, emit ExEx, or admit tunnels.
    /// The authenticated certificate includes the parent participants needed
    /// for native reward attribution, beyond the header's state commitments.
    /// A supplied catch-up reward source has also passed native finality binding;
    /// use it for historical attribution and return it in the execution result.
    /// Execute the supplied partition and preserve the complete bundle receipts;
    /// ordinary rejection candidates must not contribute fees or state writes.
    async fn execute(&self, request: Execution<'_>) -> Result<ExecutedEpoch>;
}

impl<A: Host> Node<A> {
    /// Import one consecutive finalized epoch. None means no valid bundle was
    /// available before the deadline; canonical state and services stay at the
    /// current head. A competing commit causes publication to reject this base.
    pub async fn import_finalized<H: BundleHost>(
        &self,
        certificate: &[u8],
        peers: &Bundles<H>,
        executor: &impl Executor,
        timeout: f64,
    ) -> Result<Option<Publication>> {
        let (parent, state) = self.store.snapshot().await?;
        let (finalized, context) = self
            .publisher
            .verify_execution(&parent, certificate, &executor.graph())
            .await?;
        let header = &finalized.header;
        let rules = executor.rules(&parent, header, &context)?;
        let id = hash::proposal_id(header)?;
        let bundle = if let Some(raw) = peers.local(&id).await? {
            // A cache hit is not execution evidence. Bind every retained byte
            // again, exactly as for a signed peer response, before replay.
            consensus_bundle::finalized(header, &raw, &rules)?
        } else if header.tx_list_hash == engine::tx_list_hash_for_header(&[])
            && header.receipt_root == hash::receipt_root(&[])?
        {
            consensus_bundle::finalized(
                header,
                &RawBundle {
                    tx_hashes: vec![],
                    txs_json: vec![],
                    receipts_json: vec![],
                },
                &rules,
            )?
        } else if let Some((_, bundle)) = peers
            .query(header.epoch_id, id, timeout, |response| {
                Ok(consensus_bundle::finalized(header, &response.bundle, &rules).ok())
            })
            .await?
        {
            bundle
        } else {
            // Native finalized acquisition rechecks its cache after a
            // missed query: another proposal worker may have supplied
            // the exact bundle while the peer request was pending.
            let Some(raw) = peers.local(&id).await? else {
                return Ok(None);
            };
            consensus_bundle::finalized(header, &raw, &rules)?
        };
        let bundle = bundle.replay(rules.envelope)?;
        let executed = executor
            .execute(Execution {
                parent: &parent,
                state,
                finalized: &finalized,
                reward_source: None,
                bundle,
                rules: context,
            })
            .await
            .context("execute finalized bundle")?;
        self.publish(&parent, certificate, executed).await.map(Some)
    }

    /// Execute one complete catch-up record without fetching its bundle again.
    /// The optional historical reward source is authenticated before the host
    /// can use it, and the host must return that same canonical attribution.
    pub async fn import_record(
        &self,
        record: &CatchupEpochRecord,
        executor: &impl Executor,
    ) -> Result<Publication> {
        use octra_node_protocol::consensus::{codec::Wire, reward};
        let (parent, state) = self.store.snapshot().await?;
        let (finalized, context) = self
            .publisher
            .verify_record(&parent, record, &executor.graph())
            .await?;
        let rules = executor.rules(&parent, &finalized.header, &context)?;
        let bundle = consensus_bundle::finalized(
            &finalized.header,
            &RawBundle {
                tx_hashes: record.tx_hashes.clone(),
                txs_json: record.txs_json.clone(),
                receipts_json: record.receipts_json.clone(),
            },
            &rules,
        )?;
        let bundle = bundle.replay(rules.envelope)?;
        let source = record
            .reward_source
            .as_ref()
            .context("catch-up reward source missing")?;
        let executed = executor
            .execute(Execution {
                parent: &parent,
                state,
                finalized: &finalized,
                reward_source: Some(source),
                bundle,
                rules: context,
            })
            .await
            .context("execute catch-up record")?;
        anyhow::ensure!(
            reward::validate(&executed.reward_source)? == reward::validate(source)?,
            "execution reward attribution differs from catch-up source"
        );
        self.publish(&parent, &finalized.encode()?, executed).await
    }
}
