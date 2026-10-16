//! Authenticate the local execution result before atomically publishing it.
//!
//! Validator history and execution are trusted host services. Neither is taken
//! from the peer's certificate. This boundary verifies persisted native QCs;
//! live voting, validator activation, transaction execution and catch-up outcome
//! admission remain the driver's responsibility.
pub mod history;
pub mod proposal;
mod vm_receipts;
use futures::TryStreamExt;
use num_bigint::BigInt;
use std::sync::Arc;

use octra_exex::{native_history::NativeTransaction, CommittedEpochSource, Sequence, StateRoot};
use octra_node_protocol::consensus::{
    catchup, codec::Wire, qc, relief::Mark, reward_attribution, CatchupEpochRecord,
    CatchupFinality, Finalize, RewardSource, ValidatorSet,
};
use octra_node_protocol::{
    native_json::Document, preverify_commit, transaction::Transaction, transaction_outcome,
};

use crate::{
    canonical::{self, AppliedEpoch, CanonicalStore, Head, PreparedCommit, ReliefSource},
    state_batch::Snapshot,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("finality: {0}")]
    Invalid(String),
    #[error("trusted validator history unavailable: {0}")]
    Authority(String),
    #[error("outcome verification unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Store(#[from] canonical::Error),
}
type Result<T> = std::result::Result<T, Error>;
fn invalid(error: impl std::fmt::Display) -> Error {
    Error::Invalid(error.to_string())
}

/// Resolve the epoch's authorized set from authenticated local configuration
/// and activation history at `parent`. Never resolve it from peer metadata.
/// Missing history is an operational failure; it cannot authorize a new set.
#[async_trait::async_trait]
pub trait ValidatorHistory: Send + Sync {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> std::result::Result<EpochRules, String>;
}

pub struct EpochRules {
    pub validators: ValidatorSet,
    pub receipts: ReceiptRules,
    /// Exact locally selected evidence, reauthenticated against parent metadata.
    /// The publisher retains it atomically; a peer cannot provide this field.
    pub relief: Option<Mark>,
}

#[derive(Clone)]
pub struct ReceiptRules {
    pub required: bool,
    pub crypto_active: bool,
    pub stealth_minimum: BigInt,
}

#[derive(Clone)]
pub struct ExecutedEpoch {
    /// Actual footer observations for native local epochlog queries. Missing
    /// historical material remains absent; it is never reconstructed as zero.
    pub epoch_observation: Option<octra_node_protocol::epoch_journal::Observation>,
    /// Observed execution work for local metrics; excluded from all commitments.
    pub metrics: octra_node_protocol::metrics::Epoch,
    pub state: Snapshot,
    pub transactions: Vec<NativeTransaction>,
    /// Auxiliary VM output for confirmed and rejected calls from this replay.
    /// It is retained locally and is not an additional consensus commitment.
    pub vm_receipts: crate::canonical::VmReceipts,
    /// Exact consensus outcome/preverification bytes produced or validated by
    /// execution. These are distinct from each transaction's VM receipt.
    pub consensus_receipts: Vec<Vec<u8>>,
    /// Attribution used by the execution footer, retained for native catch-up.
    pub reward_source: RewardSource,
    /// Local Irmin commit metadata; not fields in the epoch certificate.
    pub date: i64,
    pub message: Vec<u8>,
}

pub struct Publisher<A> {
    store: Arc<CanonicalStore>,
    authority: A,
}

impl<A: ValidatorHistory> Publisher<A> {
    /// Audit every retained epoch before enabling publication. Stores imported
    /// through the trusted raw storage API need their original finality and
    /// consensus receipts; missing evidence is never silently grandfathered in.
    pub async fn open(store: Arc<CanonicalStore>, authority: A) -> Result<Self> {
        let publisher = Self { store, authority };
        publisher.audit().await?;
        Ok(publisher)
    }

    /// Authenticate a consecutive certificate before spending resources on its
    /// bundle. Publication separately binds every field to local execution.
    async fn checked_certificate(
        &self,
        base: &Head,
        bytes: &[u8],
    ) -> Result<(Finalize, EpochRules)> {
        let finalized = decode(bytes)?;
        let epoch = next_epoch(base, &finalized)?;
        let rules = self.rules(base, epoch).await?;
        qc::validate_finalize(
            self.store.chain().chain_id.as_bytes(),
            &rules.validators,
            &finalized,
            qc::FinalityMode::Persisted,
        )
        .map_err(invalid)?;
        if finalized.header.prev_state_root != base.cursor.state_root.0 {
            return Err(invalid("finality previous root mismatch"));
        }
        Ok((finalized, rules))
    }

    async fn rules(&self, base: &Head, epoch: u64) -> Result<EpochRules> {
        let relief = self.store.reader().relief_after(base).await?;
        self.authority
            .resolve(base, epoch, relief)
            .await
            .map_err(Error::Authority)
    }

    pub async fn verify_certificate(&self, base: &Head, bytes: &[u8]) -> Result<Finalize> {
        self.checked_certificate(base, bytes)
            .await
            .map(|(certificate, _)| certificate)
    }

    /// Authenticate and bind execution against the same captured authority.
    /// A live relief journal may change while historical roots are read; it
    /// must not replace the membership that authenticated this certificate.
    pub async fn verify_execution(
        &self,
        base: &Head,
        bytes: &[u8],
        graph: &octra_node_protocol::rules::Graph,
    ) -> Result<(Finalize, crate::execution_rules::Bound)> {
        let (finalized, authority) = self.checked_certificate(base, bytes).await?;
        let bound = self
            .execution_rules(base, &finalized, &authority, graph)
            .await?;
        Ok((finalized, bound))
    }

    async fn execution_rules(
        &self,
        base: &Head,
        finalized: &Finalize,
        rules: &EpochRules,
        graph: &octra_node_protocol::rules::Graph,
    ) -> Result<crate::execution_rules::Bound> {
        if graph.chain_id() != self.store.chain().chain_id.as_bytes() {
            return Err(invalid("execution graph differs from canonical chain"));
        }
        let legacy = rules
            .validators
            .validators
            .iter()
            .map(|v| v.address.clone())
            .collect::<Vec<_>>();
        crate::execution_rules::Bound::canonical(graph, base, finalized, &legacy, self)
            .await
            .map(|bound| bound.capture(rules))
            .map_err(|e| Error::Authority(e.to_string()))
    }

    /// Authenticate peer record metadata at the actual committed parent. A
    /// source-agreed range is still untrusted until these per-epoch checks and
    /// local execution bind its effects to the QC. Execution uses the same
    /// authority captured for these checks.
    pub async fn verify_record(
        &self,
        base: &Head,
        record: &CatchupEpochRecord,
        graph: &octra_node_protocol::rules::Graph,
    ) -> Result<(Finalize, crate::execution_rules::Bound)> {
        let proof = record
            .finality
            .as_ref()
            .ok_or_else(|| invalid("catch-up finality missing"))?;
        let (finalized, rules) = self
            .checked_certificate(base, &proof.finalize.encode().map_err(invalid)?)
            .await?;
        let set = &rules.validators;
        let next_txid = base
            .txid_hi
            .checked_add(1)
            .and_then(|first| {
                i64::try_from(record.tx_hashes.len())
                    .ok()
                    .and_then(|count| first.checked_add(count))
            })
            .ok_or_else(|| invalid("transaction index exhausted"))?;
        catchup::verify_record_finality(
            self.store.chain().chain_id.as_bytes(),
            &octra_node_protocol::consensus::hash::validator_set_hash(set).map_err(invalid)?,
            next_txid,
            record,
        )
        .map_err(invalid)?;
        let reward = record
            .reward_source
            .as_ref()
            .ok_or_else(|| invalid("catch-up reward source missing"))?;
        reward_attribution::bind_finality(
            set,
            &finalized,
            &reward_attribution::of_source(reward).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let bound = self
            .execution_rules(base, &finalized, &rules, graph)
            .await?;
        Ok((finalized, bound))
    }

    pub async fn prepare(
        &self,
        base: &Head,
        certificate: &[u8],
        executed: ExecutedEpoch,
    ) -> Result<PreparedCommit> {
        let finalized = decode(certificate)?;
        let epoch = next_epoch(base, &finalized)?;
        let root = canonical::execution_root(base, epoch, &executed.state, &executed.transactions)?;
        let (_, relief, validators) = self
            .authenticate(
                base,
                &finalized,
                root,
                &executed.transactions,
                &executed.consensus_receipts,
                &executed.reward_source,
            )
            .await?;
        vm_receipts::validate(&executed)?;
        let mut prepared = self
            .store
            .prepare(
                base,
                AppliedEpoch {
                    epoch,
                    state: executed.state,
                    expected_root: root,
                    transactions: executed.transactions,
                    certificate: certificate.to_vec(),
                    date: executed.date,
                    message: executed.message,
                },
            )
            .await?;
        // Same SQLite transaction as state/history/ExEx. A failure or dropped
        // preparation rolls back all four, including initial schema creation.
        prepared
            .retain_consensus_receipts(&executed.consensus_receipts)
            .await?;
        prepared.retain_vm_receipts(&executed.vm_receipts).await?;
        prepared
            .retain_reward_source(&finalized.proposal_id, &executed.reward_source)
            .await?;
        prepared.retain_relief(relief.as_ref()).await?;
        if let Some(observation) = &executed.epoch_observation {
            prepared
                .retain_epoch_observation(&finalized, &validators, observation)
                .await?;
        }
        Ok(prepared)
    }

    /// Audit a fixed published suffix after a prefix already checked by this
    /// process. Restart still uses `audit` to recheck the entire retained chain.
    pub async fn audit_after(&self, after: Sequence) -> Result<Sequence> {
        if self
            .store
            .chain()
            .chain_id
            .starts_with("octra-single-local-")
            || self.store.is_single().await?
        {
            return Err(invalid("local Single store cannot provide BFT finality"));
        }
        let end = self.store.head().await?;
        if after.0 > end.cursor.sequence.0 {
            return Err(invalid("audited prefix exceeds canonical head"));
        }
        if after == end.cursor.sequence {
            return Ok(end.cursor.sequence);
        }
        futures::stream::iter(((after.0 + 1)..=end.cursor.sequence.0).map(Ok::<_, Error>))
            .try_for_each_concurrent(4, |number| async move {
                self.record(Sequence(number)).await.map(|_| ())
            })
            .await?;
        Ok(end.cursor.sequence)
    }

    /// Audit all retained epochs before startup publication or explicit
    /// operator verification.
    pub async fn audit(&self) -> Result<()> {
        self.audit_after(Sequence(0)).await.map(|_| ())
    }

    async fn authenticate(
        &self,
        base: &Head,
        finalized: &Finalize,
        state_root: StateRoot,
        transactions: &[NativeTransaction],
        receipts: &[Vec<u8>],
        reward: &RewardSource,
    ) -> Result<(CatchupEpochRecord, Option<Mark>, ValidatorSet)> {
        let epoch = next_epoch(base, finalized)?;
        let rules = self.rules(base, epoch).await?;
        let set = rules.validators;
        let expected_set =
            octra_node_protocol::consensus::hash::validator_set_hash(&set).map_err(invalid)?;
        reward_attribution::bind_finality(
            &set,
            finalized,
            &reward_attribution::of_source(reward).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let next_txid = base
            .txid_hi
            .checked_add(1)
            .and_then(|first| {
                i64::try_from(transactions.len())
                    .ok()
                    .and_then(|count| first.checked_add(count))
            })
            .ok_or_else(|| invalid("transaction index exhausted"))?;
        let mut parsed = Vec::with_capacity(transactions.len());
        for (offset, transaction) in transactions.iter().enumerate() {
            transaction.validate().map_err(invalid)?;
            if transaction.txid != base.txid_hi + 1 + offset as i64 {
                return Err(invalid("nonconsecutive transaction identifier"));
            }
            let document = Document::parse(&transaction.transaction).map_err(invalid)?;
            parsed.push(Transaction::from_document(&document).map_err(invalid)?);
        }
        // Reuse the native catch-up gates with commitments built from local
        // execution. The record's time, proposer and round come from the QC.
        let tx_hashes: Vec<_> = transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().to_vec())
            .collect();
        let record = CatchupEpochRecord {
            epoch_id: epoch as i64,
            prev_state_root: base.cursor.state_root.0.to_vec(),
            state_root: state_root.0.to_vec(),
            tx_list_hash: finalized.header.tx_list_hash.clone(),
            tx_hashes,
            txs_json: transactions
                .iter()
                .map(|tx| tx.transaction.clone())
                .collect(),
            receipt_root: finalized.header.receipt_root.clone(),
            receipts_json: receipts.to_vec(),
            epoch_ts: finalized.header.ts,
            creator_addr: finalized.header.creator_addr.clone(),
            commit_round: finalized.commit_round,
            reward_source: Some(
                octra_node_protocol::consensus::reward::validate(reward).map_err(invalid)?,
            ),
            finality: Some(CatchupFinality {
                finalize: finalized.clone(),
                validator_set: set.clone(),
            }),
        };
        let parsed_hashes = parsed
            .iter()
            .map(|tx| tx.hash().map(|hash| hash.to_vec()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(invalid)?;
        catchup::verify_record_hashes(&record, &parsed_hashes).map_err(invalid)?;
        catchup::verify_record_receipts(&record).map_err(invalid)?;
        let partition =
            transaction_outcome::decode(&parsed, receipts, false).map_err(|error| match error {
                transaction_outcome::Error::Rejected(error) => invalid(format!(
                    "catchup outcome mismatch epoch = {epoch} reason = {error}"
                )),
                transaction_outcome::Error::Unavailable(error) => Error::Unavailable(error),
            })?;
        if rules.receipts.required || !partition.preverify.is_empty() {
            preverify_commit::check_strings(
                &partition.preverify,
                &parsed,
                rules.receipts.crypto_active,
                &rules.receipts.stealth_minimum,
            )
            .map_err(|error| match error {
                preverify_commit::Error::Invalid(reason) => invalid(format!(
                    "catchup preverify mismatch epoch = {epoch} reason = {}",
                    String::from_utf8_lossy(&reason)
                )),
                preverify_commit::Error::Unavailable(reason) => Error::Unavailable(reason),
            })?;
        }
        catchup::verify_record_finality(
            self.store.chain().chain_id.as_bytes(),
            &expected_set,
            next_txid,
            &record,
        )
        .map_err(invalid)?;
        Ok((record, rules.relief, set))
    }

    /// Export a retained epoch only after rechecking its QC, execution
    /// commitments, receipt policy and historical reward binding.
    pub async fn record(&self, sequence: Sequence) -> Result<CatchupEpochRecord> {
        let previous = sequence
            .0
            .checked_sub(1)
            .ok_or_else(|| invalid("genesis has no finalized record"))?;
        let base = self.store.retained_head(Sequence(previous)).await?;
        let head = self.store.retained_head(sequence).await?;
        let epoch = self
            .store
            .source()
            .load(sequence)
            .await
            .map_err(invalid)?
            .ok_or_else(|| invalid("canonical outbox missing"))?;
        if epoch.cursor != head.cursor || epoch.parent_root != base.cursor.state_root {
            return Err(invalid("canonical outbox binding differs"));
        }
        let finalized = decode(&self.store.certificate(sequence).await?)?;
        if head.cursor.epoch.0 != next_epoch(&base, &finalized)? {
            return Err(invalid("retained epoch differs from finality"));
        }
        let receipts = self.store.consensus_receipts(sequence).await?;
        let (proposal, reward) = self.store.reward_source(sequence).await?;
        if proposal != finalized.proposal_id {
            return Err(invalid("retained reward proposal differs from finality"));
        }
        self.authenticate(
            &base,
            &finalized,
            head.cursor.state_root,
            &epoch.events,
            &receipts,
            &reward,
        )
        .await
        .map(|(record, _, _)| record)
    }

    /// A read-only allocation boundary for the native HTTP range service. The
    /// conservative database representation guards account for base64 archive
    /// identities and serde's integer-array receipt encoding. They do not alter
    /// accepted blocks or replace `record` authentication. Oversized auxiliary
    /// archive representations are operationally unavailable, not absent.
    pub async fn record_bounded(
        &self,
        sequence: Sequence,
        maximum: usize,
    ) -> Result<Option<CatchupEpochRecord>> {
        let retained = self.store.retained_head(sequence).await?;
        let lengths = self.store.reader().record_lengths(&retained).await?;
        let events = maximum
            .checked_mul(8)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .ok_or_else(|| Error::Unavailable("canonical archive read budget overflow".into()))?;
        let receipts = maximum
            .checked_mul(4)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .ok_or_else(|| Error::Unavailable("canonical receipt read budget overflow".into()))?;
        if lengths.events > events
            || lengths.receipts > receipts
            || lengths.certificate > 32 * 1024 * 1024
            || lengths.reward > 4 * 1024 * 1024
        {
            return Err(Error::Unavailable(
                "canonical archive exceeds bounded read budget".into(),
            ));
        }
        let record = self.record(sequence).await?;
        let mut size = 0usize;
        for raw in &record.txs_json {
            size = size
                .checked_add(64)
                .and_then(|n| n.checked_add(raw.len()))
                .ok_or_else(|| invalid("range response exceeds full limit"))?;
            if size > maximum {
                return Ok(None);
            }
        }
        Ok(Some(record))
    }
}

fn decode(bytes: &[u8]) -> Result<Finalize> {
    // Native catch-up finality frame limit; reject before parsing/allocation.
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(invalid("certificate exceeds native frame limit"));
    }
    Finalize::decode(bytes).map_err(invalid)
}

fn next_epoch(base: &Head, finalized: &Finalize) -> Result<u64> {
    let epoch = base
        .cursor
        .epoch
        .0
        .checked_add(1)
        .filter(|n| *n < (1u64 << 62) - 1)
        .ok_or_else(|| invalid("epoch exhausted"))?;
    if finalized.epoch_id != epoch as i64 {
        return Err(invalid("nonconsecutive finalized epoch"));
    }
    Ok(epoch)
}
