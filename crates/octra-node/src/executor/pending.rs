//! Queue ownership for proposal construction. Intake must use the native
//! staging admission path; construction rechecks every selected transaction.
use super::Native;
use crate::proposal::Draft;
use anyhow::{anyhow, Result};
use num_bigint::BigInt;
use octra_node_protocol::{
    control_payload::BondedReady,
    duty, resource_lanes,
    transaction::{self, OpType, RuleMode, Transaction},
    validator::{
        ready,
        set_fold::{self, State},
    },
};
use octra_node_runtime::{
    account_store,
    consensus_bundle::Rules,
    proposal_select,
    staging::{preview, DropRecord, Pool},
    state_batch::StateBatch,
};
use std::{
    collections::BTreeSet,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Pending {
    pool: Mutex<Pool>,
}
impl Pending {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool: Mutex::new(pool),
        }
    }
    pub fn transactions(&self) -> Result<Vec<Transaction>> {
        Ok(self
            .pool
            .try_lock()
            .map_err(|_| anyhow!("staging busy"))?
            .all()
            .cloned()
            .collect())
    }
    /// Called only with an authenticated durable record by canonical publication.
    /// Both confirmed work and recorded refusals are processed, as upstream.
    /// Removal is idempotent so a post-commit callback can be retried safely.
    pub(crate) fn committed(
        &self,
        record: &octra_node_protocol::consensus::CatchupEpochRecord,
    ) -> Result<()> {
        let transactions = record
            .txs_json
            .iter()
            .map(|raw| {
                Transaction::from_document(&octra_node_protocol::native_json::Document::parse(raw)?)
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        let partition = octra_node_protocol::transaction_outcome::decode(
            &transactions,
            &record.receipts_json,
            true,
        )?;
        let mut hashes = record.tx_hashes.clone();
        for rejection in partition.rejections {
            hashes.push(hex::encode(rejection.tx.hash()?).into_bytes());
        }
        self.pool
            .try_lock()
            .map_err(|_| anyhow!("staging busy"))?
            .remove_processed(&hashes);
        Ok(())
    }
    pub(super) fn capture(
        &self,
        draft: &Draft,
        rules: &Rules,
        capacity: &BigInt,
    ) -> Result<(Vec<Transaction>, Vec<Transaction>)> {
        let state = draft.state();
        let ledger = account_store::ledger(&StateBatch::from_snapshot(state.clone()))?;
        let context = draft.context();
        let epoch = context.header().epoch_id;
        let fold = context.rules().fold.context();
        let duty = state
            .get(&[b"meta", set_fold::META_KEY])
            .map_or_else(|| Some(State::default()), |raw| State::from_bytes(raw).ok());
        let parent = context.parent_commit().filter(|p| {
            p.certificate.epoch_id == epoch - 1
                && p.certificate.chain_id == context.header().chain_id
                && p.certificate.header.proposed_state_root == context.parent().cursor.state_root.0
        });
        draft.with_current(|| {
            let mut pool = self.pool.try_lock().map_err(|_| anyhow!("staging busy"))?;
            let mut accepted = BTreeSet::new();
            // Snapshot entries before mutating epoch-local preview markers.
            let entries: Vec<_> = pool.all().cloned().collect();
            for tx in entries {
                if fold.ready_exec_mode == RuleMode::Active && tx.op_type == OpType::ValidatorReady
                {
                    if duty::expired(&tx, Some(epoch - 1), RuleMode::Active) {
                        continue;
                    }
                    let Ok(claim) = BondedReady::parse(tx.message.as_deref()) else {
                        continue;
                    };
                    let Some((state, parent)) = duty.as_ref().zip(parent) else {
                        continue;
                    };
                    if ready::reference(
                        epoch,
                        claim.head_epoch,
                        claim.head_proposal_id.as_deref(),
                        Some(parent),
                        state,
                    )
                    .is_err()
                    {
                        continue;
                    }
                }
                let hash = hex::encode(tx.hash()?).into_bytes();
                if fold.proof_exec == RuleMode::Active
                    && pool
                        .preview(preview::Message::Ready(Some(epoch - 1), hash.clone()))
                        .is_err()
                {
                    continue;
                }
                if resource_lanes::queue_check(&tx, fold.proof_exec, &rules.stealth_minimum)
                    .is_err()
                    || transaction::check_compute(
                        rules.envelope.compute,
                        rules.envelope.settle,
                        std::slice::from_ref(&tx),
                    )
                    .is_err()
                    || transaction::check_envelopes(
                        rules.envelope.envelope,
                        std::slice::from_ref(&tx),
                    )
                    .is_err()
                {
                    continue;
                }
                accepted.insert(hash);
            }
            let nonce = |sender: &[u8]| ledger.account(sender).map(|a| a.nonce);
            let select = |circles: bool| {
                pool.ready_epoch(capacity, &nonce, &|tx| {
                    (circles
                        || !octra_node_runtime::preverify_batch::snapshot_transition(tx.op_type))
                        && tx
                            .hash()
                            .is_ok_and(|h| accepted.contains(hex::encode(h).as_bytes()))
                })
                .into_iter()
                .map(|e| e.tx.clone())
                .collect()
            };
            Ok((select(true), select(false)))
        })
    }
    pub(super) fn refuse(&self, draft: &Draft, tx: &Transaction) -> Result<Option<DropRecord>> {
        draft.with_current(|| {
            let mut pool = self.pool.try_lock().map_err(|_| anyhow!("staging busy"))?;
            let epoch = draft.context().header().epoch_id;
            let hash = hex::encode(tx.hash()?).into_bytes();
            pool.preview(preview::Message::Refuse {
                head: epoch - 1,
                epoch,
                hash: hash.clone(),
            })
            .map_err(|e| anyhow!(e))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or_else(|e| -e.duration().as_secs_f64(), |d| d.as_secs_f64());
            Ok(pool.drop_preview(&hash, now))
        })
    }
    pub(super) fn hold(&self, draft: &Draft, tx: &Transaction) -> Result<()> {
        draft.with_current(|| {
            let mut pool = self.pool.try_lock().map_err(|_| anyhow!("staging busy"))?;
            let epoch = draft.context().header().epoch_id;
            pool.preview(preview::Message::Hold {
                head: epoch - 1,
                epoch,
                hash: hex::encode(tx.hash()?).into_bytes(),
            })
            .map_err(|e| anyhow!(e))
        })
    }
}
impl Native {
    /// Preverify outside the queue lock, then authenticate and stage against
    /// exactly the same canonical generation. A commit invalidates the lease.
    pub async fn submit(
        &self,
        admission: std::sync::Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
    ) -> Result<Vec<u8>> {
        use octra_node_runtime::{admission, preverify_batch::Checked, staging::intake};
        use transaction::Nonce;
        let draft = admission.draft();
        let rules = self.draft_rules(draft)?;
        let fold = draft.context().rules().fold.context();
        let head = draft.context().header().epoch_id - 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let ledger = account_store::ledger(&StateBatch::from_snapshot(draft.state().clone()))?;
        let account = ledger.account(&tx.from);
        admission::pre_signature(
            &tx,
            account.is_some(),
            &admission::Precheck {
                now,
                max_timestamp_drift: 300.,
                observer: false,
                bft: true,
                profile: &self.config.profile,
                duty: Some((head, fold.ready_exec_mode)),
                limits: self.config.payload,
            },
        )
        .map_err(|e| anyhow!("{e:?}"))?;
        let tx = transaction::normalize_envelope(
            &tx,
            account
                .and_then(|a| a.public_key.as_deref())
                .or(tx.public_key.as_deref()),
        )
        .map_err(|e| anyhow!(e.reason))?;
        admission::signature(&tx, account.and_then(|a| a.public_key.as_deref()))
            .map_err(|e| anyhow!("{e:?}"))?;
        admission::payload(&tx, self.config.payload).map_err(|e| anyhow!("{e:?}"))?;
        let host = self.clone();
        let captured = admission.clone();
        let input = tx.clone();
        let minimum = rules.stealth_minimum.clone();
        let verified = super::run_worker(self.worker.clone(), move || {
            let captured = captured.draft();
            let ledger =
                account_store::ledger(&StateBatch::from_snapshot(captured.state().clone()))?;
            Ok(host.prove(
                &input,
                &ledger,
                captured.state(),
                captured.context().parent().ledger_root.as_bytes(),
                host.private_profile(captured.context().rules(), head + 1),
                &minimum,
            ))
        })
        .await?;
        let verdict = match verified {
            Checked::Ready(_) => Ok(()),
            Checked::Skip { reason, .. } => Err(String::from_utf8_lossy(&reason).into_owned()),
        };
        struct Intake(Result<(), String>);
        impl intake::Host for Intake {
            fn preverify(&mut self, _: &Transaction, _: &Pool) -> Result<(), String> {
                self.0.clone()
            }
            fn save_drops(&mut self, _: &[DropRecord]) {}
            fn invalidate(&mut self, _: &[u8]) {}
            fn changed(&mut self, _: &Pool) {}
            fn accepted(&mut self, _: &Transaction, _: &Pool) {}
        }
        draft.with_current(|| {
            let mut pool = pending
                .pool
                .try_lock()
                .map_err(|_| anyhow!("staging busy"))?;
            intake::submit(
                &mut pool,
                &tx,
                &ledger,
                &intake::Rules {
                    bft: true,
                    profile: self.config.profile.clone(),
                    compute: rules.envelope.compute,
                    settle: rules.envelope.settle,
                    proof: fold.proof_exec,
                    duty: Some((head, fold.ready_exec_mode)),
                    queue_head: Some(head),
                    stealth_minimum: rules.stealth_minimum,
                },
                &intake::Rpc {
                    now,
                    max_drift: 300.,
                    observer: false,
                    preverify_capacity: true,
                    preverify_pending: Nonce::new(0)?,
                    preverify_maximum: Nonce::new(128)?,
                    nonce_window: Nonce::new(64)?,
                },
                &mut Intake(verdict),
                &|| now,
            )
            .map_err(|e| anyhow!("{e:?}"))
        })
    }

    pub(super) fn admits_pending(&self, draft: &Draft, rules: &Rules, tx: &Transaction) -> bool {
        self.config.profile.consensus_admits(tx.op_type)
            && resource_lanes::queue_check(
                tx,
                draft.context().rules().fold.context().proof_exec,
                &rules.stealth_minimum,
            )
            .is_ok()
            && transaction::check_compute(
                rules.envelope.compute,
                rules.envelope.settle,
                std::slice::from_ref(tx),
            )
            .is_ok()
            && transaction::check_envelopes(rules.envelope.envelope, std::slice::from_ref(tx))
                .is_ok()
    }
    pub(super) async fn previous_circle(&self, draft: &Draft) -> Result<Option<bool>> {
        let context = draft.context();
        let transactions = match context.parent_commit() {
            Some(p) => {
                let proposal = p.certificate.proposal_id.as_slice().try_into()?;
                self.history
                    .bundle(proposal)
                    .await?
                    .map(|raw| {
                        raw.txs_json
                            .iter()
                            .map(|raw| {
                                Transaction::from_document(
                                    &octra_node_protocol::native_json::Document::parse(raw)?,
                                )
                                .map_err(Into::into)
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?
            }
            None => None,
        };
        Ok(proposal_select::previous(
            &context.header().chain_id,
            context.header().epoch_id,
            context.parent_commit(),
            transactions.as_deref(),
        )?)
    }
}
