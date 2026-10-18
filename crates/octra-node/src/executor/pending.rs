//! Queue ownership for proposal construction. Intake must use the native
//! staging admission path; construction rechecks every selected transaction.
use super::{
    pending_store::{Disk, Recovery},
    Native,
};
use crate::{import::Executor as _, proposal::Draft};
use anyhow::{anyhow, Result};
use num_bigint::BigInt;
use octra_exex::Cursor;
use octra_node_protocol::{
    control_payload::BondedReady,
    duty, resource_lanes,
    transaction::{self, OpType, RuleMode, Transaction},
    validator::{
        ready,
        set_fold::{self, State as DutyState},
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
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct Pending {
    state: Arc<Mutex<State>>,
}
struct State {
    pool: Pool,
    disk: Option<Disk>,
    recovery: Option<Recovery>,
    failed: bool,
}
#[derive(Debug)]
pub(super) struct Unavailable(String);
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Unavailable {}
impl Pending {
    pub fn new(pool: Pool) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                pool,
                disk: None,
                recovery: None,
                failed: false,
            })),
        }
    }
    pub(crate) async fn open(
        path: std::path::PathBuf,
        store: &octra_node_runtime::canonical::CanonicalStore,
    ) -> Result<Self> {
        let (disk, recovery) = Disk::load(path, store).await?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                pool: Pool::default(),
                disk: Some(disk),
                recovery: Some(recovery),
                failed: false,
            })),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| anyhow!(Unavailable("staging busy".into())))?;
        anyhow::ensure!(
            !state.failed && state.recovery.is_none(),
            Unavailable("durable staging unavailable".into())
        );
        Ok(state)
    }
    /// Called on a blocking worker. Hold the short canonical lease only during
    /// the in-memory transition, then fsync with the queue still exclusively held.
    /// Failed persistence poisons admission until restart, never returns success.
    fn mutate<T>(
        &self,
        draft: Option<&Draft>,
        cursor: Cursor,
        apply: impl FnOnce(&mut Pool) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.lock()?;
        let result = match draft {
            Some(draft) => draft
                .with_current(|| Ok(apply(&mut state.pool)))
                .map_err(|e| anyhow!(Unavailable(e.to_string())))?,
            None => apply(&mut state.pool),
        };
        let State {
            pool, disk, failed, ..
        } = &mut *state;
        if let Some(disk) = disk {
            if let Err(error) = disk.save(pool, cursor) {
                *failed = true;
                return Err(anyhow!(Unavailable(error.to_string())));
            }
        }
        result
    }
    pub fn transactions(&self) -> Result<Vec<Transaction>> {
        Ok(self.lock()?.pool.all().cloned().collect())
    }
    /// Gossip reads only the requested queue hashes. Recovery or a concurrent
    /// writer may defer that lookup; a corrupt journal or poisoned owner never
    /// becomes an apparently empty queue.
    pub(crate) fn ingress_read<T>(&self, read: impl FnOnce(&Pool) -> T) -> Result<Option<T>> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(anyhow!(Unavailable(
                    "durable staging owner poisoned".into()
                )));
            }
        };
        anyhow::ensure!(
            !state.failed,
            Unavailable("durable staging unavailable".into())
        );
        Ok(state.recovery.is_none().then(|| read(&state.pool)))
    }
    /// Durable entries are replayed against the current canonical head by
    /// `recover`; per-commit callbacks must wait until that replay completes.
    pub(crate) fn awaiting_recovery(&self) -> Result<bool> {
        let state = self.state.try_lock().map_err(|_| anyhow!("staging busy"))?;
        anyhow::ensure!(!state.failed, "durable staging unavailable");
        Ok(state.recovery.is_some())
    }
    /// Capture queue metadata under the same short read lock. Callers cannot
    /// retain a reference to or mutate the pool through this capability.
    pub(crate) fn inspect<T>(&self, read: impl FnOnce(&Pool) -> T) -> Result<T> {
        Ok(read(&self.lock()?.pool))
    }
    /// Retire stale duty against one authenticated current admission lease.
    pub(crate) fn expire_duty(&self, draft: &Draft, sender: Option<&[u8]>) -> Result<()> {
        let mode = draft.context().rules().fold.context().ready_exec_mode;
        let head = draft.context().header().epoch_id - 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        if !self.inspect(|pool| {
            pool.all().any(|tx| {
                sender.is_none_or(|s| tx.from == s) && duty::expired(tx, Some(head), mode)
            })
        })? {
            return Ok(());
        }
        self.mutate(Some(draft), draft.context().parent().cursor, |pool| {
            pool.expire_duty(sender, Some(head), mode, &|| now);
            Ok(())
        })
    }
    /// Authenticate the sender and remove the exact queue hash in one current
    /// canonical lease. Persistence completes before a success is exposed.
    pub(crate) fn remove_authorized(
        &self,
        draft: &Draft,
        request: &octra_node_protocol::registration_rpc::Removal,
    ) -> Result<std::result::Result<(), octra_node_protocol::rpc::Fault>> {
        self.mutate(Some(draft), draft.context().parent().cursor, |pool| {
            let Some(tx) = pool.find(&request.hash) else {
                return Ok(Err(octra_node_protocol::registration_rpc::staging_missing()));
            };
            if let Err(fault) = request.authorize(&tx.from) {
                return Ok(Err(fault));
            }
            if pool.remove(&request.hash) {
                Ok(Ok(()))
            } else {
                Ok(Err(octra_node_protocol::registration_rpc::staging_missing()))
            }
        })
    }
    pub(crate) fn dropped(&self, hash: &[u8]) -> Result<Option<DropRecord>> {
        let state = self.lock()?;
        if let Some(row) = state.pool.dropped(hash) {
            return Ok(Some(row.clone()));
        }
        state
            .disk
            .as_ref()
            .map_or(Ok(None), |disk| disk.dropped(hash))
    }
    pub(crate) fn drops(&self, address: &[u8]) -> Result<Vec<DropRecord>> {
        let state = self.lock()?;
        let saved = state
            .disk
            .as_ref()
            .map_or(Ok(Vec::new()), |disk| disk.drops(address))?;
        let mut rows = saved
            .into_iter()
            .map(|row| (row.hash.clone(), row))
            .collect::<BTreeMap<_, _>>();
        for row in state
            .pool
            .drops()
            .filter(|row| row.from == address || row.to == address)
        {
            rows.insert(row.hash.clone(), row.clone());
        }
        Ok(rows.into_values().collect())
    }
    /// Reconcile canonical commits which won a crash race, then reauthenticate
    /// every remaining candidate before publishing a single recovered queue.
    /// Failed recovery leaves the prior journal available for the next restart.
    pub(crate) async fn recover<A: crate::Host>(
        &self,
        submission: &crate::rpc::Submission<A>,
    ) -> Result<()> {
        let saved = {
            let state = self.state.try_lock().map_err(|_| anyhow!("staging busy"))?;
            anyhow::ensure!(!state.failed, "durable staging unavailable");
            state.recovery.clone()
        };
        let Some(mut saved) = saved else {
            return Ok(());
        };
        let head = submission.node.head().await?;
        anyhow::ensure!(
            saved.cursor.sequence <= head.cursor.sequence,
            "pending queue is ahead of canonical head"
        );
        if saved.cursor.sequence < head.cursor.sequence {
            for sequence in saved.cursor.sequence.0 + 1..=head.cursor.sequence.0 {
                let record = submission
                    .node
                    .publisher
                    .record(octra_exex::Sequence(sequence))
                    .await?;
                for hash in processed(&record)? {
                    saved.entries.remove(std::str::from_utf8(&hash)?);
                }
            }
        }
        let restored = Self::new(Pool::default());
        let mut entries = saved
            .entries
            .values()
            .map(|s| Ok((s.transaction()?, s.added_at)))
            .collect::<Result<Vec<_>>>()?;
        // Account/nonce order permits dependency checks; original age still
        // determines expiry, eviction ties and recent-order indexing.
        entries.sort_by(|(a, _), (b, _)| a.from.cmp(&b.from).then(a.nonce.cmp(&b.nonce)));
        for (tx, added_at) in entries {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
            if added_at > now || now - added_at > octra_node_runtime::staging::TTL {
                continue;
            }
            let admission = Arc::new(
                submission
                    .node
                    .admission_capture(
                        &submission.executor.graph(),
                        submission.policy,
                        &submission.address,
                        now,
                    )
                    .await?,
            );
            if let Err(error) = submission
                .executor
                .submit_at(admission, &restored, tx, Some(added_at))
                .await
            {
                if error.is::<Unavailable>() {
                    return Err(error);
                }
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let admission = Arc::new(
            submission
                .node
                .admission_capture(
                    &submission.executor.graph(),
                    submission.policy,
                    &submission.address,
                    now,
                )
                .await?,
        );
        anyhow::ensure!(
            admission.draft().context().parent() == &head,
            "canonical head changed during pending recovery"
        );
        let pending = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut target = pending
                .state
                .try_lock()
                .map_err(|_| anyhow!("staging busy"))?;
            anyhow::ensure!(
                target.recovery.is_some() && !target.failed,
                "pending recovery already completed"
            );
            let mut source = restored.lock()?;
            source
                .pool
                .restore_preview(saved.preview, i64::try_from(head.cursor.epoch.0)?)
                .map_err(anyhow::Error::msg)?;
            admission.draft().with_current(|| Ok(()))?;
            if let Some(disk) = &mut target.disk {
                disk.save(&source.pool, head.cursor)?;
            }
            target.pool = std::mem::take(&mut source.pool);
            target.recovery = None;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    /// Called only with an authenticated durable record by canonical publication.
    /// Both confirmed work and recorded refusals are processed, as upstream.
    /// Removal is idempotent so a post-commit callback can be retried safely.
    pub(crate) fn committed(
        &self,
        record: &octra_node_protocol::consensus::CatchupEpochRecord,
        cursor: Cursor,
    ) -> Result<()> {
        let hashes = processed(record)?;
        self.mutate(None, cursor, |pool| {
            pool.remove_processed(&hashes);
            Ok(())
        })
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
        let duty = state.get(&[b"meta", set_fold::META_KEY]).map_or_else(
            || Some(DutyState::default()),
            |raw| DutyState::from_bytes(raw).ok(),
        );
        let parent = context.parent_commit().filter(|p| {
            p.certificate.epoch_id == epoch - 1
                && p.certificate.chain_id == context.header().chain_id
                && p.certificate.header.proposed_state_root == context.parent().cursor.state_root.0
        });
        self.mutate(Some(draft), draft.context().parent().cursor, |pool| {
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
        self.mutate(Some(draft), draft.context().parent().cursor, |pool| {
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
        self.mutate(Some(draft), draft.context().parent().cursor, |pool| {
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
        self.submit_at(admission, pending, tx, None).await
    }
    /// Preserve native admission tags across worker and persistence boundaries.
    /// Operational failures never become malformed-transaction refusals.
    pub async fn submit_native(
        &self,
        admission: Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, octra_node_runtime::admission::Error> {
        self.intake(admission, pending, tx, None, true, None, None)
            .await
            .map_err(
                |error| match error.downcast::<octra_node_runtime::admission::Error>() {
                    Ok(error) => error,
                    Err(error) => {
                        octra_node_runtime::admission::Error::Unavailable(error.to_string())
                    }
                },
            )
    }
    pub(crate) async fn submit_duty(
        &self,
        admission: Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
        guard: Arc<octra_node_runtime::validator_control::DutyGuard>,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<Vec<u8>> {
        anyhow::ensure!(
            tx.op_type == OpType::ValidatorReady,
            "validator duty operation required"
        );
        self.intake(
            admission,
            pending,
            tx,
            None,
            true,
            Some(guard),
            Some(wallet),
        )
        .await
    }
    pub(crate) async fn submit_operator(
        &self,
        admission: Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<Vec<u8>> {
        self.intake(admission, pending, tx, None, true, None, Some(wallet))
            .await
    }
    pub(super) async fn submit_at(
        &self,
        admission: Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
        added_at: Option<f64>,
    ) -> Result<Vec<u8>> {
        self.intake(admission, pending, tx, added_at, false, None, None)
            .await
    }
    async fn intake(
        &self,
        admission: Arc<crate::proposal::Admission>,
        pending: &Pending,
        tx: Transaction,
        added_at: Option<f64>,
        rpc: bool,
        duty_guard: Option<Arc<octra_node_runtime::validator_control::DutyGuard>>,
        wallet_guard: Option<Arc<tokio::sync::OwnedMutexGuard<()>>>,
    ) -> Result<Vec<u8>> {
        use octra_node_runtime::{
            admission,
            preverify_batch::{Checked, Kind},
            staging::intake,
        };
        use transaction::Nonce;
        let draft = admission.draft();
        let rules = self
            .draft_rules(draft)
            .map_err(|e| anyhow!(Unavailable(e.to_string())))?;
        let fold = draft.context().rules().fold.context();
        let head = draft.context().header().epoch_id - 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let ledger = account_store::ledger(&StateBatch::from_snapshot(draft.state().clone()))?;
        let account = ledger.account(&tx.from);
        transaction::check_compute(
            rules.envelope.compute,
            rules.envelope.settle,
            std::slice::from_ref(&tx),
        )
        .map_err(|error| {
            admission::Error::Rejected(transaction::EnvelopeError {
                tag: "malformed_transaction",
                reason: error.to_string(),
            })
        })?;
        admission::pre_signature(
            &tx,
            account.is_some(),
            &admission::Precheck {
                now,
                max_timestamp_drift: 300.,
                observer: rpc && self.observer_submissions,
                bft: true,
                profile: &self.config.profile,
                duty: Some((head, fold.ready_exec_mode)),
                limits: self.config.payload,
            },
        )
        .map_err(admission::Error::from)?;
        let tx = transaction::normalize_envelope(
            &tx,
            account
                .and_then(|a| a.public_key.as_deref())
                .or(tx.public_key.as_deref()),
        )
        .map_err(admission::Error::from)?;
        admission::signature(&tx, account.and_then(|a| a.public_key.as_deref()))
            .map_err(admission::Error::from)?;
        admission::payload(&tx, self.config.payload)?;
        admission::post_signature(
            &tx,
            admission::Postcheck {
                preverify_has_capacity: true,
                preverify_pending: Nonce::default(),
                preverify_pending_max: Nonce::new(128)?,
                bft: true,
                confirmed_nonce: account.expect("sender admission").nonce,
                bft_window: self.pending_nonce_window,
            },
        )
        .map_err(admission::Error::from)?;
        let host = self.clone();
        let captured = admission.clone();
        let input = tx.clone();
        let minimum = rules.stealth_minimum.clone();
        let proving_guard = duty_guard.clone();
        let proving_wallet = wallet_guard.clone();
        let verified = super::run_worker(self.worker.clone(), move || {
            let _duty = proving_guard;
            let _wallet = proving_wallet;
            // Native queue intake starts only private/key-switch proof jobs.
            // Circle bindings are checked against the ordered proposal state;
            // accepting the queue entry supplies no execution receipt.
            if matches!(
                input.op_type,
                OpType::CircleCall | OpType::CircleBalanceCellPut | OpType::CircleRegisterCellPut
            ) {
                return Ok(Checked::Ready(None));
            }
            let captured = captured.draft();
            let ledger =
                account_store::ledger(&StateBatch::from_snapshot(captured.state().clone()))?;
            Ok(host.prove(
                &input,
                &ledger,
                captured.state(),
                captured.context().parent().ledger_root.as_bytes(),
                head + 1,
                host.private_policy(captured.context().rules(), head + 1),
                &minimum,
            ))
        })
        .await
        .map_err(|e| anyhow!(Unavailable(e.to_string())))?;
        let unavailable = matches!(
            &verified,
            Checked::Skip {
                kind: Kind::Unavailable,
                ..
            }
        );
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
        let pending = pending.clone();
        let captured = admission.clone();
        let host = self.clone();
        let added_at = added_at.unwrap_or(now);
        anyhow::ensure!(
            added_at.is_finite()
                && added_at >= 0.
                && added_at <= now
                && now - added_at <= octra_node_runtime::staging::TTL,
            "saved transaction expired"
        );
        super::run_worker(self.worker.clone(), move || {
            // Cancellation of the awaiting caller must not release the local
            // intent lock while an owned queue worker can still persist duty.
            let _duty = duty_guard;
            let _wallet = wallet_guard;
            let draft = captured.draft();
            let fold = draft.context().rules().fold.context();
            Ok(
                pending.mutate(Some(draft), draft.context().parent().cursor, |pool| {
                    intake::submit(
                        pool,
                        &tx,
                        &ledger,
                        &intake::Rules {
                            bft: true,
                            profile: host.config.profile.clone(),
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
                            observer: rpc && host.observer_submissions,
                            preverify_capacity: true,
                            preverify_pending: Nonce::new(0)?,
                            preverify_maximum: Nonce::new(128)?,
                            nonce_window: host.pending_nonce_window,
                        },
                        &mut Intake(verdict),
                        &|| added_at,
                    )
                    .map_err(|e| {
                        if unavailable {
                            anyhow!(Unavailable(format!("{e:?}")))
                        } else {
                            anyhow!(e)
                        }
                    })
                }),
            )
        })
        .await
        .map_err(|e| anyhow!(Unavailable(e.to_string())))?
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

fn processed(record: &octra_node_protocol::consensus::CatchupEpochRecord) -> Result<Vec<Vec<u8>>> {
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
    Ok(hashes)
}

#[cfg(test)]
mod ingress_tests {
    use super::*;
    use octra_exex::{EpochId, Sequence, StateRoot};

    #[test]
    fn gossip_waits_for_queue_recovery_but_fails_on_poisoned_persistence() {
        let pending = Pending::new(Pool::default());
        assert_eq!(
            pending.ingress_read(|pool| pool.all().count()).unwrap(),
            Some(0)
        );
        let state = pending.state.lock().unwrap();
        assert!(pending
            .ingress_read(|_| panic!("busy queue must not be inspected"))
            .unwrap()
            .is_none());
        drop(state);
        let mut state = pending.state.lock().unwrap();
        state.recovery = Some(Recovery {
            cursor: Cursor {
                sequence: Sequence(0),
                epoch: EpochId(0),
                state_root: StateRoot([0; 32]),
            },
            entries: BTreeMap::new(),
            preview: Pool::default().preview_state(),
        });
        drop(state);
        assert!(pending
            .ingress_read(|_| panic!("recovering queue must not be inspected"))
            .unwrap()
            .is_none());
        let mut state = pending.state.lock().unwrap();
        state.failed = true;
        drop(state);
        assert!(pending
            .ingress_read(|_| panic!("failed journal must not be inspected"))
            .is_err());
    }
    #[test]
    fn poisoned_gossip_owner_is_fatal_instead_of_empty() {
        let pending = Pending::new(Pool::default());
        let poisoned = pending.clone();
        let _ = std::thread::spawn(move || {
            let _owner = poisoned.state.lock().unwrap();
            panic!("deliberate owner poison");
        })
        .join();
        assert!(pending
            .ingress_read(|_| ())
            .unwrap_err()
            .to_string()
            .contains("poisoned"));
    }
}
