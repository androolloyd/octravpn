//! The real operation hosts for Single sender execution; no BFT envelope or QC is constructed.
use super::Native;
use anyhow::{ensure, Result};
use num_bigint::BigInt;
use octra_exex::native_history::{ArchiveProof, NativeTransaction};
use octra_node_protocol::{
    epoch_rewards::{Attribution, Validator},
    rules::{RootRead, Rule},
    single::Preverify,
    transaction::{OpType, Transaction},
    transaction_outcome,
};
use octra_node_runtime::{
    account_store,
    canonical::Head,
    circle_transaction, compute_transaction,
    epoch_execution::Effect,
    execution::{Completion, Error, OperationHost, Rejection, Route},
    execution_rules::Bound,
    program_transaction, single_execution, single_private,
    state_batch::{Snapshot, StateBatch},
    validator_epoch, validator_transaction,
};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
pub struct Request<'a> {
    pub parent: &'a Head,
    pub state: Snapshot,
    pub context: &'a Bound,
    pub envelope: transaction_outcome::Rules,
    pub validators: &'a [(Vec<u8>, Vec<u8>)],
    pub proposer: &'a [u8],
    pub transactions: &'a [Transaction],
    pub deferred: single_private::Deferred,
    pub preverify: BTreeMap<String, Preverify>,
    pub ready: BTreeMap<String, single_private::CacheBinding>,
    pub maximum_defer: i64,
    pub inline: bool,
    pub ready_roots: &'a BTreeMap<i64, Option<Vec<u8>>>,
}
pub struct Output {
    pub epoch: single_execution::Epoch,
    pub transactions: Vec<NativeTransaction>,
    pub vm_receipts: octra_node_runtime::canonical::VmReceipts,
    pub deferred: single_private::Deferred,
    pub kat_backfills: BTreeMap<Vec<u8>, Vec<u8>>,
}
struct Host<F> {
    process: F,
    fees: Rc<RefCell<BigInt>>,
}
impl<F> OperationHost for Host<F>
where
    F: FnMut(
        Route,
        &Transaction,
        &mut octra_node_protocol::state::Ledger,
        &mut StateBatch,
    ) -> Result<Completion, Error>,
{
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut octra_node_protocol::state::Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        (self.process)(route, tx, ledger, state)
    }
}
impl<F> single_execution::Host for Host<F>
where
    Self: OperationHost,
{
    fn charged_rejection_fees(&self) -> BigInt {
        self.fees.borrow().clone()
    }
}
// Native float_of_int follows the OCaml int63 epoch*10 wrap. Precision loss is
// intentional and must not change to saturating or floating multiplication.
#[allow(clippy::cast_precision_loss)]
fn vm_time(epoch: i64) -> f64 {
    ((epoch.wrapping_mul(10).wrapping_shl(1)) >> 1) as f64
}
fn effect(value: Effect, fees: &RefCell<BigInt>) -> Completion {
    match value {
        Effect::Confirmed(_) => Completion::Confirmed {
            created_account: None,
        },
        Effect::Rejected(refusal) => Completion::Rejected(Rejection {
            tag: String::from_utf8_lossy(&refusal.error_type).into_owned(),
            reason: refusal.reason,
            notify_reason: None,
            consume_nonce: false,
            persist_state: false,
        }),
        Effect::RejectedAfterFee { fee, refusal } => {
            *fees.borrow_mut() += fee;
            Completion::Rejected(Rejection {
                tag: String::from_utf8_lossy(&refusal.error_type).into_owned(),
                reason: refusal.reason,
                notify_reason: None,
                consume_nonce: false,
                persist_state: true,
            })
        }
    }
}
impl Native {
    /// Resolve the very same native fold with parent=None. In particular this
    /// refuses activated public set-fold instead of inventing a Single parent QC.
    pub async fn single_context(
        &self,
        parent: &Head,
        validators: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Bound> {
        let epoch = i64::try_from(parent.cursor.epoch.0)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Single epoch exhausted"))?;
        let legacy = validators
            .iter()
            .map(|(address, _)| address.clone())
            .collect::<Vec<_>>();
        let mut roots = BTreeMap::new();
        loop {
            let requested = RefCell::new(Vec::new());
            let bound = Bound::resolve(&self.config.graph, epoch, None, &legacy, &|height| {
                roots.get(&height).cloned().unwrap_or_else(|| {
                    requested.borrow_mut().push(height);
                    RootRead::Missing
                })
            });
            let next = requested
                .into_inner()
                .into_iter()
                .find(|h| !roots.contains_key(h));
            if let Some(height) = next {
                let root = if height >= 0 && height as u64 <= parent.cursor.epoch.0 {
                    self.history
                        .root(height)
                        .await?
                        .map_or(RootRead::Missing, |r| {
                            RootRead::Root(hex::encode(r).into_bytes())
                        })
                } else {
                    RootRead::Missing
                };
                roots.insert(height, root);
                continue;
            }
            return bound.map_err(anyhow::Error::new);
        }
    }
    pub fn execute_single(&self, request: Request<'_>) -> Result<Output> {
        self.execute_single_registered(request, &BTreeMap::new())
    }
    pub fn execute_single_registered(
        &self,
        request: Request<'_>,
        registered: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Output> {
        let Request {
            parent,
            state,
            context,
            envelope,
            validators: members,
            proposer,
            transactions,
            deferred,
            preverify,
            ready,
            maximum_defer,
            inline,
            ready_roots,
        } = request;
        let epoch = i64::try_from(parent.cursor.epoch.0)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Single epoch exhausted"))?;
        let mut state = StateBatch::from_snapshot(state);
        ensure!(
            hex::encode(state.published_root()?) == parent.ledger_root,
            "Single snapshot differs from parent"
        );
        state.begin()?;
        let keys = members.to_vec();
        let addresses = keys.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>();
        let reward = Attribution {
            proposer: proposer.to_vec(),
            proposer_public_key: keys
                .iter()
                .find(|(a, _)| a == proposer)
                .map(|(_, k)| k.clone()),
            validators: keys
                .iter()
                .map(|(address, public)| Validator {
                    address: address.clone(),
                    public_key: Some(public.clone()),
                    weight: 1.into(),
                })
                .collect(),
        };
        let previous = hex::encode(parent.cursor.state_root.0);
        let mut calls = circle_transaction::Calls::new(
            &self.runtime,
            context.circle,
            epoch,
            vm_time(epoch),
            previous.as_bytes(),
            circle_transaction::Verification::Capture,
        );
        let mut programs = program_transaction::Calls::new(
            &self.runtime,
            context.circle,
            octra_node_runtime::program::artifact::SourceRules::captured(context.fold.context()),
            epoch,
            vm_time(epoch),
            previous.as_bytes(),
            self.config.max_multi_exec_calls,
        )?;
        let mut private = single_private::Epoch::new(
            deferred,
            preverify,
            self.config.max_fhe,
            self.config.max_stealth,
            maximum_defer,
            inline,
        );
        private.ready = ready;
        let root_at = |height| ready_roots.get(&height).cloned().flatten();
        let mut validators = validator_transaction::Host {
            chain: self.config.graph.chain_id(),
            epoch,
            policy: &self.config.validators,
            fold: context.fold.clone(),
            ready: validator_transaction::ReadyEnvironment {
                prev_state_root: previous.as_bytes(),
                max_lag: self.config.ready_max_lag,
                root_at: Some(&root_at),
            },
        };
        let committed = state.snapshot();
        let replay = octra_node_runtime::compute_replay::NativeReplay::new(&self.runtime);
        let mut settlement = octra_node_runtime::compute_settle::Service::new(replay);
        let mut compute = compute_transaction::Host {
            chain: self.config.graph.chain_id(),
            epoch,
            fold: &context.fold,
            settle: envelope.settle,
            previous_root: previous.as_bytes(),
            committed_head: Some(&committed),
            verifier: Some(&mut settlement),
        };
        let fees = Rc::new(RefCell::new(BigInt::from(0)));
        let charged = fees.clone();
        let mut kat_backfills = BTreeMap::new();
        let operation = |route: Route,
                         tx: &Transaction,
                         ledger: &mut octra_node_protocol::state::Ledger,
                         state: &mut StateBatch|
         -> Result<Completion, Error> {
            let _crypto = self.runtime.crypto_scope(
                false,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            );
            if route == Route::Validator {
                return validators.execute(route, tx, ledger, state);
            }
            if matches!(
                route,
                Route::Encrypt | Route::Decrypt | Route::KeySwitch | Route::Stealth | Route::Claim
            ) {
                let previous_kats = kat_backfills.clone();
                let key_hash = state.get(&[b"pvac_hashes", &tx.from]).map(<[u8]>::to_vec);
                let value = private.process(
                    tx,
                    ledger,
                    state,
                    self.private_policy(context, epoch),
                    epoch,
                    self.config.migration.as_deref(),
                    || self.single_key(key_hash.as_deref(), &tx.from),
                    |address, _| {
                        if !octra_node_protocol::transaction::is_valid_address(address) {
                            return Err(Error("Single KAT address invalid".into()));
                        }
                        let expected =
                            octra_node_runtime::crypto_payload::expected_kat().into_bytes();
                        let path = self
                            .config
                            .pvac_dir
                            .join(format!("{}.kat", String::from_utf8_lossy(address)));
                        let current = kat_backfills.get(address).cloned().or_else(|| {
                            std::fs::read(path).ok().map(|mut b| {
                                if let Some(n) = b.iter().position(|x| *x == b'\n') {
                                    b.truncate(n);
                                }
                                b
                            })
                        });
                        if let Some(current) = current {
                            Ok(current == expected)
                        } else {
                            kat_backfills.insert(address.to_vec(), expected);
                            Ok(true)
                        }
                    },
                    |key| self.persist_key(key),
                );
                if tx.op_type == OpType::KeySwitch
                    && matches!(&value, Ok(Completion::Confirmed { .. }))
                {
                    kat_backfills.insert(
                        tx.from.clone(),
                        octra_node_runtime::crypto_payload::expected_kat().into_bytes(),
                    );
                }
                if !matches!(
                    &value,
                    Ok(Completion::Confirmed { .. }
                        | Completion::Rejected(Rejection {
                            persist_state: true,
                            ..
                        }))
                ) {
                    kat_backfills = previous_kats;
                }
                return value;
            }
            let value = match tx.op_type {
                OpType::ComputeFund | OpType::ComputeReturn | OpType::ComputeSettle => {
                    compute.process(tx, ledger, state)?
                }
                OpType::ContractDeploy
                | OpType::ProgramDeploy
                | OpType::ContractCall
                | OpType::ProgramExec
                | OpType::MultiExec
                | OpType::ContractUpgrade => programs.process(tx, ledger, state)?,
                _ => calls.process(tx, ledger, state)?,
            };
            Ok(effect(value, &charged))
        };
        let mut host = Host {
            process: operation,
            fees,
        };
        let request = single_execution::Request {
            validators: validator_epoch::Request {
                chain: self.config.graph.chain_id(),
                epoch,
                policy: &self.config.validators,
                legacy_members: &addresses,
                previous_root: previous.as_bytes(),
                committed_head: Some(&committed),
            },
            envelope,
            emission: &self.config.emission,
            reward: &reward,
            validator_keys: &keys,
        };
        let executed = single_execution::execute_registered(
            &request,
            &context.fold,
            transactions,
            &mut state,
            &mut host,
            registered,
        )?;
        drop(host);
        let mut vm_receipts = calls.receipts().clone();
        for (hash, raw) in programs.receipts() {
            ensure!(
                vm_receipts.insert(hash.clone(), raw.clone()).is_none(),
                "duplicate Single VM receipt"
            );
        }
        let archived = executed
            .confirmed
            .iter()
            .enumerate()
            .map(|(offset, &index)| {
                let tx = &transactions[index];
                let hash = hex::encode(tx.hash()?);
                let raw = tx.identity_bytes()?;
                Ok(NativeTransaction {
                    txid: parent
                        .txid_hi
                        .checked_add(i64::try_from(offset)? + 1)
                        .ok_or_else(|| anyhow::anyhow!("Single transaction index exhausted"))?,
                    hash: hash.clone(),
                    identity: raw.clone(),
                    transaction: raw,
                    proof: ArchiveProof::Exact,
                    receipt: vm_receipts.get(&hash).cloned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Output {
            epoch: executed,
            transactions: archived,
            vm_receipts,
            deferred: private.deferred,
            kat_backfills,
        })
    }
}
impl Native {
    pub async fn single_ready_roots(
        &self,
        parent: &Head,
        context: &Bound,
        transactions: &[Transaction],
    ) -> Result<BTreeMap<i64, Option<Vec<u8>>>> {
        self.ready_roots(parent, context, transactions).await
    }
    pub fn single_chain(&self) -> &[u8] {
        self.config.graph.chain_id()
    }
    pub fn single_intake_rules(
        &self,
        epoch: i64,
        context: &Bound,
        envelope: transaction_outcome::Rules,
    ) -> octra_node_runtime::staging::intake::Rules {
        octra_node_runtime::staging::intake::Rules {
            bft: false,
            profile: self.config.profile.clone(),
            compute: envelope.compute,
            settle: envelope.settle,
            proof: context.fold.context().standard_mode,
            duty: Some((epoch - 1, context.fold.context().ready_exec_mode)),
            queue_head: Some(epoch - 1),
            stealth_minimum: 5000.into(),
        }
    }
    pub async fn single_source_rules(&self, parent: &Head) -> Result<transaction_outcome::Rules> {
        let epoch = i64::try_from(parent.cursor.epoch.0)?
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Single epoch exhausted"))?;
        let mut roots = BTreeMap::new();
        let mut modes = Vec::new();
        for rule in [Rule::TxEnvelope, Rule::VmBytes, Rule::Settle] {
            if let Some(plan) = self
                .config
                .graph
                .activation(rule)
                .filter(|plan| epoch >= plan.activation_epoch)
            {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    roots.entry(plan.anchor_epoch)
                {
                    let root = if plan.anchor_epoch >= 0
                        && (plan.anchor_epoch as u64) <= parent.cursor.epoch.0
                    {
                        self.history
                            .root(plan.anchor_epoch)
                            .await?
                            .map_or(RootRead::Missing, |root| {
                                RootRead::Root(hex::encode(root).into_bytes())
                            })
                    } else {
                        RootRead::Missing
                    };
                    entry.insert(root);
                }
            }
            modes.push(
                self.config
                    .graph
                    .mode(rule, epoch, &|height| {
                        roots.get(&height).cloned().unwrap_or(RootRead::Missing)
                    })
                    .map_err(anyhow::Error::msg)?,
            );
        }
        Ok(transaction_outcome::Rules {
            envelope: modes[0],
            compute: modes[1],
            settle: modes[2],
        })
    }
    /// Capture public range inputs without performing any proof work or holding
    /// a producer lock for the duration of verification.
    pub fn single_range_task(
        &self,
        state: &Snapshot,
        tx: &Transaction,
        context: &Bound,
        epoch: i64,
    ) -> Result<Option<single_private::worker::Task>> {
        if tx.op_type != OpType::Stealth {
            return Ok(None);
        }
        let batch = StateBatch::from_snapshot(state.clone());
        let account = account_store::load(&batch, &tx.from)?
            .ok_or_else(|| anyhow::anyhow!("Single range sender missing"))?;
        let ledger = octra_node_protocol::state::Ledger::from_accounts(BTreeMap::from([(
            tx.from.clone(),
            account,
        )]))?;
        let Some(key) = self.single_key(batch.get(&[b"pvac_hashes", &tx.from]), &tx.from)? else {
            return Ok(None);
        };
        single_private::worker::Task::new(
            &ledger,
            tx,
            self.private_policy(context, epoch).balance,
            &key,
        )
        .map(Some)
        .map_err(anyhow::Error::msg)
    }
    pub fn single_preverify(
        &self,
        state: &Snapshot,
        tx: &Transaction,
        context: &Bound,
        epoch: i64,
    ) -> (Preverify, Option<single_private::CacheBinding>) {
        if tx.op_type != OpType::Stealth {
            return (Preverify::Ready, None);
        }
        let result = (|| {
            let batch = StateBatch::from_snapshot(state.clone());
            let ledger = account_store::ledger(&batch).map_err(|e| {
                octra_node_runtime::private_balance::Error::Unavailable(e.to_string())
            })?;
            let Some(key) = self.single_key(batch.get(&[b"pvac_hashes", &tx.from]), &tx.from)?
            else {
                return Ok(None);
            };
            single_private::CacheBinding::preverify(
                &ledger,
                tx,
                self.private_policy(context, epoch).balance,
                &key,
            )
            .map(Some)
        })();
        match result {
            Ok(binding) => (Preverify::Ready, binding),
            Err(octra_node_runtime::private_balance::Error::Rejected(f)) => (
                Preverify::Failed(f.preverify_reason.unwrap_or(f.reason)),
                None,
            ),
            Err(octra_node_runtime::private_balance::Error::Unavailable(reason)) => {
                (Preverify::Unavailable(reason.into_bytes()), None)
            }
        }
    }
    pub fn single_apply_kats(&self, kats: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
        std::fs::create_dir_all(&self.config.pvac_dir)?;
        for (address, kat) in kats {
            ensure!(
                octra_node_protocol::transaction::is_valid_address(address),
                "Single KAT recovery address invalid"
            );
            ensure!(
                kat == octra_node_runtime::crypto_payload::expected_kat().as_bytes(),
                "Single KAT recovery value differs"
            );
            let path = self
                .config
                .pvac_dir
                .join(format!("{}.kat", std::str::from_utf8(address)?));
            if std::fs::read(&path)
                .ok()
                .is_some_and(|raw| raw.split(|b| *b == b'\n').next() == Some(kat.as_slice()))
            {
                continue;
            }
            use std::io::Write;
            let mut staged = tempfile::NamedTempFile::new_in(&self.config.pvac_dir)?;
            staged.write_all(kat)?;
            staged.as_file().sync_all()?;
            staged.persist(&path)?;
            std::fs::File::open(&self.config.pvac_dir)?.sync_all()?;
        }
        Ok(())
    }
}
impl Native {
    /// Versioned local provenance over the actual captured execution settings.
    /// It is never a state root or consensus-profile hash.
    pub fn single_policy(&self, settings: &crate::single::Settings) -> Result<[u8; 32]> {
        Self::single_policy_for(&self.config, settings)
    }
    pub fn single_policy_for(
        config: &super::Config,
        settings: &crate::single::Settings,
    ) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let plans=octra_node_protocol::rules::ALL.into_iter().map(|rule|{let activation=config.graph.activation(rule);serde_json::json!({"rule":format!("{rule:?}"),"activation":activation.map(|a|serde_json::json!([a.anchor_epoch,a.anchor_state_root,a.activation_epoch]))})}).collect::<Vec<_>>();
        Ok(Sha256::digest(serde_json::to_vec(&serde_json::json!({"schema":"single-host-config-v1","chain":config.graph.chain_id(),"rules":plans,"ready_config":config.graph.ready_config_hash(),"migration_payload_sha256":config.migration.as_ref().map(|admission|hex::encode(Sha256::digest(admission.payload()))),"profile":format!("{:?}",config.profile),"payload":format!("{:?}",config.payload),"protocol":config.protocol.activation_epoch(),"validators":format!("{:?}",config.validators),"emission_guard":config.emission.emission_guard,"emission_schedule":format!("{:?}",config.emission.schedule),"emission_legacy_total":config.emission.legacy_total,"sender_key_activation":config.sender_key_activation,"private_result_activation":config.private_result_activation,"max_fhe":config.max_fhe,"max_stealth":config.max_stealth,"max_multi_exec_calls":config.max_multi_exec_calls,"ready_max_lag":config.ready_max_lag,"settings":settings}))?).into())
    }
}

impl Native {
    fn single_key(
        &self,
        hash: Option<&[u8]>,
        address: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, octra_node_runtime::private_balance::Error> {
        use octra_node_runtime::private_balance::Error as PrivateError;
        match hash {
            Some(b"none") => Ok(None),
            Some(hash) => self
                .key_blob(hash)
                .map_err(|e| PrivateError::Unavailable(e.0))?
                .map(Some)
                .ok_or_else(|| PrivateError::Unavailable("pvac blob unavailable".into())),
            None => {
                if !octra_node_protocol::transaction::is_valid_address(address) {
                    return Err(PrivateError::Unavailable(
                        "Single PVAC legacy address invalid".into(),
                    ));
                }
                let path = self
                    .config
                    .pvac_dir
                    .join(format!("{}.pk", String::from_utf8_lossy(address)));
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                    );
                }
                let Ok(file) = options.open(path) else {
                    return Ok(None);
                };
                let meta = file
                    .metadata()
                    .map_err(|e| PrivateError::Unavailable(e.to_string()))?;
                if !meta.is_file() {
                    return Ok(None);
                }
                if meta.len() > octra_node_runtime::pvac::MAX_BLOB_BYTES as u64 {
                    return Err(PrivateError::Unavailable(
                        "legacy PVAC blob exceeds local limit".into(),
                    ));
                }
                use std::io::Read;
                let mut raw = Vec::new();
                if file.take(meta.len()).read_to_end(&mut raw).is_err() {
                    return Ok(None);
                }
                Ok(Some(raw))
            }
        }
    }
}
