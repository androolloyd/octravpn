//! Staged native execution for authenticated finalized imports. The publisher
//! owns finality, canonical commits and ExEx; this host owns no canonical writer.
mod admission;
use crate::import::{Execution, Executor};
pub use admission::Limits;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::native_history::{ArchiveProof, NativeTransaction};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    consensus::{policy::Protocol, reward_attribution, EpochHeader},
    control_payload::{BondedReady, LegacyReady},
    preverify_commit::Gate,
    rules::{self, Graph, Rule},
    transaction::{OpType, RuleMode},
    transaction_outcome, transaction_payload, transaction_policy,
    validator::policy::Policy,
};
use octra_node_runtime::{
    account_store,
    canonical::Head,
    circle::CircleRuntime,
    circle_transaction,
    consensus_bundle::Rules,
    epoch_execution::{self, Effect},
    epoch_footer,
    execution::{Error, OperationHost, Route},
    execution_rules::Bound,
    finality::{history::History, ExecutedEpoch},
    private_balance,
    private_crypto::ResultPolicy,
    private_epoch, validator_epoch, validator_transaction,
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

/// Capture these native startup settings once. Peer data cannot select policy.
pub struct Config {
    pub graph: Graph,
    pub protocol: Protocol,
    pub profile: transaction_policy::Profile,
    pub payload: transaction_payload::Limits,
    pub bundle: Limits,
    pub validators: Policy,
    pub emission: epoch_footer::Policy,
    pub sender_key_activation: Option<i64>,
    pub private_result_activation: i64,
    pub max_fhe: usize,
    pub ready_max_lag: i64,
    /// Native PVAC directory, containing content-addressed `blobs/<hash>.pk`.
    pub pvac_dir: PathBuf,
}

#[derive(Clone)]
pub struct Native {
    config: Arc<Config>,
    runtime: CircleRuntime,
    history: Arc<dyn History>,
    worker: Arc<Semaphore>,
}
impl Native {
    pub fn new(config: Config, runtime: CircleRuntime, history: Arc<dyn History>) -> Result<Self> {
        ensure!(
            (0..1_i64 << 62).contains(&config.private_result_activation),
            "invalid private result activation epoch"
        );
        Ok(Self {
            config: Arc::new(config),
            runtime,
            history,
            worker: Arc::new(Semaphore::new(1)),
        })
    }

    async fn ready_roots(&self, request: &Execution<'_>) -> Result<BTreeMap<i64, Option<Vec<u8>>>> {
        let mut roots = BTreeMap::new();
        if request.rules.fold.context().ready_exec_mode == RuleMode::Active {
            return Ok(roots);
        }
        roots.insert(
            i64::try_from(request.parent.cursor.epoch.0)?,
            Some(request.parent.cursor.state_root.0.to_vec()),
        );
        for tx in request.bundle.partition().transactions() {
            if tx.op_type != OpType::ValidatorReady {
                continue;
            }
            let head = BondedReady::parse(tx.message.as_deref())
                .map(|r| r.head_epoch)
                .or_else(|_| LegacyReady::parse(tx.message.as_deref()).map(|r| r.head_epoch));
            let Ok(head) = head else {
                continue;
            };
            if roots.contains_key(&head)
                || !u64::try_from(head).is_ok_and(|height| height <= request.parent.cursor.epoch.0)
            {
                continue;
            }
            roots.insert(head, self.history.root(head).await?);
        }
        Ok(roots)
    }

    fn apply(
        &self,
        request: Execution<'_>,
        roots: &BTreeMap<i64, Option<Vec<u8>>>,
    ) -> Result<ExecutedEpoch> {
        let Execution {
            parent,
            mut state,
            finalized,
            reward_source: source,
            bundle,
            rules: context,
        } = request;
        let config = &self.config;
        let rules = self.rules(parent, &finalized.header, &context)?;
        ensure!(
            hex::encode(state.published_root()?) == parent.ledger_root,
            "execution snapshot differs from canonical parent"
        );
        let mut ledger = account_store::ledger(&state)?;
        admission::check(
            &config.profile,
            &config.bundle,
            &rules,
            bundle.bundle(),
            &ledger,
        )?;
        let authority = context.authority()?;
        let keys = authority
            .validators
            .validators
            .iter()
            .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
            .collect::<Vec<_>>();
        let members = keys
            .iter()
            .map(|(address, _)| address.clone())
            .collect::<Vec<_>>();
        let epoch = finalized.epoch_id;
        let reward = match source {
            Some(source) => reward_attribution::of_source(source)?,
            None => reward_attribution::resolve(
                &finalized.chain_id,
                epoch,
                config.protocol,
                &finalized.header.creator_addr,
                &keys,
                finalized.parent_commit.as_ref(),
            )?,
        };
        let reward = reward_attribution::bind_finality(&authority.validators, finalized, &reward)?;
        let receipts = transaction_outcome::split(&bundle.bundle().receipts_json, true)?;
        let gate = Gate::parse(&receipts.preverify).map_err(anyhow::Error::msg)?;
        let previous = hex::encode(parent.cursor.state_root.0);
        let mut calls = circle_transaction::Calls::new(
            &self.runtime,
            context.circle,
            epoch,
            finalized.header.ts,
            previous.as_bytes(),
            circle_transaction::Verification::Consume {
                root: parent.ledger_root.as_bytes(),
                gate: &gate,
            },
        );
        let fold = context.fold.context();
        let mut private = private_epoch::Epoch::new(
            private_balance::Profile {
                fields: context.private_payload,
                strict: fold.standard_mode == RuleMode::Active,
                math: if fold.math {
                    ScalarRule::Wide
                } else {
                    ScalarRule::Prior
                },
                result: if epoch >= config.private_result_activation {
                    ResultPolicy::Recoverable
                } else {
                    ResultPolicy::Legacy
                },
            },
            config.max_fhe,
            Some(&gate),
        );
        let root_at = |head| roots.get(&head).cloned().flatten();
        let mut validators = validator_transaction::Host {
            chain: &finalized.chain_id,
            epoch,
            policy: &config.validators,
            fold: context.fold.clone(),
            ready: validator_transaction::ReadyEnvironment {
                prev_state_root: previous.as_bytes(),
                max_lag: config.ready_max_lag,
                root_at: Some(&root_at),
            },
        };
        let committed = state.snapshot();
        state.begin()?;
        let request = epoch_execution::Request {
            validators: validator_epoch::Request {
                chain: &finalized.chain_id,
                epoch,
                policy: &config.validators,
                legacy_members: &members,
                previous_root: previous.as_bytes(),
                committed_head: Some(&committed),
            },
            envelope: rules.envelope,
            sender_key_activation: config.sender_key_activation,
            preverification: Some(epoch_execution::Preverification {
                gate: &gate,
                crypto_active: rules.crypto_active,
                minimum: &rules.stealth_minimum,
            }),
            emission: &config.emission,
            reward: &reward,
            validator_keys: &keys,
        };
        let executed = bundle.partition().execute(
            &request,
            &context.fold,
            &mut ledger,
            &mut state,
            |tx, ledger, state| {
                if transaction_policy::is_validator(tx.op_type) {
                    return Effect::from_completion(
                        tx,
                        validators.execute(Route::Validator, tx, ledger, state)?,
                    );
                }
                match tx.op_type {
                    OpType::Standard | OpType::Op01Burn => {
                        epoch_execution::public(tx, ledger, state)
                    }
                    OpType::Encrypt
                    | OpType::Decrypt
                    | OpType::Stealth
                    | OpType::Claim
                    | OpType::KeySwitch => {
                        private.process(tx, ledger, state, |hash| self.key_blob(hash))
                    }
                    OpType::CircleCall | OpType::CircleDeploy | OpType::CircleProgramUpdate => {
                        calls.process(tx, ledger, state)
                    }
                    _ => Err(Error(format!(
                        "execution host unavailable for {}",
                        tx.op_type.as_str()
                    ))),
                }
            },
        )?;
        let transactions = executed
            .artifacts
            .confirmed
            .iter()
            .enumerate()
            .map(|(offset, (input, _))| {
                let tx = &bundle.partition().transactions()[*input];
                let hash = hex::encode(tx.hash()?);
                let identity = tx.identity_bytes()?;
                Ok(NativeTransaction {
                    txid: parent
                        .txid_hi
                        .checked_add(
                            i64::try_from(offset)?
                                .checked_add(1)
                                .context("transaction index exhausted")?,
                        )
                        .context("transaction index exhausted")?,
                    hash: hash.clone(),
                    identity: identity.clone(),
                    transaction: identity,
                    proof: ArchiveProof::Exact,
                    receipt: calls.receipts().get(&hash).cloned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ExecutedEpoch {
            state: state.snapshot(),
            transactions,
            consensus_receipts: bundle.bundle().receipts_json.clone(),
            reward_source: reward_attribution::to_source(&reward)?,
            date: epoch,
            message: b"finalized epoch".to_vec(),
        })
    }

    fn key_blob(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if hash.len() != 64
            || !hash
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Error("invalid pvac blob hash".into()));
        }
        let name = format!(
            "{}.pk",
            std::str::from_utf8(hash).expect("checked hexadecimal hash")
        );
        match std::fs::read(self.config.pvac_dir.join("blobs").join(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error(format!("pvac blob unavailable: {error}"))),
        }
    }
}

#[async_trait::async_trait]
impl Executor for Native {
    fn graph(&self) -> Graph {
        self.config.graph.clone()
    }
    fn rules(&self, parent: &Head, header: &EpochHeader, context: &Bound) -> Result<Rules> {
        ensure!(
            header.chain_id == self.config.graph.chain_id()
                && parent.cursor.epoch.0.checked_add(1) == u64::try_from(header.epoch_id).ok()
                && header.prev_state_root == parent.cursor.state_root.0
                && header.proto_version == self.config.protocol.version_at(header.epoch_id),
            "execution configuration differs from finalized header"
        );
        let receipts = &context.authority()?.receipts;
        ensure!(
            receipts.crypto_active == self.config.profile.private_v1,
            "execution crypto profile differs from authenticated policy"
        );
        let mode = |rule| rules::at(&header.chain_id, rule, header.epoch_id);
        Ok(Rules {
            payload: self.config.payload,
            crypto_active: receipts.crypto_active,
            stealth_minimum: receipts.stealth_minimum.clone(),
            envelope: transaction_outcome::Rules {
                envelope: mode(Rule::TxEnvelope),
                compute: mode(Rule::VmBytes),
                settle: mode(Rule::Settle),
            },
        })
    }
    async fn execute(&self, request: Execution<'_>) -> Result<ExecutedEpoch> {
        self.rules(request.parent, &request.finalized.header, &request.rules)?;
        let roots = self.ready_roots(&request).await?;
        let host = self.clone();
        let parent = request.parent.clone();
        let finalized = request.finalized.clone();
        let source = request.reward_source.cloned();
        run_worker(self.worker.clone(), move || {
            host.apply(
                Execution {
                    parent: &parent,
                    state: request.state,
                    finalized: &finalized,
                    reward_source: source.as_ref(),
                    bundle: request.bundle,
                    rules: request.rules,
                },
                &roots,
            )
        })
        .await
    }
}

async fn run_worker<T: Send + 'static>(
    worker: Arc<Semaphore>,
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let permit = worker
        .try_acquire_owned()
        .context("native execution worker busy")?;
    tokio::task::spawn_blocking(move || {
        // Cancellation of the async importer cannot admit a second CPU job
        // while this non-cancellable blocking worker still owns its state.
        let _permit = permit;
        job()
    })
    .await
    .context("native execution worker failed")?
}

#[cfg(test)]
mod tests {
    use super::run_worker;
    use std::{
        sync::{mpsc, Arc},
        time::Duration,
    };
    use tokio::sync::{oneshot, Semaphore};

    #[tokio::test]
    async fn cancelled_import_keeps_its_worker_until_execution_stops() {
        let worker = Arc::new(Semaphore::new(1));
        let running = worker.clone();
        let (started, ready) = oneshot::channel();
        let (release, wait) = mpsc::channel();
        let task = tokio::spawn(run_worker(running, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        }));
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(run_worker(worker.clone(), || Ok(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("worker busy"));
        release.send(()).unwrap();
        drop(
            tokio::time::timeout(Duration::from_secs(5), worker.clone().acquire_owned())
                .await
                .unwrap()
                .unwrap(),
        );
        run_worker(worker, || Ok(())).await.unwrap();
    }
}
