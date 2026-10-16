//! First-party validator duty uses the configured operator identity and the
//! ordinary authenticated transaction queue. It never manufactures a vote.
use crate::import::Executor as _;
use crate::{peers::Authority, rpc::Submission, Committed, Host};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::codec::Wire,
    duty,
    light_rpc::json::{object, string},
    native_json::{Document, Value},
    network::{frame::Frame, transaction_gossip::Message},
    rules::{self, Rule},
    transaction::{OpType, RuleMode, Transaction},
    transaction_policy,
    validator::{
        admission::Candidate,
        intent::Identity,
        registry::{self, Registry},
        set_fold,
    },
};
use octra_node_runtime::{
    account_store,
    state_batch::StateBatch,
    validator_control::{Control, DutyGuard},
    validator_duty::{
        self as actor, control,
        post::{self, Eligibility, Failure},
        Action, Fault, Sample, Stage,
    },
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

fn now() -> Result<f64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs_f64())
        .map_err(|e| e.to_string())
}
fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
struct Capture {
    view: Committed,
    epoch: i64,
    candidate: Option<Candidate>,
    mode: RuleMode,
    active: bool,
}
struct Delivery<A: Host> {
    submission: Arc<Submission<A>>,
    authority: Authority,
    key: SigningKey,
    control: Control,
    client: reqwest::Client,
    operator_rpc: Option<String>,
    enabled: AtomicBool,
}
impl<A: Host> Delivery<A> {
    fn capture(&self) -> Result<Capture, String> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err("validator duty is stopped".into());
        }
        let view = self.submission.node.snapshot().map_err(text)?;
        let epoch = i64::try_from(view.head().cursor.epoch.0)
            .map_err(text)?
            .checked_add(1)
            .ok_or("validator duty epoch overflow")?;
        let registry = view
            .state()
            .get(&[b"meta", registry::META_KEY])
            .map(Registry::from_bytes)
            .transpose()
            .map_err(text)?
            .unwrap_or_default();
        let candidate = registry.find(&self.submission.address).cloned();
        if candidate
            .as_ref()
            .is_some_and(|c| c.pubkey.as_slice() != self.key.verifying_key().as_bytes().as_slice())
        {
            return Err("validator duty enrollment public key differs".into());
        }
        let chain = self.submission.node.store.chain().chain_id.as_bytes();
        Ok(Capture {
            view,
            epoch,
            candidate,
            mode: rules::at(chain, Rule::ReadyExecution, epoch),
            active: self
                .authority
                .compute_validators()
                .is_validator(&self.submission.address),
        })
    }
    fn identity(&self, candidate: &Candidate) -> Identity {
        Identity {
            chain_id: self
                .submission
                .node
                .store
                .chain()
                .chain_id
                .as_bytes()
                .to_vec(),
            address: self.submission.address.clone(),
            pubkey: STANDARD
                .encode(self.key.verifying_key().as_bytes())
                .into_bytes(),
            bonded_epoch: candidate.bonded_epoch,
        }
    }
    fn bonded(&self, capture: &Capture) -> Result<bool, String> {
        if rules::at(
            self.submission.node.store.chain().chain_id.as_bytes(),
            Rule::SetFold,
            capture.epoch,
        ) != RuleMode::Active
        {
            return Ok(false);
        }
        control::bonded(
            &self.control,
            &self.submission.address,
            STANDARD
                .encode(self.key.verifying_key().as_bytes())
                .as_bytes(),
            Ok(control::Enrollment {
                chain_id: self.submission.node.store.chain().chain_id.as_bytes(),
                head_epoch: capture.epoch - 1,
                candidate: capture.candidate.as_ref(),
            }),
        )
    }
    fn account(&self, capture: &Capture) -> Result<octra_node_protocol::state::Account, String> {
        account_store::load(
            &StateBatch::from_snapshot(capture.view.state().clone()),
            &self.submission.address,
        )
        .map_err(text)?
        .ok_or_else(|| "validator set fold account is unavailable".into())
    }
    fn point(&self, epoch: i64) -> Result<Capture, String> {
        let capture = self.capture()?;
        let driver = self
            .authority
            .driver()
            .map_err(text)?
            .ok_or("consensus driver unavailable")?;
        let status = driver.status().borrow().clone();
        actor::plan(
            epoch,
            actor::Point {
                epoch: capture.epoch,
                head: Some(capture.epoch - 1),
                finalized: status.height == epoch && status.finalized,
            },
        )
        .map_err(octra_node_runtime::validator_duty::Refusal::reason)?;
        if status.height != epoch || !status.started {
            return Err("validator duty epoch changed".into());
        }
        Ok(capture)
    }
    async fn proposal_id(&self, view: &Committed) -> Result<Option<String>, String> {
        let head = view.head();
        let certificate = if head.cursor.sequence.0 == 0 {
            self.submission
                .node
                .store
                .checkpoint_parent()
                .ok_or("validator duty head certificate is unavailable")?
                .certificate
        } else {
            self.submission
                .node
                .publisher
                .record(head.cursor.sequence)
                .await
                .map_err(text)?
                .finality
                .ok_or("validator duty head certificate is unavailable")?
                .finalize
                .certificate()
        };
        if certificate.epoch_id != head.cursor.epoch.0 as i64
            || certificate.chain_id != self.submission.node.store.chain().chain_id.as_bytes()
            || certificate.header.proposed_state_root != head.cursor.state_root.0
            || certificate.proposal_id.len() != 32
        {
            return Err("validator duty head certificate differs".into());
        }
        Ok(Some(hex::encode(certificate.proposal_id)))
    }
    async fn expire(&self, sender: Option<Vec<u8>>) -> Result<(), String> {
        let admission = Arc::new(
            self.submission
                .node
                .admission_capture(
                    &self.submission.executor.graph(),
                    self.submission.policy,
                    &self.submission.address,
                    now()?,
                )
                .await
                .map_err(text)?,
        );
        let pending = self.submission.pending.clone();
        tokio::task::spawn_blocking(move || {
            pending.expire_duty(admission.draft(), sender.as_deref())
        })
        .await
        .map_err(text)?
        .map_err(text)
    }
    async fn stage(
        &self,
        tx: Transaction,
        capture: &Capture,
        current: &(dyn Fn() -> bool + Send + Sync),
        guard: Arc<DutyGuard>,
        wallet: Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) -> Result<Vec<u8>, String> {
        if tx.op_type != OpType::ValidatorReady {
            return Err("validator duty operation required".into());
        }
        if !current() {
            return Err("validator duty head changed".into());
        }
        let fresh = self.capture()?;
        if fresh.view.head() != capture.view.head()
            || !self.bonded(&fresh)?
            || self.account(&fresh)?.nonce >= tx.nonce
        {
            return Err("validator duty head changed".into());
        }
        if duty::expired(&tx, Some(fresh.epoch - 1), fresh.mode) {
            return Err("validator ready head has expired".into());
        }
        let expected = hex::encode(tx.hash().map_err(text)?).into_bytes();
        // The shared staging path checks current relay fees and preview state
        // before its native exact-hash ValidatorReady retry shortcut.
        let admission = Arc::new(
            self.submission
                .node
                .admission_capture(
                    &self.submission.executor.graph(),
                    self.submission.policy,
                    &self.submission.address,
                    now()?,
                )
                .await
                .map_err(text)?,
        );
        if admission.draft().context().parent() != capture.view.head() || !current() {
            return Err("validator duty head changed".into());
        }
        let hash = self
            .submission
            .executor
            .submit_duty(admission, &self.submission.pending, tx, guard, wallet)
            .await
            .map_err(text)?;
        if hash != expected {
            return Err("validator duty staging hash mismatch".into());
        }
        (self.submission.staging_notify)();
        Ok(hash)
    }
    async fn post_rpc(&self, tx: &Transaction) -> Result<(), Failure> {
        let Some(url) = &self.operator_rpc else {
            return Ok(());
        };
        let result = async {
            let mut body =
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"octra_submit\",\"params\":[".to_vec();
            body.extend(tx.to_json_bytes().map_err(text)?);
            body.extend_from_slice(b"]}");
            let mut response = self
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(text)?;
            let status = response.status().as_u16();
            let mut raw = vec![];
            while let Some(chunk) = response.chunk().await.map_err(text)? {
                if chunk.len() > 65_536 - raw.len() {
                    return Ok(Err(Failure::Refused(
                        "validator duty RPC response exceeds limit".into(),
                    )));
                }
                raw.extend_from_slice(&chunk);
            }
            if !(200..300).contains(&status) {
                return Ok(Err(post::http_failure(status)));
            }
            let doc = Document::parse(&raw).map_err(text)?;
            let result = if !matches!(doc.root(), Value::Object(_)) {
                Err(Failure::Retry(
                    "validator duty RPC response is invalid".into(),
                ))
            } else if let Some(error) = doc.field(doc.root(), b"error") {
                Err(post::rpc_failure(&doc, error))
            } else if doc.field(doc.root(), b"result").is_some() {
                Ok(())
            } else {
                Err(Failure::Retry("validator duty RPC result is absent".into()))
            };
            Ok::<_, String>(result)
        };
        tokio::time::timeout(Duration::from_secs(5), result)
            .await
            .map_err(|_| Failure::Retry("validator duty RPC deadline exceeded".into()))?
            .map_err(Failure::Retry)?
    }
}
#[async_trait::async_trait]
impl<A: Host> post::Host for Delivery<A> {
    fn staged(&self, hash: &[u8]) -> bool {
        self.submission
            .pending
            .inspect(|pool| pool.find(hash).is_some())
            // Queue contention cannot prove an exact delivery has vanished.
            .unwrap_or(true)
    }
    fn landed(&self, tx: &Transaction) -> bool {
        self.capture()
            .and_then(|c| self.account(&c))
            .is_ok_and(|a| a.nonce >= tx.nonce)
    }
    fn eligible(&self, tx: &Transaction, bonded_epoch: Option<i64>) -> Eligibility {
        let Some(bonded_epoch) = bonded_epoch else {
            return Eligibility::Eligible;
        };
        let Some(head) = self
            .submission
            .node
            .store
            .cached_head()
            .and_then(|h| i64::try_from(h.cursor.epoch.0).ok())
        else {
            return Eligibility::Paused;
        };
        let mode = rules::at(
            self.submission.node.store.chain().chain_id.as_bytes(),
            Rule::ReadyExecution,
            head + 1,
        );
        let capture = self.capture();
        control::eligible(
            mode,
            head,
            bonded_epoch,
            capture
                .as_ref()
                .map(|c| control::Enrollment {
                    chain_id: self.submission.node.store.chain().chain_id.as_bytes(),
                    head_epoch: c.epoch - 1,
                    candidate: c.candidate.as_ref(),
                })
                .map_err(String::as_str),
            tx,
        )
    }
    async fn post(
        &self,
        tx: Transaction,
        bonded_epoch: Option<i64>,
        current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<(), Failure> {
        let wallet = Arc::new(self.submission.executor.operator_wallet().await);
        let capture = self.capture().map_err(Failure::Wait)?;
        let candidate = capture
            .candidate
            .as_ref()
            .filter(|c| Some(c.bonded_epoch) == bonded_epoch && c.exit_epoch.is_none())
            .ok_or_else(|| Failure::Wait("validator duty enrollment changed".into()))?;
        let lease = Arc::new(
            self.control
                .duty_guard(&self.identity(candidate))
                .map_err(|e| Failure::Wait(e.to_string()))?,
        );
        if !current() || self.eligible(&tx, bonded_epoch) != Eligibility::Eligible {
            return Err(Failure::Wait("validator duty head changed".into()));
        }
        let hash = self
            .stage(
                tx.clone(),
                &capture,
                current.as_ref(),
                lease.clone(),
                wallet.clone(),
            )
            .await
            .map_err(Failure::Wait)?;
        drop(lease);
        drop(wallet);
        let tx_json = tx
            .to_json_bytes()
            .map_err(|e| Failure::Refused(e.to_string()))?;
        let payload = Message::Transaction {
            hash,
            json: tx_json,
        }
        .encode()
        .map_err(|e| Failure::Refused(e.to_string()))?;
        self.submission
            .swarm
            .broadcast(
                Frame {
                    message: 0x20,
                    payload,
                },
                None,
                false,
            )
            .await
            .map_err(|e| Failure::Retry(e.to_string()))?;
        match self.post_rpc(&tx).await {
            Err(Failure::Refused(reason)) => Err(Failure::Retry(reason)),
            result => result,
        }
    }
    fn warn(&self, reason: &str) {
        eprintln!("validator: event = set_post_failed reason = {reason}");
    }
}
struct Duty<A: Host> {
    delivery: Arc<Delivery<A>>,
    post: post::Post<Delivery<A>>,
}
#[async_trait::async_trait]
impl<A: Host> actor::Host for Duty<A> {
    fn sample(&self) -> Sample {
        match self.delivery.capture() {
            Ok(capture) => Sample {
                epoch: capture.epoch,
                active: capture.active,
                bonded: self.delivery.bonded(&capture),
            },
            Err(reason) => Sample {
                epoch: self
                    .delivery
                    .submission
                    .node
                    .store
                    .cached_head()
                    .and_then(|h| i64::try_from(h.cursor.epoch.0).ok())
                    .map_or(-1, |e| e.wrapping_add(1)),
                active: false,
                bonded: Err(reason),
            },
        }
    }
    async fn read(&self, epoch: i64) -> Result<set_fold::Receipt, String> {
        let capture = self.delivery.capture()?;
        if capture.epoch != epoch {
            return Err("validator duty head is not committed".into());
        }
        let raw = capture
            .view
            .state()
            .get(&[b"meta", set_fold::META_KEY])
            .ok_or("committed validator duty is unavailable")?;
        Ok(set_fold::State::from_bytes(raw)
            .map_err(text)?
            .receipt(&self.delivery.submission.address))
    }
    fn peers(&self) -> usize {
        self.delivery.submission.swarm.peers().len()
    }
    async fn send(&self, epoch: i64, action: Action) -> Result<(), (Fault, String)> {
        if self.post.pending() {
            self.post.tick();
            return Ok(());
        }
        let result = async {
            let capture = self.delivery.point(epoch).map_err(|e| (Fault::Send, e))?;
            if rules::at(
                self.delivery
                    .submission
                    .node
                    .store
                    .chain()
                    .chain_id
                    .as_bytes(),
                Rule::SetFold,
                epoch,
            ) != RuleMode::Active
            {
                return Err((Fault::Send, "validator set fold rule is not active".into()));
            }
            let proposal = if capture.mode == RuleMode::Active {
                self.delivery
                    .proposal_id(&capture.view)
                    .await
                    .map_err(|e| (Fault::Receipt, e))?
            } else {
                None
            };
            let status = self.delivery.submission.status.as_ref().ok_or((
                Fault::Receipt,
                "validator duty profile is unavailable".into(),
            ))?;
            let config = status
                .ready_config_hash(capture.view.head())
                .await
                .map_err(|e| {
                    (
                        Fault::Receipt,
                        String::from_utf8_lossy(&e.message).into_owned(),
                    )
                })?;
            self.delivery
                .expire(Some(self.delivery.submission.address.clone()))
                .await
                .map_err(|e| (Fault::Send, e))?;
            let wallet = Arc::new(self.delivery.submission.executor.operator_wallet().await);
            let fresh = self.delivery.point(epoch).map_err(|e| (Fault::Send, e))?;
            if fresh.view.head() != capture.view.head() {
                return Err((Fault::Send, "validator duty head changed".into()));
            }
            let candidate = fresh
                .candidate
                .as_ref()
                .filter(|c| c.exit_epoch.is_none())
                .ok_or((Fault::Receipt, "validator duty enrollment changed".into()))?;
            let lease = Arc::new(
                self.delivery
                    .control
                    .duty_guard(&self.delivery.identity(candidate))
                    .map_err(|e| (Fault::Control, e.to_string()))?,
            );
            let account = self
                .delivery
                .account(&fresh)
                .map_err(|e| (Fault::Send, e))?;
            let nonce = self
                .delivery
                .submission
                .pending
                .inspect(|pool| pool.duty_nonce(&self.delivery.submission.address, account.nonce))
                .map_err(|e| (Fault::Send, e.to_string()))?
                .ok_or((Fault::Send, "validator duty nonce is pending".into()))?;
            let mut fields = vec![
                (
                    "consensus_pubkey",
                    string(STANDARD.encode(self.delivery.key.verifying_key().as_bytes())),
                ),
                ("head_epoch", string((epoch - 1).to_string())),
                (
                    "state_root",
                    string(hex::encode(fresh.view.head().cursor.state_root.0)),
                ),
                (
                    "chain_id",
                    string(
                        self.delivery
                            .submission
                            .node
                            .store
                            .chain()
                            .chain_id
                            .as_bytes(),
                    ),
                ),
                ("config_hash", string(hex::encode(config))),
                ("catchup_head_epoch", string((epoch - 1).to_string())),
            ];
            if let Some(proposal) = &proposal {
                fields.push(("head_proposal_id", string(proposal)));
            }
            if let Action::Appeal(proof) = action {
                fields.push((
                    "duty_vote",
                    string(
                        STANDARD.encode(
                            proof
                                .vote
                                .encode()
                                .map_err(|e| (Fault::Send, e.to_string()))?,
                        ),
                    ),
                ));
                fields.push((
                    "duty_commit",
                    string(
                        STANDARD.encode(
                            proof
                                .commit
                                .encode()
                                .map_err(|e| (Fault::Send, e.to_string()))?,
                        ),
                    ),
                ));
            }
            let mut tx = Transaction {
                from: self.delivery.submission.address.clone(),
                to: self.delivery.submission.address.clone(),
                amount: 0.into(),
                nonce,
                ou: 0.into(),
                timestamp: now().map_err(|e| (Fault::Send, e))?,
                signature: vec![],
                public_key: Some(
                    STANDARD
                        .encode(self.delivery.key.verifying_key().as_bytes())
                        .into_bytes(),
                ),
                message: Some(object(&fields)),
                op_type: OpType::ValidatorReady,
                encrypted_data: None,
            };
            tx.ou = transaction_policy::ou_cost(&tx, &0.into());
            tx.signature = STANDARD
                .encode(
                    self.delivery
                        .key
                        .sign(
                            &tx.signing_bytes()
                                .map_err(|e| (Fault::Send, e.to_string()))?,
                        )
                        .to_bytes(),
                )
                .into_bytes();
            let hash = self
                .delivery
                .stage(
                    tx.clone(),
                    &fresh,
                    &|| self.delivery.enabled.load(Ordering::Acquire),
                    lease.clone(),
                    wallet.clone(),
                )
                .await
                .map_err(|e| (Fault::Send, e))?;
            drop(lease);
            drop(wallet);
            self.post.put(
                hash,
                tx,
                Some(post::Retry {
                    bonded_epoch: candidate.bonded_epoch,
                    retain: proposal.is_some(),
                }),
            );
            Ok(())
        };
        result.await
    }
    fn warn(&self, fault: Fault, reason: &str) {
        eprintln!("validator: event = {} reason = {reason}", fault.event());
    }
    fn observe(&self, stage: Stage, epoch: i64, proof: &duty::Proof) {
        match actor::proof_key(proof) {
            Ok(key) => eprintln!("validator: event = set_proof stage = {} proof = {key} vote_epoch = {} round = {} epoch = {epoch}",stage.name(),proof.vote.epoch_id,proof.vote.round),
            Err(reason) => self.warn(Fault::Internal,&reason),
        }
    }
}
pub(crate) struct Service<A: Host> {
    actor: actor::Actor<Duty<A>>,
    delivery: Arc<Delivery<A>>,
    post: post::Post<Delivery<A>>,
}
impl<A: Host> Service<A> {
    /// Call only for the explicitly configured voting operator with bonded
    /// lifecycle policy enabled. Observers never instantiate this signer.
    pub(crate) fn new(
        submission: Arc<Submission<A>>,
        authority: Authority,
        key: SigningKey,
        data: &std::path::Path,
        operator_rpc: Option<String>,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .user_agent("octra-validator-duty/1")
            .build()?;
        let delivery = Arc::new(Delivery {
            submission,
            authority,
            key,
            control: Control::new(data),
            client,
            operator_rpc,
            enabled: AtomicBool::new(true),
        });
        let post = post::Post::new(delivery.clone());
        let actor = actor::Actor::new(Arc::new(Duty {
            delivery: delivery.clone(),
            post: post.clone(),
        }));
        Ok(Self {
            actor,
            delivery,
            post,
        })
    }
    pub(crate) fn handler(&self) -> octra_node_runtime::consensus_driver::DutyHandler {
        let actor = self.actor.clone();
        Arc::new(move |epoch, proof| {
            let _ = actor.notify(epoch, proof);
        })
    }
    pub(crate) async fn run(
        self: Arc<Self>,
        mut stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let mut observed = None;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { _=stop.wait_for(|v|*v)=>break, _=interval.tick()=>() }
            let head = self.delivery.submission.node.store.cached_head();
            let serving = self.delivery.submission.node.snapshot().is_ok();
            let driver = self
                .delivery
                .authority
                .driver()
                .ok()
                .flatten()
                .map(|handle| {
                    let status = handle.status().borrow().clone();
                    (status.height, status.started)
                });
            let current = head.as_ref().map(|h| {
                (
                    h.cursor,
                    self.delivery.submission.swarm.peers().len(),
                    serving,
                    driver,
                )
            });
            if observed != current {
                if let Some(head) = head {
                    if serving {
                        if let Err(reason) = self.delivery.expire(None).await {
                            eprintln!(
                                "validator: event = {} reason = {reason}",
                                Fault::Send.event()
                            );
                        }
                        self.post.tick();
                        let _ = self.actor.wake(head.cursor.epoch.0 as i64);
                    }
                }
                observed = current;
            }
        }
        self.delivery.enabled.store(false, Ordering::Release);
        self.actor.stop();
        self.post.stop();
        self.actor.shutdown().await;
        self.post.shutdown().await;
        Ok(())
    }
}
impl<A: Host> Drop for Service<A> {
    fn drop(&mut self) {
        self.delivery.enabled.store(false, Ordering::Release);
        self.actor.stop();
        self.post.stop();
    }
}
