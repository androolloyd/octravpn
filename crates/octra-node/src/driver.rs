//! Executable validator host. Canonical history supplies authority; local
//! execution supplies voting evidence and the native journal supplies durability.
use crate::{
    executor::{Built, Native, Pending, Prepared, ProposalError},
    import::Executor,
    peers, Host, Node,
};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{
        codec::Wire, evidence::VoteConflict, hash, journal::JournalOwner, Bytes, Error,
        ParentCommit, Proposal, ValidatorSet,
    },
    network::swarm::Swarm,
};
use octra_node_runtime::{
    bundle_queries::Bundles,
    canonical::Head,
    consensus_bundle,
    consensus_driver::{Host as DriverHost, ProposalPlan, Verdict},
    consensus_recovery,
    consensus_votes::{Precommit, Readiness},
    finality::{proposal::Policy, EpochRules},
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

fn error(e: impl std::fmt::Display) -> Error {
    e.to_string().into()
}
fn now() -> Result<f64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs_f64())
        .map_err(error)
}
enum Evidence {
    Built(Arc<Built>),
    Prepared(Arc<Prepared>),
}
impl Evidence {
    fn epoch(&self) -> i64 {
        match self {
            Self::Built(v) => v.plan().header.epoch_id,
            Self::Prepared(v) => v.candidate().context().proposal().epoch_id,
        }
    }
    fn raw(&self) -> &consensus_bundle::RawBundle {
        match self {
            Self::Built(v) => v.bundle(),
            Self::Prepared(v) => v.bundle(),
        }
    }
    fn current<A: Host>(&self, node: &Node<A>) -> bool {
        match self {
            Self::Built(v) => node.draft_current(v.draft()),
            Self::Prepared(v) => node.proposal_current(v.candidate()),
        }
    }
    fn rules(&self, native: &Native) -> anyhow::Result<consensus_bundle::Rules> {
        match self {
            Self::Built(v) => native.draft_rules(v.draft()),
            Self::Prepared(v) => native.proposal_rules(v.candidate()),
        }
    }
}
struct Epoch {
    head: Head,
    number: i64,
    parent: Option<ParentCommit>,
    rules: EpochRules,
}
#[derive(Default)]
struct Cache {
    epoch: Option<Arc<Epoch>>,
    frozen: BTreeMap<(i64, i64), Arc<Built>>,
    executions: BTreeMap<[u8; 32], Arc<Evidence>>,
}
#[derive(Clone)]
pub struct Config {
    pub key: SigningKey,
    pub address: Bytes,
    pub policy: Policy,
    pub journal: JournalOwner,
    pub epoch_capacity: num_bigint::BigInt,
    pub stealth_slots: usize,
    pub evidence_dir: PathBuf,
}
pub struct Validator<A: Host> {
    node: Arc<Node<A>>,
    executor: Native,
    pending: Arc<Pending>,
    peers: peers::Authority,
    bundles: Bundles<peers::Authority>,
    swarm: Swarm,
    config: Config,
    cache: Mutex<Cache>,
    enabled: AtomicBool,
}
impl<A: Host> Validator<A> {
    pub fn new(
        node: Arc<Node<A>>,
        executor: Native,
        pending: Arc<Pending>,
        network: &peers::Network,
        config: Config,
    ) -> Result<Self, Error> {
        Self::with_peers(
            node,
            executor,
            pending,
            network.authority.clone(),
            network.bundles.clone(),
            network.swarm.clone(),
            config,
        )
    }
    pub(crate) fn with_peers(
        node: Arc<Node<A>>,
        executor: Native,
        pending: Arc<Pending>,
        peers: peers::Authority,
        bundles: Bundles<peers::Authority>,
        swarm: Swarm,
        config: Config,
    ) -> Result<Self, Error> {
        if config.stealth_slots > 128 || config.epoch_capacity <= 0.into() {
            return Err("invalid staging limits".into());
        }
        Ok(Self {
            node,
            executor,
            pending,
            peers,
            bundles,
            swarm,
            config,
            cache: Mutex::default(),
            enabled: AtomicBool::new(false),
        })
    }
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }
    /// Seed a nonvoting observer from its authenticated retained head while
    /// public service admission remains suspended during catch-up.
    pub(crate) async fn activate_retained(&self, number: i64) -> Result<ValidatorSet, Error> {
        let head = self.node.head().await.map_err(error)?;
        self.activate_at(number, head).await
    }
    async fn activate_at(&self, number: i64, head: Head) -> Result<ValidatorSet, Error> {
        if i64::try_from(head.cursor.epoch.0)
            .map_err(error)?
            .checked_add(1)
            != Some(number)
        {
            return Err("activation is not consecutive".into());
        }
        let relief = self
            .node
            .store
            .reader()
            .relief_after(&head)
            .await
            .map_err(error)?;
        let rules = self
            .node
            .host
            .resolve(&head, number as u64, relief)
            .await
            .map_err(error)?;
        let parent = self
            .node
            .publisher
            .proposal_parent(&head, self.config.policy)
            .await
            .map_err(error)?;
        self.swarm.advance_profile(number)?;
        let validators = rules.validators.clone();
        self.swarm.set_validators(
            validators
                .validators
                .iter()
                .map(|member| member.pubkey.clone())
                .collect(),
        )?;
        self.peers.set_validators(validators.clone())?;
        self.peers.prune(number - 1)?;
        let mut cache = self.cache.lock().map_err(error)?;
        cache.frozen.retain(|(epoch, _), _| *epoch >= number);
        cache.executions.retain(|_, v| v.epoch() >= number);
        cache.epoch = Some(Arc::new(Epoch {
            head,
            number,
            parent,
            rules,
        }));
        Ok(validators)
    }
    /// Restore only the next epoch's authenticated lock, after re-executing its
    /// durable bundle against the canonical parent. Never discard an unresolved lock.
    pub async fn recover(
        &self,
        engine: &mut octra_node_protocol::consensus::engine::Engine,
    ) -> Result<(), Error> {
        let epoch = self.epoch()?;
        self.recover_at(engine, epoch).await
    }
    /// Check an observer's durable journal against its retained head while
    /// external serving remains suspended during authenticated catch-up.
    pub(crate) async fn recover_retained(
        &self,
        engine: &mut octra_node_protocol::consensus::engine::Engine,
    ) -> Result<(), Error> {
        let epoch = self.cached_epoch()?;
        if self.node.head().await.map_err(error)? != epoch.head {
            return Err("validator view advanced".into());
        }
        self.recover_at(engine, epoch).await
    }
    async fn recover_at(
        &self,
        engine: &mut octra_node_protocol::consensus::engine::Engine,
        epoch: Arc<Epoch>,
    ) -> Result<(), Error> {
        let journal = self.config.journal.clone();
        let records = tokio::task::spawn_blocking(move || journal.pending())
            .await
            .map_err(error)??;
        let pending = records
            .iter()
            .filter(|p| p.epoch_id >= epoch.number)
            .collect::<Vec<_>>();
        if pending.iter().any(|p| p.epoch_id != epoch.number) {
            return Err("pending journal is ahead of canonical history".into());
        }
        let Some(record) = pending.into_iter().max_by_key(|p| p.round) else {
            return Ok(());
        };
        let wire = record
            .proposal_b64
            .as_ref()
            .ok_or("legacy pending record requires peer reconciliation")?;
        let proposal =
            Proposal::decode(&octra_node_protocol::native_base64::decode(wire).map_err(error)?)?;
        let candidate = Arc::new(
            self.node
                .proposal_candidate(
                    &proposal,
                    &self.executor.graph(),
                    self.config.policy,
                    now()?,
                )
                .await
                .map_err(error)?,
        );
        let rules = self.executor.proposal_rules(&candidate).map_err(error)?;
        let context = consensus_recovery::Context {
            chain_id: &proposal.chain_id,
            validator_set: &epoch.rules.validators,
            protocol: self.config.policy.protocol,
            rules: &rules,
        };
        let recovered = consensus_recovery::recover(&context, record)?;
        if recovered.vote.validator != self.config.address {
            return Err("pending lock belongs to another validator".into());
        }
        let prepared = Arc::new(
            self.executor
                .verify_proposal(candidate, &recovered.bundle.to_raw()?)
                .await
                .map_err(error)?,
        );
        let id = hash::proposal_id(&proposal.header)?;
        self.peers
            .cache(epoch.number, id, prepared.bundle().clone())?;
        self.cache
            .lock()
            .map_err(error)?
            .executions
            .insert(id, Arc::new(Evidence::Prepared(prepared)));
        engine.restore_precommit_lock(recovered.proposal)
    }
    fn epoch(&self) -> Result<Arc<Epoch>, Error> {
        let epoch = self.cached_epoch()?;
        if self.node.snapshot().map_err(error)?.head() != &epoch.head {
            return Err("validator view advanced".into());
        }
        Ok(epoch)
    }
    fn cached_epoch(&self) -> Result<Arc<Epoch>, Error> {
        let epoch = self
            .cache
            .lock()
            .map_err(error)?
            .epoch
            .clone()
            .ok_or("validator epoch unavailable")?;
        Ok(epoch)
    }
    fn plan(built: &Built) -> ProposalPlan {
        ProposalPlan {
            header: built.plan().header.clone(),
            tx_hashes: built.plan().tx_hashes.clone(),
            parent_commit: built.plan().parent_commit.clone(),
        }
    }
    async fn precommit(&self, request: Precommit) -> Result<bool, Error> {
        let epoch = self.epoch()?;
        let proposal = Proposal::decode(&request.proposal_wire)?;
        let id = hash::proposal_id(&proposal.header)?;
        let evidence = self
            .cache
            .lock()
            .map_err(error)?
            .executions
            .get(&id)
            .cloned()
            .ok_or("local proposal execution unavailable")?;
        if evidence.epoch() != epoch.number || !evidence.current(&self.node) {
            return Ok(false);
        }
        let rules = evidence.rules(&self.executor).map_err(error)?;
        let journal = self.config.journal.clone();
        let address = self.config.address.clone();
        let protocol = self.config.policy.protocol;
        let time = now()?;
        let saved = evidence.clone();
        tokio::task::spawn_blocking(move || {
            consensus_recovery::before_precommit(
                &consensus_recovery::Context {
                    chain_id: &proposal.chain_id,
                    validator_set: &epoch.rules.validators,
                    protocol,
                    rules: &rules,
                },
                &journal,
                &address,
                &request,
                saved.raw(),
                &saved.raw().tx_hashes,
                time,
                |_| Err("local bundle changed".into()),
            )
        })
        .await
        .map_err(error)??;
        Ok(evidence.current(&self.node))
    }
}
#[async_trait::async_trait]
impl<A: Host> DriverHost for Validator<A> {
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Ok(self.config.key.sign(bytes).to_bytes().to_vec())
    }
    fn readiness(&self) -> Readiness {
        let epoch = self.epoch().ok();
        Readiness {
            role_can_vote: epoch.as_ref().is_some_and(|e| {
                e.rules.validators.public_key(&self.config.address)
                    == Some(self.config.key.verifying_key().as_bytes())
            }),
            can_vote: self.enabled.load(Ordering::Acquire)
                && epoch.is_some()
                && matches!(self.node.status(), crate::Status::Serving(_)),
            finality_proof_needed: false,
        }
    }
    fn verify_parent(&self, number: i64, parent: Option<&ParentCommit>) -> Result<(), Error> {
        let epoch = self.epoch()?;
        if epoch.number != number {
            return Err("parent check epoch differs".into());
        }
        octra_node_runtime::finality::proposal::check_parent(epoch.parent.as_ref(), parent)
            .map_err(error)
    }
    async fn build(&self, number: i64) -> Result<Option<ProposalPlan>, Error> {
        let epoch = self.epoch()?;
        let driver = self.peers.driver()?.ok_or("consensus driver unavailable")?;
        let status = driver.status().borrow().clone();
        if epoch.number != number || status.height != number {
            return Ok(None);
        }
        let key = (number, status.round);
        if let Some(built) = self.cache.lock().map_err(error)?.frozen.get(&key).cloned() {
            return Ok(self
                .node
                .draft_current(built.draft())
                .then(|| Self::plan(&built)));
        }
        let draft = match self
            .node
            .proposal_draft(
                &self.executor.graph(),
                self.config.policy,
                &self.config.address,
                now()?,
            )
            .await
        {
            Ok(draft) => Arc::new(draft),
            Err(e) => {
                self.warning(&e.to_string());
                return Ok(None);
            }
        };
        let built = match self
            .executor
            .build_pending(
                draft,
                self.pending.clone(),
                self.config.epoch_capacity.clone(),
                self.config.stealth_slots,
            )
            .await
        {
            Ok(built) => Arc::new(built),
            Err(e) => {
                self.warning(&e.to_string());
                return Ok(None);
            }
        };
        if !self.node.draft_current(built.draft()) {
            return Ok(None);
        }
        let id = hash::proposal_id(&built.plan().header)?;
        self.peers.cache(number, id, built.bundle().clone())?;
        let mut cache = self.cache.lock().map_err(error)?;
        if let Some(prior) = cache.frozen.get(&key) {
            return Ok(Some(Self::plan(prior)));
        }
        let plan = Self::plan(&built);
        cache
            .executions
            .insert(id, Arc::new(Evidence::Built(built.clone())));
        cache.frozen.insert(key, built);
        Ok(Some(plan))
    }
    async fn verify(&self, proposal: &Proposal) -> Result<Verdict, Error> {
        let candidate = match self
            .node
            .proposal_candidate(proposal, &self.executor.graph(), self.config.policy, now()?)
            .await
        {
            Ok(c) => Arc::new(c),
            Err(octra_node_runtime::finality::Error::Invalid(_)) => return Ok(Verdict::Reject),
            Err(e) => {
                self.warning(&e.to_string());
                return Ok(Verdict::Wait);
            }
        };
        let id = hash::proposal_id(&proposal.header)?;
        let rules = self.executor.proposal_rules(&candidate).map_err(error)?;
        let Some((_, bundle)) = self
            .bundles
            .query(proposal.epoch_id, id, 10., |r| {
                Ok(consensus_bundle::proposal_wire(proposal, &r.bundle, &rules).ok())
            })
            .await?
        else {
            return Ok(Verdict::Wait);
        };
        let prepared = match self
            .executor
            .verify_proposal(candidate.clone(), &bundle.to_raw()?)
            .await
        {
            Ok(p) => Arc::new(p),
            Err(ProposalError::Invalid(_)) => return Ok(Verdict::Reject),
            Err(e) => {
                self.warning(&e.to_string());
                return Ok(Verdict::Wait);
            }
        };
        if !self.node.proposal_current(&candidate) {
            return Ok(Verdict::Wait);
        }
        self.peers
            .cache(proposal.epoch_id, id, prepared.bundle().clone())?;
        self.cache
            .lock()
            .map_err(error)?
            .executions
            .insert(id, Arc::new(Evidence::Prepared(prepared)));
        Ok(Verdict::Accept)
    }
    async fn before_precommit(&self, request: Precommit) -> bool {
        match self.precommit(request).await {
            Ok(ready) => ready,
            Err(e) => {
                self.warning(&e.to_string());
                false
            }
        }
    }
    async fn activate(&self, number: i64) -> Result<ValidatorSet, Error> {
        let head = self.node.snapshot().map_err(error)?.head().clone();
        self.activate_at(number, head).await
    }
    async fn validators(&self, number: i64) -> Result<ValidatorSet, Error> {
        let epoch = self.epoch()?;
        if number == epoch.number {
            return Ok(epoch.rules.validators.clone());
        }
        octra_node_runtime::finality_queries::Host::validators(&self.peers, number).await
    }
    async fn evidence(&self, conflict: VoteConflict) -> Result<(), Error> {
        let id = conflict.id()?;
        let wire = conflict.encode()?;
        let path = self.config.evidence_dir.clone();
        tokio::task::spawn_blocking(move || save_evidence(&path, &id, &wire))
            .await
            .map_err(error)?
    }
    fn warning(&self, reason: &str) {
        eprintln!("consensus: {reason}");
    }
}
fn save_evidence(directory: &std::path::Path, id: &[u8; 32], wire: &[u8]) -> Result<(), Error> {
    crate::storage::publish(
        &directory.join(format!("{}.evidence", hex::encode(id))),
        wire,
    )
    .map_err(error)
}
