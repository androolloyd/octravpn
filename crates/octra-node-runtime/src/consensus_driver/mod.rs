// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Live engine ownership. Peer readers enqueue consensus input without waiting
//! for execution, so a proposal's bundle can arrive on the same connection.
mod diagnostics;
mod grace;
mod inbound;
mod liveness;
mod outputs;
mod round_recovery;
mod work;
pub use diagnostics::Diagnostics;
pub use grace::GraceConfig;
pub use liveness::{configured_stall_sec, LivenessContext};

use crate::consensus_votes::{Precommit, Readiness, VoteGuard};
use crate::proposal_relay::{Broadcast, ProposalRelay};
use octra_node_protocol::consensus::{
    codec::Wire,
    driver_policy,
    engine::{Engine, Output},
    evidence::VoteConflict,
    hash,
    journal::JournalOwner,
    pace::Pace,
    round_pool::RoundPool,
    seen::Seen,
    Bytes, EpochHeader, Error, Finalize, ParentCommit, Proposal, RoundStep, RoundSync,
    ValidatorSet, Vote,
};
use octra_node_protocol::network::{frame::Frame, session::Peer, swarm::Swarm};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
};

pub struct ProposalPlan {
    pub header: EpochHeader,
    pub tx_hashes: Vec<Bytes>,
    pub parent_commit: Option<ParentCommit>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Wait,
    Reject,
}

/// Trusted execution and canonical-history adapter. Peer messages cannot supply
/// readiness, activation rules or validator membership to this interface.
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error>;
    fn readiness(&self) -> Readiness;
    /// Read current local health when the actor processes a poll. Peer input
    /// cannot supply these gates or a liveness reset decision.
    fn liveness(&self) -> Option<LivenessContext> {
        None
    }
    fn verify_parent(&self, epoch: i64, parent: Option<&ParentCommit>) -> Result<(), Error>;
    async fn build(&self, epoch: i64) -> Result<Option<ProposalPlan>, Error>;
    async fn verify(&self, proposal: &Proposal) -> Result<Verdict, Error>;
    async fn before_precommit(&self, record: Precommit) -> bool;
    /// Activate authenticated local configuration at the next epoch, including
    /// the native weight cap. Resource-committee effects belong to this hook.
    async fn activate(&self, epoch: i64) -> Result<ValidatorSet, Error>;
    fn warning(&self, reason: &str);
    async fn validators(&self, epoch: i64) -> Result<ValidatorSet, Error>;
    async fn evidence(&self, conflict: VoteConflict) -> Result<(), Error>;
}

/// Owns canonical publication and the application-serving lifecycle separately
/// from speculative proposal execution. Cancellation must suspend services.
#[async_trait::async_trait]
pub trait Publication: Send + Sync + 'static {
    fn head_epoch(&self) -> i64;
    /// Return only after canonical state/history/ExEx publication is durable.
    /// Retrying the same certificate after an interrupted return is idempotent.
    async fn finalized(&self, validators: &ValidatorSet, finalized: &Finalize)
        -> Result<(), Error>;
    fn stopped(&self);
}

#[derive(Clone, Debug)]
pub struct Status {
    pub started: bool,
    pub locked_round: i64,
    pub height: i64,
    pub round: i64,
    pub step: RoundStep,
    pub voting: bool,
    pub finalized: bool,
    pub issue: Option<String>,
}
pub type DutyHandler = Arc<dyn Fn(i64, Option<octra_node_protocol::duty::Proof>) + Send + Sync>;
enum Input {
    Frame(Peer, Frame),
    Wake,
    HealthPoll,
}
#[derive(Clone)]
pub struct Handle {
    input: mpsc::Sender<Input>,
    status: watch::Receiver<Status>,
    diagnostics: watch::Receiver<Result<Option<Diagnostics>, Error>>,
    proposal_grace: GraceConfig,
}
impl Handle {
    /// Local startup configuration captured by this driver generation.
    pub fn grace_config(&self) -> GraceConfig {
        self.proposal_grace
    }
    pub fn diagnostics(&self) -> Result<Option<Diagnostics>, Error> {
        if self.diagnostics.has_changed().is_err() {
            return Ok(None);
        }
        self.diagnostics.borrow().clone()
    }
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
    /// Queue without blocking a connection reader behind a bundle fetch. A
    /// full inbox is an operational backpressure error, never an accepted vote.
    pub fn enqueue(&self, peer: &Peer, frame: &Frame) -> Result<bool, Error> {
        if !matches!(
            frame.message,
            0x30 | 0x31 | 0x32 | 0x3c | 0x3d | 0x3e | 0x3f
        ) {
            return Ok(false);
        }
        self.input
            .try_send(Input::Frame(peer.clone(), frame.clone()))
            .map_err(|e| Error::from(e.to_string()))?;
        Ok(true)
    }
    pub fn wake(&self) -> Result<(), Error> {
        self.input
            .try_send(Input::Wake)
            .map_err(|e| Error::from(e.to_string()))
    }
    /// Trigger a current actor-side sample, without carrying an old snapshot
    /// across queued work or giving the caller round-reset authority.
    pub fn poll_health(&self) -> Result<(), Error> {
        self.input
            .try_send(Input::HealthPoll)
            .map_err(|e| Error::from(e.to_string()))
    }
}
enum Work {
    Build {
        generation: i64,
        height: i64,
        round: i64,
        result: Result<Option<ProposalPlan>, Error>,
    },
    Check {
        generation: i64,
        proposal: Proposal,
        peer: Peer,
        result: Result<Verdict, Error>,
    },
}
#[derive(Clone, Copy)]
struct Timeout {
    step: RoundStep,
    round: i64,
    generation: i64,
}

pub struct Driver<H: Host, C: Publication> {
    engine: Engine,
    chain: Bytes,
    address: Bytes,
    host: Arc<H>,
    publication: Arc<C>,
    swarm: Swarm,
    journal: JournalOwner,
    votes: VoteGuard,
    input: mpsc::Receiver<Input>,
    status: watch::Sender<Status>,
    diagnostic_view: watch::Sender<Result<Option<Diagnostics>, Error>>,
    round_peers: BTreeMap<Bytes, octra_node_protocol::status_rpc::consensus::RoundPeer>,
    work: JoinSet<Work>,
    pending_checks: BTreeMap<(i64, i64), work::Check>,
    active_work: Option<driver_policy::ProposalBuild>,
    seen: Seen,
    historical_replays: Seen,
    evidence: octra_node_protocol::consensus::evidence::Pool,
    round_replies: BTreeMap<Bytes, (i64, i64, RoundStep, Instant)>,
    initialized: bool,
    receive_only: bool,
    proposal_grace: GraceConfig,
    checking: bool,
    relay: ProposalRelay<Broadcast>,
    future_votes: BTreeMap<Bytes, Vote>,
    replies: BTreeMap<Bytes, Instant>,
    fetches: BTreeMap<(i64, Bytes), (driver_policy::ProposalFetch, u8, Instant)>,
    publish_retry: Option<Instant>,
    drain_again: bool,
    verified: BTreeMap<(i64, i64), Proposal>,
    timers: JoinSet<Timeout>,
    round_pool: RoundPool,
    past_round: Option<driver_policy::PastRound>,
    sync_retry: Option<round_recovery::ReplayRetry>,
    pending_votes: BTreeMap<Bytes, Vote>,
    started: Instant,
    epoch_started: i64,
    pace: Option<Pace>,
    build_retry: Option<Instant>,
    duty: Option<DutyHandler>,
    liveness: octra_node_protocol::consensus::liveness::State,
}
impl<H: Host, C: Publication> Drop for Driver<H, C> {
    fn drop(&mut self) {
        self.relay.close();
        self.publication.stopped();
    }
}
impl<H: Host, C: Publication> Driver<H, C> {
    /// The caller restores authenticated pending proposal locks before passing
    /// the engine. VoteGuard independently checks recovery wires and floors.
    /// Construction never starts voting or network tasks.
    pub fn new(
        engine: Engine,
        journal: JournalOwner,
        swarm: Swarm,
        host: H,
        publication: C,
        recovery_votes: Result<Vec<Bytes>, Error>,
    ) -> Result<(Handle, Self), Error> {
        Self::new_with_grace(
            engine,
            journal,
            swarm,
            host,
            publication,
            recovery_votes,
            GraceConfig::from_env(),
        )
    }
    /// Construct from one trusted launcher capture, also used by replacement
    /// generations. No process settings are read by this constructor.
    pub fn new_with_grace(
        mut engine: Engine,
        journal: JournalOwner,
        swarm: Swarm,
        host: H,
        publication: C,
        recovery_votes: Result<Vec<Bytes>, Error>,
        proposal_grace: GraceConfig,
    ) -> Result<(Handle, Self), Error> {
        let chain = engine.chain_id().to_vec();
        let address = engine.address().to_vec();
        let mut votes = VoteGuard::new(chain.clone(), address.clone(), journal.clone());
        votes.prepare(false, &mut engine, recovery_votes)?;
        let (input, receiver) = mpsc::channel(64);
        let (diagnostic_view, diagnostic_receiver) = watch::channel(Ok(None));
        let (status, view) = watch::channel(Status {
            started: false,
            locked_round: engine.state().locked_round,
            height: engine.state().height,
            round: engine.state().round,
            step: engine.state().step,
            voting: false,
            finalized: engine.pending_finalized().is_some(),
            issue: None,
        });
        let host = Arc::new(host);
        let warning = host.clone();
        let relay = ProposalRelay::for_swarm(swarm.clone(), move |reason| {
            warning.warning(&String::from_utf8_lossy(reason));
        });
        Ok((
            Handle {
                input,
                status: view,
                diagnostics: diagnostic_receiver,
                proposal_grace,
            },
            Self {
                engine,
                chain,
                address,
                host,
                publication: Arc::new(publication),
                swarm,
                journal,
                votes,
                input: receiver,
                status,
                diagnostic_view,
                round_peers: BTreeMap::new(),
                work: JoinSet::new(),
                pending_checks: BTreeMap::new(),
                active_work: None,
                seen: Seen::new(10_000)?,
                historical_replays: Seen::new(4096)?,
                evidence: octra_node_protocol::consensus::evidence::Pool::default(),
                round_replies: BTreeMap::new(),
                initialized: false,
                receive_only: false,
                proposal_grace,
                checking: false,
                relay,
                future_votes: BTreeMap::new(),
                replies: BTreeMap::new(),
                fetches: BTreeMap::new(),
                publish_retry: None,
                drain_again: false,
                verified: BTreeMap::new(),
                timers: JoinSet::new(),
                round_pool: RoundPool::default(),
                past_round: None,
                sync_retry: None,
                pending_votes: BTreeMap::new(),
                started: Instant::now(),
                epoch_started: 0,
                pace: None,
                build_retry: None,
                duty: None,
                liveness: octra_node_protocol::consensus::liveness::State::new(Self::wall_time()),
            },
        ))
    }
    fn now(&self) -> i64 {
        i64::try_from(self.started.elapsed().as_nanos()).unwrap_or(i64::MAX)
    }
    /// Observe a real finalization and a matching journalled omitted vote.
    /// The observer cannot replace engine outputs or supply consensus evidence.
    pub fn with_duty_handler(mut self, handler: DutyHandler) -> Self {
        self.duty = Some(handler);
        self
    }
    /// A nonvoting observer can receive authenticated finalizes without waiting
    /// to assemble a voting quorum. This also closes every local vote path if
    /// its host is accidentally marked ready later.
    pub fn receive_only(mut self) -> Self {
        self.receive_only = true;
        self
    }
    fn readiness(&self) -> Readiness {
        let mut readiness = self.host.readiness();
        if self.receive_only {
            readiness.can_vote = false;
        }
        readiness
    }
    fn refresh(&mut self) {
        let (ready, issue) = self.votes.state(&self.engine, self.readiness());
        self.engine.set_voting_ready(ready);
        self.engine.set_round_skip_ready(!self.work_grace());
        // send_replace returns the previous diagnostic result; the newly
        // captured result (including an operational error) remains observable.
        let _previous = self
            .diagnostic_view
            .send_replace(self.diagnostics(ready, issue).map(Some));
        self.status.send_replace(Status {
            started: self.initialized,
            locked_round: self.engine.state().locked_round,
            height: self.engine.state().height,
            round: self.engine.state().round,
            step: self.engine.state().step,
            voting: ready,
            finalized: self.engine.pending_finalized().is_some(),
            issue: issue.map(str::to_owned),
        });
    }
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), Error> {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            result=self.run_inner()=>result,
            ()=async {while !*shutdown.borrow_and_update() {if shutdown.changed().await.is_err(){break;}}}=>Ok(()),
        }
    }
    fn wall_time() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
    async fn run_inner(&mut self) -> Result<(), Error> {
        let minimum = if self.receive_only || self.engine.validators().n <= 1 {
            0
        } else if octra_node_protocol::consensus::policy::quorum_active(
            &self.chain,
            self.engine.state().height,
        ) {
            (self.engine.validators().quorum - 1).max(1) as usize
        } else {
            1
        };
        for _ in 0..60 {
            if self.swarm.peers().len() >= minimum {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if !self.receive_only {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let validators = self.host.activate(self.engine.state().height).await?;
        self.engine.replace_validator_set(validators);
        self.refresh();
        self.relay.open(self.engine.generation());
        if self.engine.is_pristine() {
            self.engine.start_height(self.engine.state().height);
        }
        if let Some(public) = self.engine.validators().public_key(&self.address) {
            match self.journal.load_syncs(
                &self.chain,
                &self.address,
                self.engine.state().height,
                public,
            ) {
                Ok(syncs) => {
                    for sync in syncs {
                        self.round_pool.add_local(sync, Self::wall_time());
                    }
                }
                Err(e) => self.host.warning(&e.to_string()),
            }
        }
        self.initialized = true;
        self.epoch_started = self.now();
        self.round_sync(self.engine.state().round, self.engine.state().step, true)
            .await?;
        loop {
            self.drain_again = false;
            self.drain().await?;
            if self.drain_again {
                continue;
            }
            let retry = self.next_deadline();
            let pacing = self.pace.map_or(retry, |p| {
                self.started + Duration::from_nanos(p.until.max(0) as u64)
            });
            tokio::select! {
                input=self.input.recv()=>match input {Some(Input::Frame(peer,frame))=>self.receive(&peer,frame).await?,Some(Input::Wake)=>(),Some(Input::HealthPoll)=>self.poll_health().await?,None=>return Ok(())},
                output=self.work.join_next(),if !self.work.is_empty()=>{
                    let work=match output.ok_or("proposal worker disappeared")? {
                        Ok(work)=>work,Err(e) if e.is_cancelled()=>continue,Err(e)=>return Err(e.to_string().into()),
                    };
                    self.finish(work).await?;
                },
                timeout=self.timers.join_next(),if !self.timers.is_empty()=>{
                    let timeout=timeout.ok_or("consensus timer disappeared")?.map_err(|e|Error::from(e.to_string()))?;
                    if timeout.step==RoundStep::Propose && self.active_work.is_some_and(|work|work.current(timeout.generation,self.engine.state().height,timeout.round,timeout.step)) && self.work_grace() {
                        self.timer(timeout,Duration::from_millis(500));
                    }else{
                        self.refresh();
                        self.engine.on_timeout(timeout.step,timeout.round,timeout.generation,&mut |bytes|self.host.sign(bytes))?;
                    }
                },
                ()=tokio::time::sleep_until(retry.min(pacing))=>{
                    if let Some(p)=self.pace.filter(|p|p.until<=self.now()) {self.pace=None;if p.current(self.engine.state().height,self.engine.generation()){self.epoch_started=self.now();}}
                    if self.build_retry.is_some_and(|until|until<=Instant::now()){self.build_retry=None;}
                    if self.publish_retry.is_some_and(|until|until<=Instant::now()){self.publish_retry=None;}
                    self.retry_round_sync().await?;
                },
            }
        }
    }
}
