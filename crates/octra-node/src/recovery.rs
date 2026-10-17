//! Live catch-up owns a stopped driver generation. Canonical publication,
//! journal floors and admission must agree before another generation can vote.
use crate::{
    consensus::Canonical,
    consensus_join, driver,
    executor::{Native, Pending},
    import::Executor,
    peers::Authority,
    rpc::Submission,
    sync::{PeerCatchUpError, Peers},
    Host, Node, RootEvidence,
};
use anyhow::{Context, Result};
use octra_node_protocol::{
    consensus::{
        catchup,
        engine::{Engine, TimeoutConfig},
        ValidatorSet,
    },
    network::swarm::Swarm,
};
use octra_node_runtime::{
    bundle_queries::Bundles,
    consensus_driver::{Driver, DutyHandler, Host as _},
    epoch_roots::{self, EpochRoots, WaitFor},
    finality_queries::Finality,
    validator_history::CanonicalValidators,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time::Instant};

mod health;
#[cfg(test)]
mod live_tests;
#[cfg(test)]
#[path = "../../octra-node-runtime/tests/common/bundle_peer.rs"]
mod test_peer;

pub(crate) type Live<A> = Driver<driver::Validator<A>, Canonical<A, Authority, Native>>;
/// Responses come only from `EpochRoots::query`, whose handler verifies each
/// validator signature. Only the native fault-tolerant head target may stop a
/// driver; a lone signed hint cannot create a persistent catch-up obligation.
fn target_from_verified_roots(
    chain: &[u8],
    epoch: i64,
    local_root: &[u8],
    stake: &ValidatorSet,
    responses: &[epoch_roots::Response],
) -> Result<Option<u64>> {
    let matching = responses
        .iter()
        .filter(|r| r.state_root.as_deref() == Some(local_root))
        .cloned()
        .collect::<Vec<_>>();
    if epoch_roots::reached(chain, epoch, stake, WaitFor::SourceAgreement, &matching)? {
        let heads = matching
            .iter()
            .map(|r| catchup::PeerHead {
                responder_addr: r.responder_addr.clone(),
                responder_head_epoch: r.responder_head_epoch,
            })
            .collect::<Vec<_>>();
        let advertised = catchup::pick_target_epoch(&heads, stake.f, epoch)?;
        if advertised > epoch {
            return Ok(Some(u64::try_from(advertised)?));
        }
    }
    Ok(None)
}
pub(crate) struct Service<A: Host> {
    pub node: Arc<Node<A>>,
    pub submission: Arc<Submission<A>>,
    pub executor: Native,
    pub pending: Arc<Pending>,
    pub authority: Authority,
    pub swarm: Swarm,
    pub bundles: Bundles<Authority>,
    pub roots: EpochRoots<Authority>,
    pub finality: Finality<Authority>,
    pub membership: CanonicalValidators,
    pub join: consensus_join::Client,
    pub config: driver::Config,
    pub timeouts: TimeoutConfig,
    pub voting: bool,
    pub minimum_peers: usize,
    pub health: octra_node_protocol::consensus::health::Config,
    pub budget: Duration,
    pub duty: Option<DutyHandler>,
}
struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}
impl Running {
    fn start<A: Host>(driver: Live<A>) -> Self {
        Self::spawn(|signal| async move { driver.run(signal).await.map_err(anyhow::Error::from) })
    }
    fn spawn<F: std::future::Future<Output = Result<()>> + Send + 'static>(
        run: impl FnOnce(watch::Receiver<bool>) -> F,
    ) -> Self {
        let (stop, signal) = watch::channel(false);
        Self {
            stop,
            task: tokio::spawn(run(signal)),
        }
    }
    async fn stop(&mut self) -> Result<()> {
        self.stop.send_replace(true);
        (&mut self.task).await??;
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // A cancelled supervisor must not leave an independently voting task.
        // Already-dispatched commits retain their own writer/operation lease.
        self.task.abort();
    }
}
struct Admission<A: Host> {
    node: Arc<Node<A>>,
    authority: Authority,
}
impl<A: Host> Drop for Admission<A> {
    fn drop(&mut self) {
        self.node.suspend("consensus recovery supervisor stopped");
        self.authority.detach();
    }
}
impl<A: Host> Service<A> {
    async fn build(&self) -> Result<Live<A>> {
        let height = i64::try_from(self.node.head().await?.cursor.epoch.0)?
            .checked_add(1)
            .context("consensus epoch overflow")?;
        let validator = driver::Validator::with_peers(
            self.node.clone(),
            self.executor.clone(),
            self.pending.clone(),
            self.authority.clone(),
            self.bundles.clone(),
            self.swarm.clone(),
            self.config.clone(),
        )?;
        let set = validator.activate(height).await?;
        let mut engine = Engine::new(
            self.node.store.chain().chain_id.as_bytes().to_vec(),
            self.config.address.clone(),
            set,
            height,
            self.config.policy.protocol,
            self.timeouts,
        );
        validator.recover(&mut engine).await?;
        validator.set_enabled(self.voting);
        let publication = Canonical::new(
            self.node.clone(),
            self.bundles.clone(),
            self.executor.clone(),
            10.,
        )
        .await?
        .with_pending(self.pending.clone());
        let (handle, mut driver) = Driver::new(
            engine,
            self.config.journal.clone(),
            self.swarm.clone(),
            validator,
            publication,
            Ok(vec![]),
        )?;
        if let Some(duty) = &self.duty {
            driver = driver.with_duty_handler(duty.clone());
        }
        self.authority.attach(handle)?;
        Ok(driver)
    }
    /// Probe complete signed ranges without importing alongside a live driver.
    /// Advertised heads can trigger a probe but cannot become canonical state.
    async fn target(&self, deadline: Instant) -> Result<Option<u64>> {
        let head = self.node.head().await?;
        let from = i64::try_from(head.cursor.epoch.0)?
            .checked_add(1)
            .context("recovery epoch overflow")?;
        let range = self
            .finality
            .query_range(from, catchup::RANGE_EPOCHS, 3., |response| {
                Ok(
                    catchup::valid_chunk_first_epoch(&response.status, &response.records, from)
                        && catchup::verify_chain_continuity(
                            &response.records,
                            from,
                            &head.cursor.state_root.0,
                        )
                        .is_ok()
                        && response
                            .records
                            .iter()
                            .all(|record| catchup::verify_record_receipts(record).is_ok()),
                )
            })
            .await;
        let mut target = None;
        if let Ok(Some(response)) = range {
            if self
                .node
                .publisher
                .verify_record(&head, &response.records[0], &self.executor.graph())
                .await
                .is_ok()
            {
                target = Some(response.records[0].epoch_id as u64);
            }
        }
        if target.is_none() && Instant::now() < deadline {
            let epoch = i64::try_from(head.cursor.epoch.0)?;
            let responses = self
                .roots
                .query(epoch, 2., WaitFor::SourceAgreement, false)
                .await?;
            let stake = self.membership.stake_set(&head, epoch + 1).await?;
            target = target_from_verified_roots(
                self.node.store.chain().chain_id.as_bytes(),
                epoch,
                &head.cursor.state_root.0,
                &stake,
                &responses,
            )?;
        }
        if Instant::now() < deadline {
            if let Some(http) = self
                .join
                .proved_target(&self.node, &self.membership, &self.executor, deadline)
                .await?
            {
                target = Some(target.map_or(http, |p| p.max(http)));
            }
        }
        Ok(target)
    }
    async fn refresh_transport(&self) -> Result<()> {
        let head = self.node.head().await?;
        let next = head
            .cursor
            .epoch
            .0
            .checked_add(1)
            .context("recovery epoch overflow")?;
        let relief = self.node.store.reader().relief_after(&head).await?;
        let rules = self
            .node
            .host
            .resolve(&head, next, relief)
            .await
            .map_err(anyhow::Error::msg)?;
        self.swarm.advance_profile(i64::try_from(next)?)?;
        self.swarm.set_validators(
            rules
                .validators
                .validators
                .iter()
                .map(|member| member.pubkey.clone())
                .collect(),
        )?;
        self.authority.set_validators(rules.validators)?;
        Ok(())
    }
    async fn current_attested(
        &self,
        ahead_streak: &mut i64,
    ) -> Result<Option<octra_node_runtime::canonical::Head>> {
        if self.minimum_peers == 0 {
            return Ok((!self.node.root_quarantined()).then_some(self.node.head().await?));
        }
        let sample = health::query(self).await?;
        let Some((sample, evidence)) = self.admissible(sample, ahead_streak, false).await? else {
            return Ok(None);
        };
        Ok(self
            .clear_attested(&sample, evidence, ahead_streak)
            .await?
            .then_some(sample.head))
    }

    async fn clear_attested(
        &self,
        sample: &health::Sample,
        evidence: RootEvidence,
        ahead_streak: &mut i64,
    ) -> Result<bool> {
        if self.node.root_quarantined() {
            if !self
                .node
                .clear_root_quarantine_at(
                    &sample.head,
                    &sample.ticket,
                    evidence,
                    matches!(sample.status, health::Status::Attested { consensus: true }),
                )
                .await?
            {
                return Ok(false);
            }
            *ahead_streak = 0;
        }
        Ok(true)
    }

    /// Native health distinguishes count attestation from weighted finality,
    /// and treats ahead, in-sync and soft/hard lag as different admission paths.
    async fn admissible(
        &self,
        sample: health::Sample,
        ahead_streak: &mut i64,
        count_ahead: bool,
    ) -> Result<Option<(health::Sample, RootEvidence)>> {
        use octra_node_protocol::consensus::health::{
            self as policy, AheadNoQuorumPlan, AheadQuorumPlan, LagMode,
        };
        if matches!(sample.status, health::Status::Stale) {
            return Ok(None);
        }
        if (sample.responses < sample.required || matches!(sample.status, health::Status::Unknown))
            && !self.node.root_quarantined()
            && matches!(self.node.status(), crate::Status::Suspended(_))
        {
            self.node.suspend(&format!(
                "awaiting current-head attestation: epoch {} matching {} responses {} required {} target {}",
                sample.head.cursor.epoch.0, sample.matching, sample.responses, sample.required, sample.peer_target,
            ));
        }
        if sample.responses < sample.required {
            return Ok(None);
        }
        let epoch = i64::try_from(sample.head.cursor.epoch.0)?;
        if sample.peer_target < epoch {
            if count_ahead {
                *ahead_streak = ahead_streak.saturating_add(1);
            }
            let ahead = epoch.saturating_sub(sample.peer_target);
            if matches!(
                sample.status,
                health::Status::Attested { .. } | health::Status::Conflicting { .. }
            ) {
                match policy::ahead_quorum_plan(
                    epoch,
                    ahead,
                    *ahead_streak,
                    self.health.ahead_grace_epochs,
                    self.health.ahead_drift_tolerance,
                    self.health.ahead_streak_threshold,
                    self.node.root_quarantined(),
                ) {
                    AheadQuorumPlan::QuarantineAhead => {
                        self.node
                            .quarantine_root_at(
                                &sample.head,
                                &format!("ahead_of_target_by_{ahead}_streak_{ahead_streak}"),
                            )
                            .await?;
                    }
                    AheadQuorumPlan::StayActive { wake_ready: true }
                    | AheadQuorumPlan::DelayQuarantine { wake_ready: true } => {
                        return Ok(Some((sample, RootEvidence::AheadCurrentRootQuorum)))
                    }
                    _ => (),
                }
                return Ok(None);
            }
            if policy::ahead_no_quorum_plan(
                epoch,
                ahead,
                self.health.ahead_grace_epochs,
                self.health.ahead_drift_tolerance,
                self.node.root_quarantined(),
            ) == AheadNoQuorumPlan::WaitCurrentHead
            {
                return Ok(Some((sample, RootEvidence::AheadWaitCurrentHead)));
            }
            // A fresh current-root proof can recover ahead quarantine. Missing
            // evidence never authorizes truncating the protected canonical tail.
            let fresh = health::query(self).await?;
            if fresh.head != sample.head || matches!(fresh.status, health::Status::Stale) {
                return Ok(None);
            }
            if self.quarantine_conflict(&fresh).await? {
                return Ok(None);
            }
            return Ok(matches!(fresh.status, health::Status::Attested { .. })
                .then_some((fresh, RootEvidence::AheadCurrentRootQuorum)));
        }
        if sample.peer_target > epoch {
            let lag = sample.peer_target.saturating_sub(epoch);
            if policy::classify_lag_mode(lag, self.health.soft_catchup_max_lag)
                == LagMode::Quarantine
            {
                self.node
                    .quarantine_root_at(&sample.head, &format!("lag_{lag}"))
                    .await?;
                return Ok(None);
            }
            // The native first admission permits a matching one-epoch soft lag;
            // subsequent forward import still checks the complete certificate.
            return Ok((lag == 1
                && !matches!(self.node.status(), crate::Status::Serving(_))
                && matches!(sample.status, health::Status::Attested { .. }))
            .then_some((sample, RootEvidence::SoftLagCurrentRoot)));
        }
        if self.quarantine_conflict(&sample).await? {
            return Ok(None);
        }
        Ok(matches!(sample.status, health::Status::Attested { .. })
            .then_some((sample, RootEvidence::InSync)))
    }
    async fn quarantine_conflict(&self, sample: &health::Sample) -> Result<bool> {
        let health::Status::Conflicting { root, consensus } = sample.status else {
            return Ok(false);
        };
        let reason = format!(
            "peer_root_mismatch_at_head epoch = {} local = {} peer = {} consensus = {}",
            sample.head.cursor.epoch.0,
            hex::encode(sample.head.cursor.state_root.0),
            hex::encode(root),
            consensus,
        );
        self.node.quarantine_root_at(&sample.head, &reason).await
    }
    /// Reconcile only records already authenticated and committed. Floor writes
    /// precede removal of stale locks; future pending locks and votes survive.
    async fn reconcile(&self, after: octra_exex::Sequence) -> Result<octra_exex::Sequence> {
        let head = self.node.quiesce().await?;
        // Include the last observed epoch: cancellation can occur after its
        // canonical cache update and before the driver's pending callback.
        if !self.pending.awaiting_recovery()? {
            let first = after.0.max(self.node.store.anchor().cursor.sequence.0 + 1);
            for sequence in first..=head.cursor.sequence.0 {
                let sequence = octra_exex::Sequence(sequence);
                let record = self.node.publisher.record(sequence).await?;
                let cursor = self.node.store.retained_head(sequence).await?.cursor;
                let pending = self.pending.clone();
                tokio::task::spawn_blocking(move || pending.committed(&record, cursor)).await??;
            }
        }
        let journal = self.config.journal.clone();
        let epoch = i64::try_from(head.cursor.epoch.0)?;
        // Canonical history is immutable and audited; select retained epochs
        // before the blocking journal mutation, never from a peer or marker.
        let pending = tokio::task::spawn_blocking({
            let journal = journal.clone();
            move || journal.pending()
        })
        .await??;
        let mut finalized = std::collections::BTreeSet::new();
        for lock in pending {
            if lock.epoch_id >= 0
                && lock.epoch_id <= epoch
                && self
                    .node
                    .store
                    .reader()
                    .head_for_epoch_opt(lock.epoch_id as u64)
                    .await?
                    .is_some()
            {
                finalized.insert(lock.epoch_id);
            }
        }
        tokio::task::spawn_blocking(move || {
            let pruned = journal.prune_finalized(epoch)?;
            pruned.votes?;
            pruned.syncs?;
            pruned.relief?;
            for epoch in finalized {
                journal.delete_pending_epoch(epoch)?;
            }
            Ok::<_, octra_node_protocol::consensus::Error>(())
        })
        .await??;
        Ok(head.cursor.sequence)
    }
    pub(crate) async fn run(
        self,
        driver: Live<A>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let _admission = Admission {
            node: self.node.clone(),
            authority: self.authority.clone(),
        };
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            result=self.run_inner(driver)=>result,
            ()=async {while !*shutdown.borrow_and_update() {if shutdown.changed().await.is_err(){break;}}}=>Ok(()),
        }
    }
    async fn run_inner(&self, driver: Live<A>) -> Result<()> {
        // Public startup retains no signing or service admission until peer
        // attestation. The supplied retained generation has never run; rebuild
        // and replay its durable locks only after that admission succeeds.
        let mut running = if self.voting && self.minimum_peers == 0 {
            Some(Running::start(driver))
        } else {
            if self.minimum_peers > 0 {
                self.node
                    .suspend("awaiting authenticated current-head attestation");
            }
            self.authority.detach();
            drop(driver);
            None
        };
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = self.node.head().await?.cursor.sequence;
        let mut progress = Instant::now();
        let mut desired = None;
        let mut ahead_streak = 0;
        loop {
            if let Some(driver) = running.as_mut() {
                tokio::select! {
                    result=&mut driver.task=>{result??;anyhow::bail!("consensus driver stopped unexpectedly")},
                    _=interval.tick()=>(),
                }
            } else {
                interval.tick().await;
            }
            let mut head = self.node.head().await?;
            if head.cursor.sequence != last {
                last = head.cursor.sequence;
                progress = Instant::now();
            }
            let connected = self.swarm.peers().len() >= self.minimum_peers;
            // A connected/advancing driver used to bypass every root probe.
            // Inspect conflicting evidence before any fast serving path; a
            // root gate survives ordinary publication and resume attempts.
            if connected && self.minimum_peers > 0 {
                match health::query(self).await {
                    Ok(mut sample) => {
                        let epoch = sample.head.cursor.epoch.0;
                        if let Some(queued) = desired.filter(|target| *target > epoch) {
                            sample.peer_target = sample.peer_target.max(i64::try_from(queued)?);
                            sample.target = Some(u64::try_from(sample.peer_target)?);
                        }
                        let soft_start = sample.target == epoch.checked_add(1)
                            && self.health.soft_catchup_max_lag >= 1
                            && running.is_none()
                            && !matches!(self.node.status(), crate::Status::Serving(_));
                        if let Some(target) = sample.target {
                            desired = Some(desired.map_or(target, |p: u64| p.max(target)));
                        }
                        match self.admissible(sample, &mut ahead_streak, true).await {
                            Ok(Some((sample, evidence))) if soft_start => {
                                // Native soft_lag_current_root admission precedes
                                // catch-up: unavailable successor data must not
                                // suppress this first one-epoch admission.
                                if self
                                    .clear_attested(&sample, evidence, &mut ahead_streak)
                                    .await?
                                    && self.node.resume_at(&sample.head).await?
                                {
                                    self.pending.recover(&self.submission).await?;
                                    if self.voting && running.is_none() {
                                        running = Some(Running::start(self.build().await?));
                                    }
                                    progress = Instant::now();
                                    continue;
                                }
                            }
                            Err(error) => eprintln!("live root admission unavailable: {error:#}"),
                            _ => (),
                        }
                    }
                    Err(error) => eprintln!("live root health unavailable: {error:#}"),
                }
                head = self.node.head().await?;
                if head.cursor.sequence != last {
                    last = head.cursor.sequence;
                    progress = Instant::now();
                }
            }
            if self.node.root_quarantined() {
                if let Some(mut driver) = running.take() {
                    driver.stop().await?;
                    self.authority.detach();
                    self.node.quiesce().await?;
                    last = self.reconcile(last).await?;
                }
            }
            let connected = self.swarm.peers().len() >= self.minimum_peers;
            if running.is_some()
                && connected
                && desired.is_none_or(|target| target <= head.cursor.epoch.0)
            {
                if let Some(driver) = self.authority.driver()? {
                    if let Err(error) = driver.poll_health() {
                        eprintln!("live liveness poll unavailable: {error}");
                    }
                }
            }
            let hint = self
                .swarm
                .peers()
                .iter()
                .map(|p| p.hello().best_epoch.max(0) as u64)
                .max()
                .unwrap_or(0);
            if running.is_some()
                && connected
                && !self.node.root_quarantined()
                && desired.is_none_or(|target| target <= head.cursor.epoch.0)
                && hint <= head.cursor.epoch.0.saturating_add(3)
                && progress.elapsed() < Duration::from_secs(30)
            {
                continue;
            }
            if !connected {
                if !self.voting && matches!(self.node.status(), crate::Status::Serving(_)) {
                    self.node.suspend("required consensus peers disconnected");
                }
                if let Some(mut driver) = running.take() {
                    self.node.suspend("required consensus peers disconnected");
                    driver.stop().await?;
                    self.authority.detach();
                    self.node.quiesce().await?;
                    last = self.reconcile(last).await?;
                }
            }
            if connected || self.join.configured() {
                match self.target(Instant::now() + Duration::from_secs(15)).await {
                    Ok(Some(target)) => {
                        desired = Some(desired.map_or(target, |p: u64| p.max(target)));
                    }
                    Ok(None) => (),
                    Err(error) => eprintln!("live recovery probe unavailable: {error:#}"),
                }
            }
            let needs_catchup = desired.is_some_and(|target| {
                target
                    > self
                        .node
                        .store
                        .cached_head()
                        .unwrap_or(head.clone())
                        .cursor
                        .epoch
                        .0
            });
            if !self.voting
                && connected
                && !self.node.root_quarantined()
                && !needs_catchup
                && matches!(self.node.status(), crate::Status::Serving(_))
            {
                continue;
            }
            if running.is_some() && connected && !needs_catchup && !self.node.root_quarantined() {
                continue;
            }
            if let Some(mut driver) = running.take() {
                self.node
                    .suspend("consensus disconnect or authenticated catch-up");
                driver.stop().await?;
                self.authority.detach();
                self.node.quiesce().await?;
                last = self.reconcile(last).await?;
            }
            self.refresh_transport().await?;
            let mut forward_attested = None;
            if let Some(target) = desired {
                let catchup_start = self.node.head().await?;
                let catchup_ticket = self.node.root_quarantine_ticket();
                let catchup = async {
                    let reached = connected
                        && self
                            .node
                            .catch_up_range(target, &self.finality, &self.executor, 5.)
                            .await?
                            .reached;
                    if reached {
                        return Ok(true);
                    }
                    let deadline = Instant::now() + self.budget;
                    if connected {
                        let remaining = deadline
                            .saturating_duration_since(Instant::now())
                            .as_secs_f64()
                            .min(8.);
                        if remaining > 0. {
                            // One successor per attempt bounds unavailable
                            // source data. Full QC and execution still decide
                            // whether that successor commits.
                            let next = self
                                .node
                                .head()
                                .await?
                                .cursor
                                .epoch
                                .0
                                .saturating_add(1)
                                .min(target);
                            match self
                                .node
                                .catch_up(
                                    next,
                                    &Peers {
                                        roots: &self.roots,
                                        finality: &self.finality,
                                        bundles: &self.bundles,
                                    },
                                    &self.executor,
                                    remaining,
                                )
                                .await
                            {
                                Ok(proof)
                                    if proof.reached && proof.head.cursor.epoch.0 >= target =>
                                {
                                    return Ok(true);
                                }
                                Ok(_) => (),
                                Err(PeerCatchUpError::Unavailable(error)) => {
                                    eprintln!("live peer proof unavailable: {error:#}");
                                }
                                Err(PeerCatchUpError::Invalid(error)) => {
                                    return Err(error.context("live peer finalized import failed"));
                                }
                            }
                        }
                    }
                    Ok::<_, anyhow::Error>(
                        self.join
                            .catch_up(&self.node, target, &self.executor, deadline)
                            .await?
                            .reached,
                    )
                }
                .await;
                // Preserve the failure cause before journal reconciliation or
                // transport refresh can themselves fail. A failed attempt no
                // longer owns a persistent queued target.
                let failure = match &catchup {
                    Ok(false) => Some("catchup_failed:unavailable"),
                    Err(_) => Some("catchup_apply_failed:invalid"),
                    Ok(true) => None,
                };
                if let Some(reason) = failure {
                    desired = None;
                    let failed = self.node.head().await?;
                    self.node.quarantine_root_at(&failed, reason).await?;
                }
                last = self.reconcile(last).await?;
                self.refresh_transport().await?;
                match catchup {
                    Ok(true) => {
                        desired = None;
                        let committed = self.node.head().await?;
                        let was_quarantined = self.node.root_quarantined();
                        if self
                            .node
                            .complete_catchup_at(&catchup_start, &committed, &catchup_ticket)
                            .await?
                        {
                            if was_quarantined {
                                ahead_streak = 0;
                            }
                            forward_attested = Some(committed);
                        }
                    }
                    Ok(false) => continue,
                    Err(error) => {
                        eprintln!("live catch-up incomplete, admission suspended: {error:#}");
                        continue;
                    }
                }
            }
            // HTTP may advance authenticated history while P2P is disconnected;
            // serving and voting still require the configured peer gate.
            if self.swarm.peers().len() < self.minimum_peers {
                continue;
            }
            let observed = match forward_attested {
                Some(observed) => observed,
                None => match self.current_attested(&mut ahead_streak).await {
                    Ok(Some(observed)) => observed,
                    Ok(None) => continue,
                    Err(error) => {
                        eprintln!("live admission proof unavailable: {error:#}");
                        continue;
                    }
                },
            };
            if !self.node.resume_at(&observed).await? {
                continue;
            }
            self.pending.recover(&self.submission).await?;
            if self.voting {
                running = Some(Running::start(self.build().await?));
            }
            progress = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_node_protocol::consensus::Validator;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn one_verified_ahead_head_cannot_stop_a_driver() {
        let chain = b"node-recovery-fixture";
        let root = [7_u8; 32];
        let validators = ValidatorSet::unweighted(
            (1..=5)
                .map(|seed| Validator {
                    address: format!("validator-{seed}").into_bytes(),
                    pubkey: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                })
                .collect(),
        );
        let signed = epoch_roots::Response {
            responder_addr: b"validator-1".to_vec(),
            responder_head_epoch: 750,
            state_root: Some(root.to_vec()),
        };
        assert_eq!(
            target_from_verified_roots(
                chain,
                10,
                &root,
                &validators,
                std::slice::from_ref(&signed)
            )
            .unwrap(),
            None
        );
        let mut mismatched = signed.clone();
        mismatched.state_root = Some(vec![0; 32]);
        assert_eq!(
            target_from_verified_roots(chain, 10, &root, &validators, &[mismatched]).unwrap(),
            None
        );
        let mut responses = vec![signed];
        responses.extend((2..=5).map(|seed| epoch_roots::Response {
            responder_addr: format!("validator-{seed}").into_bytes(),
            responder_head_epoch: 10,
            state_root: Some(root.to_vec()),
        }));
        assert_eq!(
            target_from_verified_roots(chain, 10, &root, &validators, &responses).unwrap(),
            None
        );
        responses[1].responder_head_epoch = 11;
        assert_eq!(
            target_from_verified_roots(chain, 10, &root, &validators, &responses).unwrap(),
            Some(11)
        );
    }
    struct Active(Arc<AtomicBool>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn dropping_generation_cancels_independent_driver_task() {
        let active = Arc::new(AtomicBool::new(false));
        let started = Arc::new(tokio::sync::Notify::new());
        let running = Running::spawn({
            let active = active.clone();
            let started = started.clone();
            move |_signal| async move {
                active.store(true, Ordering::SeqCst);
                let _guard = Active(active);
                started.notify_one();
                std::future::pending::<Result<()>>().await
            }
        });
        started.notified().await;
        assert!(active.load(Ordering::SeqCst));
        drop(running);
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn graceful_generation_stop_joins_before_replacement() {
        let active = Arc::new(AtomicBool::new(false));
        let started = Arc::new(tokio::sync::Notify::new());
        let mut running = Running::spawn({
            let active = active.clone();
            let started = started.clone();
            move |mut signal| async move {
                active.store(true, Ordering::SeqCst);
                let _guard = Active(active);
                started.notify_one();
                while !*signal.borrow_and_update() {
                    if signal.changed().await.is_err() {
                        break;
                    }
                }
                Ok(())
            }
        });
        started.notified().await;
        running.stop().await.unwrap();
        assert!(!active.load(Ordering::SeqCst));
        assert!(running.task.is_finished());
    }
}
