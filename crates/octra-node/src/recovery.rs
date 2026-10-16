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
    Host, Node,
};
use anyhow::{ensure, Context, Result};
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

pub(crate) type Live<A> = Driver<driver::Validator<A>, Canonical<A, Authority, Native>>;
/// Responses come only from `EpochRoots::query`, whose handler verifies each
/// validator signature. A lone higher head is a one-epoch availability hint;
/// it never supplies canonical state or relaxes finality verification.
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
    if matching.iter().any(|r| r.responder_head_epoch > epoch) {
        return Ok(Some(u64::try_from(
            epoch.checked_add(1).context("recovery epoch overflow")?,
        )?));
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
    async fn current_attested(&self) -> Result<bool> {
        if self.minimum_peers == 0 {
            return Ok(true);
        }
        let head = self.node.head().await?;
        let epoch = i64::try_from(head.cursor.epoch.0)?;
        let responses = self
            .roots
            .query(epoch, 3., WaitFor::SourceAgreement, false)
            .await?;
        let matching = responses
            .into_iter()
            .filter(|r| r.state_root.as_deref() == Some(head.cursor.state_root.0.as_slice()))
            .collect::<Vec<_>>();
        let stake = self.membership.stake_set(&head, epoch + 1).await?;
        let heads = matching
            .iter()
            .map(|r| catchup::PeerHead {
                responder_addr: r.responder_addr.clone(),
                responder_head_epoch: r.responder_head_epoch,
            })
            .collect::<Vec<_>>();
        if catchup::pick_target_epoch(&heads, stake.f, epoch)? > epoch {
            return Ok(false);
        }
        Ok(epoch_roots::reached(
            self.node.store.chain().chain_id.as_bytes(),
            epoch,
            &stake,
            WaitFor::SourceAgreement,
            &matching,
        )?)
    }
    /// Reconcile only records already authenticated and committed. Floor writes
    /// precede removal of stale locks; future pending locks and votes survive.
    async fn reconcile(&self, after: octra_exex::Sequence) -> Result<octra_exex::Sequence> {
        let head = self.node.quiesce().await?;
        // Include the last observed epoch: cancellation can occur after its
        // canonical cache update and before the driver's pending callback.
        let first = after.0.max(self.node.store.anchor().cursor.sequence.0 + 1);
        for sequence in first..=head.cursor.sequence.0 {
            let sequence = octra_exex::Sequence(sequence);
            let record = self.node.publisher.record(sequence).await?;
            let cursor = self.node.store.retained_head(sequence).await?.cursor;
            let pending = self.pending.clone();
            tokio::task::spawn_blocking(move || pending.committed(&record, cursor)).await??;
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
        let mut running = Some(Running::start(driver));
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = self.node.head().await?.cursor.sequence;
        let mut progress = Instant::now();
        let mut desired = None;
        loop {
            if let Some(driver) = running.as_mut() {
                tokio::select! {
                    result=&mut driver.task=>{result??;anyhow::bail!("consensus driver stopped unexpectedly")},
                    _=interval.tick()=>(),
                }
            } else {
                interval.tick().await;
            }
            let head = self.node.head().await?;
            if head.cursor.sequence != last {
                last = head.cursor.sequence;
                progress = Instant::now();
            }
            let connected = self.swarm.peers().len() >= self.minimum_peers;
            let hint = self
                .swarm
                .peers()
                .iter()
                .map(|p| p.hello().best_epoch.max(0) as u64)
                .max()
                .unwrap_or(0);
            if running.is_some()
                && connected
                && hint <= head.cursor.epoch.0.saturating_add(3)
                && progress.elapsed() < Duration::from_secs(30)
            {
                continue;
            }
            if !connected {
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
            if running.is_some() && connected && !needs_catchup {
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
            if let Some(target) = desired {
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
                            // One successor per attempt keeps a lone signed
                            // high-head hint bounded. Full QC and execution
                            // still decide whether that successor commits.
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
                last = self.reconcile(last).await?;
                self.refresh_transport().await?;
                match catchup {
                    Ok(true) => desired = None,
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
            if !self.current_attested().await? {
                continue;
            }
            ensure!(self.node.resume().await?, "recovery serving lease revoked");
            self.pending.recover(&self.submission).await?;
            running = Some(Running::start(self.build().await?));
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
    fn one_verified_ahead_head_probes_only_the_successor() {
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
            target_from_verified_roots(chain, 10, &root, &validators, &[signed.clone()]).unwrap(),
            Some(11)
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
