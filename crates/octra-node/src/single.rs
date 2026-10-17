//! Private Single host. This authority cannot vote, serve BFT history, or enter
//! a public network. Native epoch execution and durable ExEx remain real.
pub mod facade;
pub mod launch;
pub mod network;
mod queue;
pub mod service;
mod services;
mod workers;
use crate::executor::{single as execute, Native};
use anyhow::{ensure, Context, Result};
use octra_exex::{native_history::NativeTransaction, CheckpointStore, ExEx, ExExManager};
use octra_node_protocol::{
    epoch_journal::Observation,
    legacy_tree::Tree,
    single::{self},
    transaction::{Nonce, Transaction},
};
use octra_node_runtime::{
    account_store,
    canonical::{
        single::{Publication, Store},
        Head,
    },
};
use serde::{Deserialize, Serialize};
pub use services::PublicationHook;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::{watch, Mutex as AsyncMutex};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub mode: String,
    pub private_prior_fixture: bool,
    pub wallet_address: Vec<u8>,
    pub wallet_public: Vec<u8>,
    pub validators: Option<Vec<u8>>,
    pub next_validators: Option<Vec<u8>>,
    pub activation: Option<i64>,
    pub fee_recipient: Option<Vec<u8>>,
    pub epoch_capacity: String,
    pub stealth_minimum: String,
    pub maximum_defer: i64,
    pub inline_ranges: bool,
    pub maximum_timestamp_drift: f64,
    pub preverify_ttl: f64,
    pub preverify_maximum: usize,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            single::Role::of_mode(false, Some(self.mode.as_bytes())) == single::Role::Single,
            "Single launcher requires the explicit Single role"
        );
        ensure!(self.private_prior_fixture,"private-prior fixture startup must be explicitly acknowledged; pristine CLI rejects arbitrary private chain IDs");
        ensure!(
            self.maximum_defer >= 0 && self.maximum_defer < (1_i64 << 62),
            "Single defer limit outside native int range"
        );
        ensure!(
            self.maximum_timestamp_drift.is_finite() && self.maximum_timestamp_drift >= 0.,
            "Single timestamp drift invalid"
        );
        ensure!(
            octra_node_protocol::native_integer::parse_integer(self.epoch_capacity.as_bytes())
                .is_some_and(|v| v > 0.into()),
            "Single epoch capacity must be positive"
        );
        Ok(())
    }
    pub fn cache_limits(&self) -> Result<()> {
        ensure!(
            self.preverify_ttl.is_finite()
                && (1.0..=3600.0).contains(&self.preverify_ttl)
                && (1..=4096).contains(&self.preverify_maximum),
            "Single preverify cache bounds invalid"
        );
        Ok(())
    }
    pub fn minimum(&self) -> Result<num_bigint::BigInt> {
        let value =
            octra_node_protocol::native_integer::parse_integer(self.stealth_minimum.as_bytes())
                .context("Single stealth floor invalid")?;
        ensure!(value > 0.into(), "Single stealth floor must be positive");
        Ok(value)
    }
    pub fn validators(&self, epoch: i64) -> Vec<(Vec<u8>, Vec<u8>)> {
        single::validator_pairs(
            self.validators.as_deref(),
            self.next_validators.as_deref(),
            self.activation,
            (&self.wallet_address, &self.wallet_public),
            epoch,
        )
    }
}
struct Memory {
    queue: queue::State,
    revision: i64,
    last_epoch_time: f64,
    legacy_parent: Vec<u8>,
    failed: Option<String>,
    registered: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    inputs: std::collections::BTreeMap<String, [u8; 32]>,
    notification: Option<services::Notification>,
    stats: octra_node_protocol::metrics::Stats,
    legacy_tree: Tree,
    legacy_head: Head,
}
pub struct Node {
    store: Arc<Store>,
    native: Native,
    settings: Settings,
    memory: Mutex<Memory>,
    operations: Arc<AsyncMutex<()>>,
    writer: Arc<std::fs::File>,
    stopped: AtomicBool,
    clock: std::time::Instant,
    exex: AsyncMutex<ExExManager<NativeTransaction>>,
    jobs: workers::Jobs,
    hook: Mutex<Option<Arc<dyn PublicationHook>>>,
}
impl Node {
    /// Acquire the common canonical writer lease before recovery or serving.
    /// No BFT Publisher is constructed by this host.
    pub async fn open(
        store: Arc<Store>,
        native: Native,
        settings: Settings,
        checkpoints: Arc<dyn CheckpointStore>,
        now: f64,
    ) -> Result<Arc<Self>> {
        settings.validate()?;
        settings.cache_limits()?;
        let clock = std::time::Instant::now();
        settings.minimum()?;
        ensure!(
            settings.wallet_public
                == base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &store.identity().public_key
                )
                .as_bytes()
                && settings.wallet_address
                    == octra_node_protocol::transaction::address_from_public_key(
                        &settings.wallet_public
                    ),
            "Single local authority/wallet differs"
        );
        let writer = writer_lock(&store.database_path())?;
        ensure!(
            native.single_policy(&settings)? == store.identity().policy,
            "Single captured execution policy differs"
        );
        ensure!(
            native.single_chain() == store.identity().chain.chain_id.as_bytes(),
            "Single executor/store chain differs"
        );
        ensure!(now.is_finite() && now >= 0., "Single startup time invalid");
        store.audit().await?;
        let (head, state) = store.snapshot().await?;
        let saved = store.queue().await?;
        let mut queue = queue::State::restore(
            &saved.payload,
            &state,
            head.cursor.epoch.0 as i64,
            &settings.minimum()?,
        )?;
        native.single_apply_kats(&queue.kats)?;
        let legacy_parent = if head.cursor.sequence.0 == 0 {
            b"GENESIS".to_vec()
        } else {
            store.record(head.cursor.sequence).await?.legacy_digest
        };
        queue.cache.clear();
        queue.ready.clear(); // Proof-cache authority never survives restart.
        let epoch = i64::try_from(head.cursor.epoch.0)?
            .checked_add(1)
            .context("Single epoch exhausted")?;
        let members = settings.validators(epoch);
        let context = native.single_context(&head, &members).await?;
        let manager = ExExManager::new(store.source(), checkpoints)?;
        let legacy_tree = Tree::create(Nonce::new(epoch)?, legacy_parent.clone());
        let worker = native
            .circle_runtime()
            .crypto_pool()
            .context("Single requires an explicit crypto worker service")?
            .worker()
            .clone();
        let node = Arc::new(Self {
            store,
            native,
            settings,
            memory: Mutex::new(Memory {
                queue,
                revision: saved.revision,
                last_epoch_time: now,
                legacy_parent,
                failed: None,
                registered: std::collections::BTreeMap::default(),
                inputs: std::collections::BTreeMap::default(),
                notification: None,
                stats: octra_node_protocol::metrics::Stats::default(),
                legacy_tree,
                legacy_head: head.clone(),
            }),
            operations: Arc::new(AsyncMutex::new(())),
            writer: Arc::new(writer),
            stopped: AtomicBool::new(false),
            clock,
            exex: AsyncMutex::new(manager),
            jobs: workers::Jobs::new(worker),
            hook: Mutex::new(None),
        });
        node.schedule(&state.snapshot(), &context, epoch)?;
        Ok(node)
    }
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
    pub async fn head(&self) -> Result<Head> {
        Ok(self.store.head().await?)
    }
    pub fn queued(&self) -> Result<Vec<Transaction>> {
        let mem = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        ensure!(
            mem.failed.is_none(),
            "Single requires restart after failed publication"
        );
        Ok(mem.queue.pool.all().cloned().collect())
    }
    pub async fn register<X: ExEx<NativeTransaction>>(&self, extension: X) -> Result<()> {
        Ok(self.exex.lock().await.register(extension).await?)
    }
    pub async fn extension_status(
        &self,
        name: &str,
    ) -> Option<watch::Receiver<octra_exex::ExtensionStatus>> {
        self.exex.lock().await.status(name)
    }
    /// Cancellation cannot release the writer/serialization lease during a queue
    /// fsync or a canonical COMMIT. The short-lived worker owns both through finish.
    async fn owned<T: Send + 'static>(
        self: &Arc<Self>,
        name: &str,
        work: impl FnOnce(
                Arc<Self>,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>>
            + Send
            + 'static,
    ) -> Result<T> {
        let operation = self.operations.clone().lock_owned().await;
        ensure!(!self.stopped.load(Ordering::Acquire), "Single node stopped");
        let node = self.clone();
        let writer = self.writer.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async move {
                        let _writer = writer;
                        let result = work(node.clone()).await;
                        let notification = node.take_notification();
                        drop(operation);
                        node.flush_notification(notification);
                        result
                    })
                })();
                let _ = tx.send(result);
            })?;
        rx.await
            .context("Single owned worker stopped; restart before resuming")?
    }
    pub async fn submit(self: &Arc<Self>, tx: Transaction, now: f64) -> Result<Vec<u8>> {
        self.owned("octra-single-intake", move |node| {
            Box::pin(async move { node.submit_inner(tx, now).await })
        })
        .await
    }
    async fn submit_inner(self: &Arc<Self>, tx: Transaction, now: f64) -> Result<Vec<u8>> {
        ensure!(now.is_finite() && now >= 0., "Single intake time invalid");
        let (head, state) = self.store.snapshot().await?;
        let epoch = i64::try_from(head.cursor.epoch.0)?
            .checked_add(1)
            .context("Single epoch exhausted")?;
        let members = self.settings.validators(epoch);
        let context = self.native.single_context(&head, &members).await?;
        let envelope = self.native.single_source_rules(&head).await?;
        let mut rules = self.native.single_intake_rules(epoch, &context, envelope);
        rules.stealth_minimum = self.settings.minimum()?;
        let (mut candidate, revision) = {
            let memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            ensure!(memory.failed.is_none(), "Single requires restart");
            (memory.queue.clone(), memory.revision)
        };
        let mut ledger = account_store::ledger(&state)?;
        for (address, key) in &self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?
            .registered
        {
            ledger.register_public_key(address, key.clone());
        }
        let hash = candidate.submit(
            &self.native,
            &state.snapshot(),
            &tx,
            &ledger,
            &rules,
            &context,
            epoch,
            now,
            self.settings.maximum_timestamp_drift,
            self.jobs.pending(),
        )?;
        self.memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?
            .failed = Some("Single queue publication in progress; restart if interrupted".into());
        let revision = self
            .store
            .save_queue(&head, revision, candidate.encode()?)
            .await?;
        let mut memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        memory.queue = candidate;
        memory.revision = revision;
        memory.failed = None;
        drop(memory);
        self.schedule(&state.snapshot(), &context, epoch)?;
        Ok(hash)
    }
    /// The clock is explicit for native differential and crash/restart tests.
    /// A refused epoch leaves its parent, durable queue, timer and Tree untouched.
    pub async fn tick(self: &Arc<Self>, now: f64, date: i64) -> Result<Option<Head>> {
        self.owned("octra-single-epoch", move |node| {
            Box::pin(async move { node.tick_inner(now, date).await })
        })
        .await
    }
    async fn tick_inner(self: &Arc<Self>, now: f64, date: i64) -> Result<Option<Head>> {
        ensure!(now.is_finite() && now >= 0., "Single epoch time invalid");
        let (mut candidate, revision, legacy, last) = {
            let memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            ensure!(memory.failed.is_none(), "Single requires restart");
            (
                memory.queue.clone(),
                memory.revision,
                memory.legacy_parent.clone(),
                memory.last_epoch_time,
            )
        };
        if !single::tick(now - last).apply {
            return Ok(None);
        }
        let execution_started = std::time::Instant::now();
        let (base, state) = self.store.snapshot().await?;
        let epoch = i64::try_from(base.cursor.epoch.0)?
            .checked_add(1)
            .context("Single epoch exhausted")?;
        let members = self.settings.validators(epoch);
        let capacity = octra_node_protocol::native_integer::parse_integer(
            self.settings.epoch_capacity.as_bytes(),
        )
        .context("Single capacity invalid")?;
        let envelope = self.native.single_source_rules(&base).await?;
        let transactions = candidate
            .pool
            .epoch(&capacity)
            .into_iter()
            .filter(|entry| {
                octra_node_protocol::transaction::check_compute(
                    envelope.compute,
                    envelope.settle,
                    std::slice::from_ref(&entry.tx),
                )
                .is_ok()
                    && octra_node_protocol::transaction::check_envelopes(
                        envelope.envelope,
                        std::slice::from_ref(&entry.tx),
                    )
                    .is_ok()
            })
            .map(|entry| entry.tx.clone())
            .collect::<Vec<_>>();
        // Preserve the pristine unsorted source refusal before speculative proof work.
        single::source(&transactions)?;
        let context = self.native.single_context(&base, &members).await?;
        let addresses = members.iter().map(|(a, _)| a.clone()).collect::<Vec<_>>();
        let proposer = single::proposer(
            epoch,
            &addresses,
            self.settings.fee_recipient.as_deref(),
            None,
        )
        .map_err(anyhow::Error::msg)?;
        let roots = self
            .native
            .single_ready_roots(&base, &context, &transactions)
            .await?;
        self.schedule(&state.snapshot(), &context, epoch)?;
        // Refresh speculative state after scheduling (only Pending/completions,
        // never a verdict from admission itself).
        let (cache, ready, registered) = {
            let memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            (
                memory.queue.cache.clone(),
                memory.queue.ready.clone(),
                memory.registered.clone(),
            )
        };
        candidate.cache = cache;
        candidate.ready = ready;
        let output = self.native.execute_single_registered(
            execute::Request {
                parent: &base,
                state: state.snapshot(),
                context: &context,
                envelope,
                validators: &members,
                proposer: &proposer.address,
                transactions: &transactions,
                deferred: candidate.deferred.clone(),
                preverify: candidate.cache.clone(),
                ready: candidate.ready.clone(),
                maximum_defer: self.settings.maximum_defer,
                inline: self.settings.inline_ranges,
                ready_roots: &roots,
            },
            &registered,
        )?;
        let confirmed = output
            .epoch
            .confirmed
            .iter()
            .map(|&i| transactions[i].clone())
            .collect::<Vec<_>>();
        let mut tree = Tree::create(Nonce::new(epoch)?, legacy.clone());
        let digest = tree.finalize_epoch(
            Nonce::new(epoch)?,
            &proposer.address,
            output.epoch.tree_state_root.clone(),
            0.,
            &confirmed,
        )?;
        let metric_floor = self.settings.minimum()?;
        let metric_epoch = octra_node_protocol::metrics::Epoch {
            transactions: confirmed
                .iter()
                .map(|tx| octra_node_protocol::metrics::Record::of_transaction(tx, &metric_floor))
                .collect(),
            duration: execution_started.elapsed().as_secs_f64(),
        };
        let metric_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64();
        let observation = Observation::from_rewards(
            0.,
            &output.epoch.fees,
            &output.epoch.footer.plan,
            &output.epoch.footer.credits,
        )
        .map_err(anyhow::Error::msg)?;
        let outcomes = output.epoch.outcomes(&transactions)?;
        candidate.deferred = output.deferred;
        candidate.kats.extend(output.kat_backfills);
        candidate.cleanup(
            &output.epoch.processed,
            &output.epoch.state,
            now,
            &self.settings.minimum()?,
        )?;
        candidate.prune(
            self.clock.elapsed().as_secs_f64(),
            self.settings.preverify_ttl,
            self.settings.preverify_maximum,
        );
        let deferred = output
            .epoch
            .deferred
            .iter()
            .map(|&i| transactions[i].hash().map(|h| hex::encode(h).into_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let prepared = self
            .store
            .prepare(
                &base,
                Publication {
                    epoch: epoch as u64,
                    state: output.epoch.state,
                    transactions: output.transactions,
                    legacy_parent: legacy,
                    legacy_digest: digest.clone(),
                    observation,
                    processed: output.epoch.processed,
                    deferred,
                    wall_time: now,
                    date,
                    proposer: proposer.address,
                    tree_state_root: output.epoch.tree_state_root,
                    outcomes,
                    vm_receipts: output.vm_receipts,
                    queue: candidate.encode()?,
                    queue_revision: revision,
                },
            )
            .await?;
        // Any error from this point requires restart: COMMIT may have won a caller
        // cancellation or a local post-commit effect may need replay from signed queue.
        self.memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?
            .failed =
            Some("Single canonical publication in progress; restart if interrupted".into());
        let publication_hook = self.revoke_publication();
        let result = async {
            let head = prepared.commit().await?;
            self.native.single_apply_kats(&candidate.kats)?;
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            memory.queue = candidate;
            memory.revision = revision
                .checked_add(1)
                .context("Single queue revision exhausted")?;
            memory.last_epoch_time = now;
            memory.legacy_parent.clone_from(&digest);
            memory.legacy_tree = Tree::create(Nonce::new(epoch)?.successor(), digest);
            memory.legacy_head = head.clone();
            memory.stats.observe(&metric_epoch, || metric_time);
            memory.failed = None;
            memory.registered.clear();
            let retained = memory
                .queue
                .cache
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            memory.inputs.retain(|hash, _| retained.contains(hash));
            memory.notification = publication_hook.map(|hook| services::Notification {
                head: head.clone(),
                hook,
            });
            Ok::<_, anyhow::Error>(head)
        }
        .await;
        match result {
            Ok(head) => {
                self.exex.lock().await.notify_commit();
                Ok(Some(head))
            }
            Err(error) => {
                self.memory
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .failed = Some(error.to_string());
                Err(error)
            }
        }
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.stopped.store(true, Ordering::Release);
        self.revoke_publication();
        self.jobs.cancel_all();
        {
            let _operation = self.operations.lock().await;
        }
        self.jobs.stop().await?;
        self.exex.lock().await.shutdown().await?;
        // The stopped node may still have readers holding its Arc. Release the
        // writer lease only after all owned work and ExEx workers have drained.
        rustix::fs::flock(&self.writer, rustix::fs::FlockOperation::Unlock)
            .context("Single writer lease release failed")?;
        Ok(())
    }
}
/// Same lock path as the BFT host. A directory can never have two mode writers.
pub fn writer_lock(database: &Path) -> Result<std::fs::File> {
    let mut path = std::fs::canonicalize(database)?.into_os_string();
    path.push(".node.lock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .context("canonical writer already in use")?;
        Ok(file)
    }
    #[cfg(not(unix))]
    anyhow::bail!("Single writer locking requires Unix")
}
/// Local-history reads are deliberately a different interface from BFT catchup.
/// Native rule anchor lookups may use this committed prefix; no local record is
/// transformed into a CatchupEpochRecord or finality proof.
pub struct History(pub Arc<Store>);
#[async_trait::async_trait]
impl octra_node_runtime::finality::history::History for History {
    async fn head(&self) -> std::result::Result<Head, octra_node_runtime::finality::Error> {
        Ok(self.0.head().await?)
    }
    async fn root(
        &self,
        epoch: i64,
    ) -> std::result::Result<Option<Vec<u8>>, octra_node_runtime::finality::Error> {
        Ok(self.0.root(epoch).await?)
    }
    async fn range(
        &self,
        _: i64,
        _: i64,
    ) -> std::result::Result<
        octra_node_runtime::finality_queries::Range,
        octra_node_runtime::finality::Error,
    > {
        Err(octra_node_runtime::finality::Error::Unavailable(
            "private Single history has no BFT finality".into(),
        ))
    }
    async fn bundle(
        &self,
        _: &[u8; 32],
    ) -> std::result::Result<
        Option<octra_node_runtime::consensus_bundle::RawBundle>,
        octra_node_runtime::finality::Error,
    > {
        Err(octra_node_runtime::finality::Error::Unavailable(
            "private Single history has no BFT proposal bundle".into(),
        ))
    }
}
