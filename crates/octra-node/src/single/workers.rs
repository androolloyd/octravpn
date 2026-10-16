//! Ephemeral speculative work. Durable queue entries never contain proof flags.
use super::Node;
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{single::Preverify, transaction::OpType};
use octra_node_runtime::{
    execution_rules::Bound,
    single_private::{
        worker::{Task, Worker},
        CacheBinding,
    },
    state_batch::Snapshot,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
};
pub(super) struct Jobs {
    worker: Arc<Worker>,
    entries: Mutex<BTreeMap<String, Job>>,
    next: AtomicU64,
}
struct Job {
    generation: u64,
    cancelled: Arc<AtomicBool>,
    done: Arc<Done>,
}
struct Done {
    completed: Mutex<bool>,
    wake: Condvar,
}
impl Done {
    fn finish(&self) {
        *self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
    fn wait(&self) {
        let mut done = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*done {
            done = self
                .wake
                .wait(done)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}
impl Jobs {
    pub(super) fn capture() -> Result<Self> {
        Ok(Self {
            worker: Worker::capture().map_err(anyhow::Error::msg)?,
            entries: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
        })
    }
    pub(super) fn pending(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
    pub(super) fn cancel(&self, hash: &str) {
        if let Some(job) = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hash)
        {
            job.cancelled.store(true, Ordering::Release);
        }
    }
    pub(super) fn cancel_all(&self) {
        for job in self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
            job.cancelled.store(true, Ordering::Release);
        }
    }
    pub(super) async fn stop(&self) -> Result<()> {
        let jobs = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|job| {
                job.cancelled.store(true, Ordering::Release);
                job.done.clone()
            })
            .collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            for job in jobs {
                job.wait();
            }
        })
        .await?;
        Ok(())
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.cancel_all();
    }
}
impl Node {
    /// Called only under the owned operation lease. Captures inputs quickly,
    /// then proof computation runs independently of producer serialization.
    pub(super) fn schedule(
        self: &Arc<Self>,
        state: &Snapshot,
        context: &Bound,
        epoch: i64,
    ) -> Result<()> {
        let transactions = {
            let memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            memory
                .queue
                .pool
                .all()
                .filter(|tx| tx.op_type == OpType::Stealth)
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        let mut entries = self
            .jobs
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Single workers poisoned"))?;
        for (hash, job) in entries.iter() {
            if memory.queue.pool.find(hash.as_bytes()).is_none() {
                job.cancelled.store(true, Ordering::Release);
            }
        }
        for tx in transactions {
            let hash = hex::encode(tx.hash()?);
            if entries.contains_key(&hash) {
                continue;
            }
            let task = match self.native.single_range_task(state, &tx, context, epoch) {
                Ok(Some(task)) => Arc::new(task),
                Ok(None) => {
                    memory.queue.cache.insert(hash, Preverify::Ready);
                    continue;
                }
                Err(error) => {
                    memory
                        .queue
                        .cache
                        .insert(hash, Preverify::Unavailable(error.to_string().into_bytes()));
                    continue;
                }
            };
            if memory.inputs.get(&hash) == Some(&task.digest())
                && memory
                    .queue
                    .cache
                    .get(&hash)
                    .is_some_and(|s| !matches!(s, Preverify::Pending))
            {
                continue;
            }
            if entries.len()
                >= usize::try_from(
                    octra_node_protocol::resource_lanes::PREVERIFY_SPECULATIVE_QUEUE,
                )?
            {
                break;
            }
            let generation = self
                .jobs
                .next
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                .map_err(|_| anyhow::anyhow!("Single proof generation exhausted"))?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let done = Arc::new(Done {
                completed: Mutex::new(false),
                wake: Condvar::new(),
            });
            entries.insert(
                hash.clone(),
                Job {
                    generation,
                    cancelled: cancelled.clone(),
                    done: done.clone(),
                },
            );
            memory.queue.pending(
                &hash,
                self.clock.elapsed().as_secs_f64(),
                self.settings.preverify_maximum,
            );
            memory.inputs.insert(hash.clone(), task.digest());
            let weak = Arc::downgrade(self);
            let worker = self.jobs.worker.clone();
            let hash_worker = hash.clone();
            let spawned = std::thread::Builder::new()
                .name("octra-single-range".into())
                .spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        worker.run(&task, generation, &cancelled)
                    }))
                    .unwrap_or_else(|_| Err("Single proof worker panicked".into()));
                    if let Some(node) = weak.upgrade() {
                        if !cancelled.load(Ordering::Acquire) {
                            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                            {
                                let hash_apply = hash_worker.clone();
                                let cancelled_apply = cancelled.clone();
                                let _ = runtime.block_on(node.owned(
                                    "octra-single-range-complete",
                                    move |node| {
                                        Box::pin(async move {
                                            node.complete_range(
                                                &hash_apply,
                                                generation,
                                                &task,
                                                &cancelled_apply,
                                                result,
                                            )
                                            .await
                                        })
                                    },
                                ));
                            }
                        }
                        let mut jobs = node
                            .jobs
                            .entries
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if jobs
                            .get(&hash_worker)
                            .is_some_and(|job| job.generation == generation)
                        {
                            jobs.remove(&hash_worker);
                        }
                        drop(jobs);
                        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            let _ =
                                runtime.block_on(node.owned("octra-single-range-next", |node| {
                                    Box::pin(async move {
                                        let (head, state) = node.store.snapshot().await?;
                                        let epoch = i64::try_from(head.cursor.epoch.0)?
                                            .checked_add(1)
                                            .context("Single epoch exhausted")?;
                                        let context = node
                                            .native
                                            .single_context(&head, &node.settings.validators(epoch))
                                            .await?;
                                        node.schedule(&state.snapshot(), &context, epoch)
                                    })
                                }));
                        }
                    }
                    // Child has been reaped and no completion can mutate memory now.
                    done.finish();
                });
            if let Err(error) = spawned {
                entries.remove(&hash);
                memory
                    .queue
                    .cache
                    .insert(hash, Preverify::Unavailable(error.to_string().into_bytes()));
            }
        }
        Ok(())
    }
    async fn complete_range(
        &self,
        hash: &str,
        generation: u64,
        task: &Task,
        cancelled: &AtomicBool,
        result: std::result::Result<CacheBinding, String>,
    ) -> Result<()> {
        ensure!(!cancelled.load(Ordering::Acquire), "Single range cancelled");
        let (head, state) = self.store.snapshot().await?;
        let epoch = i64::try_from(head.cursor.epoch.0)?
            .checked_add(1)
            .context("Single epoch exhausted")?;
        let context = self
            .native
            .single_context(&head, &self.settings.validators(epoch))
            .await?;
        let tx = {
            let memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
            ensure!(memory.failed.is_none(), "Single requires restart");
            memory.queue.pool.find(hash.as_bytes()).cloned()
        };
        let Some(tx) = tx else { return Ok(()) };
        let current = self
            .native
            .single_range_task(&state.snapshot(), &tx, &context, epoch)?;
        let mut memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        let jobs = self
            .jobs
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Single workers poisoned"))?;
        if memory.failed.is_some()
            || cancelled.load(Ordering::Acquire)
            || jobs
                .get(hash)
                .is_none_or(|job| job.generation != generation)
        {
            return Ok(());
        }
        if !current.is_some_and(|current| task.same_input(&current))
            || memory.inputs.get(hash) != Some(&task.digest())
        {
            memory.queue.retire(hash.as_bytes());
            memory.inputs.remove(hash);
            return Ok(());
        }
        match result {
            Ok(binding) => {
                memory.queue.ready.insert(hash.into(), binding);
                memory.queue.cache.insert(hash.into(), Preverify::Ready);
            }
            Err(reason) => {
                memory.queue.ready.remove(hash);
                memory
                    .queue
                    .cache
                    .insert(hash.into(), Preverify::Unavailable(reason.into_bytes()));
            }
        }
        Ok(())
    }
}

impl Node {
    /// Ephemeral process-local observation only. Publication can be suspended
    /// while this cache still exists; this enum conveys neither a serving view
    /// nor the opaque range capability required by execution.
    pub fn proof_status(&self, hash: &str) -> Result<(Option<Preverify>, usize)> {
        let memory = self
            .memory
            .lock()
            .map_err(|_| anyhow::anyhow!("Single memory poisoned"))?;
        Ok((memory.queue.cache.get(hash).cloned(), self.jobs.pending()))
    }
}
