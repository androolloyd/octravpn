//! A recoverable public tree index. Canonical state authenticates every epoch
//! boundary; auxiliary events supply only the leaves needed to reconstruct it.
mod handle;
mod hints;
mod retained;
mod seed;
use super::{pool, storage::Disk, Pool, State, PLAN_MAX_AGE};
use anyhow::{ensure, Context, Result};
pub use handle::Handle;
#[cfg(test)]
pub(crate) use handle::qualification;
use hints::Delta;
use octra_node_runtime::canonical::Head;
use octra_private_payments_experimental::pool::PoolIndex;
use octravpn_core::sealed::Key;
pub use seed::Seed;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;
const ZERO: [u8; 32] = [0; 32];
const META: u8 = 0;
const RECORD: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_notes: u64,
    pub max_updates: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_notes: 65_536,
            max_updates: 65_536,
        }
    }
}
impl Limits {
    pub(super) fn check(self) -> Result<()> {
        ensure!(
            (1..=1_000_000).contains(&self.max_notes)
                && (1..=1_000_000).contains(&self.max_updates),
            "public pool index resource limits refused"
        );
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    version: u8,
    scope: [u8; 32],
    base: Head,
    cursor: Head,
    records: u64,
    updates: u64,
    limits: Limits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed: Option<seed::Base>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    head: Head,
    updates: Vec<Delta>,
}
struct Cache {
    meta: Meta,
    index: PoolIndex,
}
pub struct Index {
    source: Arc<Pool>,
    disk: Disk,
    cache: Mutex<Cache>,
}
pub struct Progress {
    pub updates: u64,
    pub epoch: u64,
    pub target: u64,
    pub processed: usize,
    pub complete: bool,
}
pub struct View {
    lease: crate::SnapshotLease,
    index: PoolIndex,
    scope: [u8; 32],
}
impl View {
    pub fn index(&self) -> &PoolIndex {
        &self.index
    }
    pub fn epoch(&self) -> u64 {
        self.lease.committed().head().cursor.epoch.0
    }
    /// The caller must not perform IO, proving or an await in this callback.
    pub fn with_current<T>(&self, action: impl FnOnce(&PoolIndex) -> Result<T>) -> Result<T> {
        self.lease
            .with_current(PLAN_MAX_AGE, || action(&self.index))
    }
}
fn matches(index: &PoolIndex, state: &State) -> bool {
    let (notes, spent, count) = index.roots();
    pool::encode_field(notes) == state.notes
        && pool::encode_field(spent) == state.spent
        && count == state.count
}
impl Index {
    pub(super) fn belongs_to(&self, source: &Pool) -> bool {
        self.source.same_custody(source)
    }
    fn scope(source: &Pool) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"Octranet canonical public pool index v1\0");
        h.update(source.origin);
        h.update(source.address);
        h.update(source.code_hash.as_bytes());
        h.update(source.config.factory.as_bytes());
        h.update(source.factory_hash.as_bytes());
        h.finalize().into()
    }
    async fn capture(source: &Pool) -> Result<crate::SnapshotLease> {
        let lease = crate::SnapshotLease::capture(source.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        source
            .directory
            .check_value_effects(lease.committed())
            .await?;
        source.state(lease.committed().state())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(lease)
    }
    async fn state_at(source: &Pool, head: &Head) -> Result<State> {
        ensure!(
            source
                .directory
                .history
                .head_for_epoch(head.cursor.epoch.0)
                .await?
                == *head,
            "public pool index history head differs"
        );
        let snapshot = super::history::Projection::at(source, head.clone()).await?;
        source.state(snapshot.snapshot())
    }
    async fn baseline(source: &Pool) -> Result<Head> {
        let lease = Self::capture(source).await?;
        let head = Self::baseline_at(source, lease.committed().head()).await?;
        if head.cursor.epoch.0 > source.directory.history.anchor().epoch.0 {
            source.record(head.cursor.epoch.0).await?;
        }
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(head)
    }
    async fn baseline_at(source: &Pool, target: &Head) -> Result<Head> {
        let mut lo = source.directory.history.anchor().epoch.0;
        let mut hi = target.cursor.epoch.0;
        ensure!(lo <= hi, "public pool baseline precedes retained history");
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let head = source.directory.history.head_for_epoch(mid).await?;
            let state = super::history::Projection::at(source, head.clone()).await?;
            let fields = super::super::Fields {
                snapshot: state.snapshot(),
                program: &source.address,
                application: super::super::Application::Circle,
            };
            match fields.uint(b"initialized", &[])? {
                0 => lo = mid + 1,
                1 => hi = mid,
                _ => {
                    anyhow::bail!("pool initialization flag differs while locating index baseline")
                }
            }
        }
        let head = source.directory.history.head_for_epoch(lo).await?;
        ensure!(
            matches(&PoolIndex::default(), &Self::state_at(source, &head).await?),
            "retained pool history has no authenticated empty baseline"
        );
        Ok(head)
    }
    pub async fn create(path: &Path, key: Key, source: Arc<Pool>, limits: Limits) -> Result<Self> {
        limits.check()?;
        let base = Self::baseline(&source).await?;
        Self::create_empty(path, key, source, limits, base).await
    }
    async fn create_empty(
        path: &Path,
        key: Key,
        source: Arc<Pool>,
        limits: Limits,
        base: Head,
    ) -> Result<Self> {
        let scope = Self::scope(&source);
        let disk = Disk::open(path, key, scope, true).await?;
        let meta = Meta {
            version: 1,
            scope,
            cursor: base.clone(),
            base,
            records: 0,
            updates: 0,
            limits,
            seed: None,
        };
        let mut tx = disk.begin().await?;
        disk.insert(&mut tx, META, &ZERO, &ZERO, &meta).await?;
        disk.commit(tx).await?;
        Ok(Self {
            source,
            disk,
            cache: Mutex::new(Cache {
                meta,
                index: PoolIndex::default(),
            }),
        })
    }
    pub async fn resume(path: &Path, key: Key, source: Arc<Pool>) -> Result<Self> {
        let scope = Self::scope(&source);
        let disk = Disk::open(path, key, scope, false).await?;
        let mut tx = disk.begin().await?;
        let meta: Meta = disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("public pool index metadata missing")?;
        tx.rollback().await?;
        meta.limits.check()?;
        ensure!(
            matches!((meta.version, meta.seed.is_some()), (1, false) | (2, true))
                && meta.scope == scope
                && meta.records <= meta.updates
                && meta.updates <= meta.limits.max_updates
                && meta.base.cursor.epoch <= meta.cursor.cursor.epoch,
            "public pool index metadata differs"
        );
        Self::capture(&source).await?;
        let (mut index, mut updates) = seed::load(&disk, &meta).await?;
        ensure!(
            matches(&index, &Self::state_at(&source, &meta.base).await?),
            "public pool seed roots differ from canonical baseline"
        );
        let mut previous = meta.base.cursor.epoch.0;
        let mut tx = disk.begin().await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(RECORD))
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            u64::try_from(count)? == meta.records,
            "public pool index records are missing or orphaned"
        );
        for number in 1..=meta.records {
            let record: Record = disk
                .load(&mut tx, RECORD, &disk.tag(RECORD, &number.to_be_bytes())?)
                .await?
                .context("public pool index segment missing")?;
            ensure!(
                !record.updates.is_empty()
                    && record.updates.len() <= 64
                    && record.head.cursor.epoch.0 >= previous
                    && record.head.cursor.epoch <= meta.cursor.cursor.epoch,
                "public pool index segment order differs"
            );
            ensure!(
                source
                    .directory
                    .history
                    .head_for_epoch(record.head.cursor.epoch.0)
                    .await?
                    == record.head,
                "public pool index segment head differs"
            );
            for update in &record.updates {
                index = update.apply(&index, meta.limits.max_notes)?;
                updates += 1;
            }
            previous = record.head.cursor.epoch.0;
        }
        tx.rollback().await?;
        ensure!(
            updates == meta.updates
                && matches(&index, &Self::state_at(&source, &meta.cursor).await?),
            "public pool index reconstructed roots differ"
        );
        if meta.cursor.cursor.epoch.0 > source.directory.history.anchor().epoch.0 {
            source.record(meta.cursor.cursor.epoch.0).await?;
        }
        Self::capture(&source).await?;
        Ok(Self {
            source,
            disk,
            cache: Mutex::new(Cache { meta, index }),
        })
    }
    /// Advance a bounded number of canonical epochs. An incomplete prefix is
    /// durable but cannot mint a current View or authorize wallet spending.
    pub async fn sync(&self, max_epochs: usize) -> Result<Progress> {
        ensure!(
            (1..=128).contains(&max_epochs),
            "public pool index sync batch refused"
        );
        self.disk.check()?;
        let mut cache = self.cache.lock().await;
        let target = Self::capture(&self.source).await?;
        let target_epoch = target.committed().head().cursor.epoch.0;
        ensure!(
            cache.meta.cursor.cursor.epoch.0 <= target_epoch,
            "public pool index is ahead of canonical history"
        );
        let mut processed = 0;
        while cache.meta.cursor.cursor.epoch.0 < target_epoch && processed < max_epochs {
            let epoch = cache.meta.cursor.cursor.epoch.0 + 1;
            let execution = self.source.record(epoch).await?;
            ensure!(
                execution.lease.committed().head() == target.committed().head()
                    && execution.before.head() == &cache.meta.cursor,
                "public pool index publication changed"
            );
            ensure!(
                matches(
                    &cache.index,
                    &self.source.state(execution.before.snapshot())?
                ),
                "public pool index prior roots differ"
            );
            let after = self.source.state(execution.after.snapshot())?;
            let updates = if matches(&cache.index, &after) {
                Vec::new()
            } else {
                hints::read(&self.source, &execution).await?
            };
            let mut index = cache.index.clone();
            let mut meta = cache.meta.clone();
            meta.updates = meta
                .updates
                .checked_add(u64::try_from(updates.len())?)
                .context("public pool index update overflow")?;
            ensure!(
                meta.updates <= meta.limits.max_updates,
                "public pool index update budget exhausted"
            );
            for update in &updates {
                index = update.apply(&index, meta.limits.max_notes)?;
            }
            ensure!(
                matches(&index, &after),
                "pool hints do not reconstruct canonical roots"
            );
            target.with_current(PLAN_MAX_AGE, || Ok(()))?;
            let mut tx = self.disk.begin().await?;
            let saved: Meta = self
                .disk
                .load(&mut tx, META, &ZERO)
                .await?
                .context("public pool index metadata missing")?;
            ensure!(
                saved == cache.meta,
                "public pool index requires recovery after an interrupted commit"
            );
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                .bind(i64::from(RECORD))
                .fetch_one(&mut *tx)
                .await?;
            ensure!(
                u64::try_from(count)? == cache.meta.records,
                "public pool index records are missing or orphaned"
            );
            for chunk in updates.chunks(64) {
                meta.records += 1;
                let record = Record {
                    head: execution.after.head().clone(),
                    updates: chunk.to_vec(),
                };
                self.disk
                    .insert(
                        &mut tx,
                        RECORD,
                        &self.disk.tag(RECORD, &meta.records.to_be_bytes())?,
                        &ZERO,
                        &record,
                    )
                    .await?;
            }
            meta.cursor = execution.after.head().clone();
            self.disk.replace(&mut tx, META, &ZERO, &meta).await?;
            self.disk.commit(tx).await?;
            *cache = Cache { meta, index };
            processed += 1;
            target.with_current(PLAN_MAX_AGE, || Ok(()))?;
        }
        Ok(Progress {
            updates: cache.meta.updates,
            epoch: cache.meta.cursor.cursor.epoch.0,
            target: target_epoch,
            processed,
            complete: cache.meta.cursor.cursor.epoch.0 == target_epoch,
        })
    }
    pub async fn view(&self) -> Result<View> {
        self.disk.check()?;
        let cache = self.cache.lock().await;
        let lease = Self::capture(&self.source).await?;
        ensure!(
            cache.meta.cursor == *lease.committed().head()
                && matches(&cache.index, &self.source.state(lease.committed().state())?),
            "public pool index has not reached the published head"
        );
        Ok(View {
            lease,
            index: cache.index.clone(),
            scope: Self::scope(&self.source),
        })
    }
    pub async fn close(self) {
        self.disk.pool.close().await;
    }
}
