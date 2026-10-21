//! Public bootstrap hints. Neither the wire header nor a stored digest is
//! authority: both reconstructed trees must match the node's canonical state.
use super::{
    matches, pool, Cache, Disk, Head, Index, Limits, Meta, Pool, PoolIndex, View, META,
    PLAN_MAX_AGE, RECORD, ZERO,
};
use anyhow::{ensure, Context, Result};
use octravpn_core::sealed::Key;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;
const KIND: u8 = 2;
const WIDTH: usize = 128;
const HEADER: usize = 96;
const MAGIC: &[u8; 8] = b"OVPNPI01";

/// Commitments in append order and sorted nullifiers. No private note data,
/// amount, spending key or witness is exported.
pub struct Seed {
    scope: [u8; 32],
    epoch: u64,
    state_root: [u8; 32],
    notes: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Base {
    notes: u64,
    nullifiers: u64,
    segments: u64,
    prior_updates: u64,
    digest: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    part: u64,
    notes: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
}
impl Seed {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    fn check(&self, limits: Limits) -> Result<()> {
        limits.check()?;
        ensure!(
            u64::try_from(self.notes.len())? <= limits.max_notes
                && u64::try_from(self.nullifiers.len())? <= limits.max_notes,
            "public pool seed exceeds resource budget"
        );
        ensure!(
            self.nullifiers.windows(2).all(|p| p[0] < p[1]),
            "public pool seed nullifiers are not strictly ordered"
        );
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check(Limits {
            max_notes: 1_000_000,
            max_updates: 1_000_000,
        })?;
        let mut out = Vec::with_capacity(HEADER + 32 * (self.notes.len() + self.nullifiers.len()));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&u64::try_from(self.notes.len())?.to_be_bytes());
        out.extend_from_slice(&u64::try_from(self.nullifiers.len())?.to_be_bytes());
        for field in self.notes.iter().chain(&self.nullifiers) {
            out.extend_from_slice(field);
        }
        Ok(out)
    }
    /// Bound both counts and the exact byte length before allocating leaf lists.
    pub fn decode(raw: &[u8], limits: Limits) -> Result<Self> {
        limits.check()?;
        ensure!(
            raw.len() >= HEADER && raw.starts_with(MAGIC),
            "public pool seed header differs"
        );
        let number =
            |a: usize| -> Result<u64> { Ok(u64::from_be_bytes(raw[a..a + 8].try_into()?)) };
        let notes = number(80)?;
        let nullifiers = number(88)?;
        ensure!(
            notes <= limits.max_notes && nullifiers <= limits.max_notes,
            "public pool seed exceeds resource budget"
        );
        let total = usize::try_from(notes + nullifiers)?;
        ensure!(
            raw.len() == HEADER + 32 * total,
            "public pool seed length differs"
        );
        let (note_bytes, nullifier_bytes) = raw[HEADER..].split_at(32 * usize::try_from(notes)?);
        let fields = |raw: &[u8]| {
            raw.chunks_exact(32)
                .map(|p| p.try_into().map_err(Into::into))
                .collect::<Result<Vec<[u8; 32]>>>()
        };
        let value = Self {
            scope: raw[8..40].try_into()?,
            epoch: number(40)?,
            state_root: raw[48..80].try_into()?,
            notes: fields(note_bytes)?,
            nullifiers: fields(nullifier_bytes)?,
        };
        value.check(limits)?;
        Ok(value)
    }
    fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}
impl View {
    pub fn seed(&self) -> Result<Seed> {
        self.lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        let pool::PublicLeaves {
            notes,
            mut nullifiers,
        } = self.index.public_leaves()?;
        nullifiers.sort_unstable();
        let head = self.lease.committed().head();
        let seed = Seed {
            scope: self.scope,
            epoch: head.cursor.epoch.0,
            state_root: head.cursor.state_root.0,
            notes,
            nullifiers,
        };
        self.lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(seed)
    }
}
async fn authenticate(source: &Pool, seed: &Seed, limits: Limits) -> Result<(Head, PoolIndex)> {
    seed.check(limits)?;
    let lease = Index::capture(source).await?;
    let result = authenticate_at(source, seed, limits, lease.committed()).await?;
    if seed.epoch > source.directory.history.anchor().epoch.0 {
        source.record(seed.epoch).await?;
    }
    lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
    Ok(result)
}
pub(super) async fn authenticate_at(
    source: &Pool,
    seed: &Seed,
    limits: Limits,
    committed: &crate::Committed,
) -> Result<(Head, PoolIndex)> {
    seed.check(limits)?;
    ensure!(
        seed.scope == Index::scope(source),
        "public pool seed scope differs"
    );
    ensure!(
        seed.epoch <= committed.head().cursor.epoch.0,
        "public pool seed epoch is not published"
    );
    let head = source.directory.history.head_for_epoch(seed.epoch).await?;
    ensure!(
        head.cursor.state_root.0 == seed.state_root,
        "public pool seed native root differs"
    );
    let state = Index::state_at(source, &head).await?;
    ensure!(
        state.count == u64::try_from(seed.notes.len())?,
        "public pool seed note count differs"
    );
    let index = PoolIndex::rebuild(&seed.notes, &seed.nullifiers)?;
    ensure!(
        matches(&index, &state),
        "public pool seed does not reconstruct canonical roots"
    );
    Ok((head, index))
}
async fn save(
    disk: &Disk,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    seed: &Seed,
    prior_updates: u64,
) -> Result<Base> {
    let count = seed.notes.len().max(seed.nullifiers.len()).div_ceil(WIDTH);
    for part in 0..count {
        let chunk = |v: &[[u8; 32]]| {
            v[(part * WIDTH).min(v.len())..((part + 1) * WIDTH).min(v.len())].to_vec()
        };
        let row = Segment {
            part: u64::try_from(part + 1)?,
            notes: chunk(&seed.notes),
            nullifiers: chunk(&seed.nullifiers),
        };
        disk.insert(
            tx,
            KIND,
            &disk.tag(KIND, &row.part.to_be_bytes())?,
            &ZERO,
            &row,
        )
        .await?;
    }
    Ok(Base {
        notes: u64::try_from(seed.notes.len())?,
        nullifiers: u64::try_from(seed.nullifiers.len())?,
        segments: u64::try_from(count)?,
        prior_updates,
        digest: seed.digest()?,
    })
}
pub(super) async fn load(disk: &Disk, meta: &Meta) -> Result<(PoolIndex, u64)> {
    let mut tx = disk.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
        .bind(i64::from(KIND))
        .fetch_one(&mut *tx)
        .await?;
    let Some(base) = &meta.seed else {
        ensure!(count == 0, "orphan public pool seed records");
        tx.rollback().await?;
        return Ok((PoolIndex::default(), 0));
    };
    ensure!(
        base.notes <= meta.limits.max_notes
            && base.nullifiers <= meta.limits.max_notes
            && base.prior_updates <= meta.updates
            && base.segments
                == base
                    .notes
                    .max(base.nullifiers)
                    .div_ceil(u64::try_from(WIDTH)?)
            && u64::try_from(count)? == base.segments,
        "public pool seed metadata or records differ"
    );
    let mut notes = Vec::new();
    let mut nullifiers = Vec::new();
    for part in 1..=base.segments {
        let row: Segment = disk
            .load(&mut tx, KIND, &disk.tag(KIND, &part.to_be_bytes())?)
            .await?
            .context("public pool seed segment missing")?;
        let expected =
            |total: u64| usize::try_from(total.saturating_sub((part - 1) * 128).min(128));
        ensure!(
            row.part == part
                && row.notes.len() == expected(base.notes)?
                && row.nullifiers.len() == expected(base.nullifiers)?,
            "public pool seed segment shape differs"
        );
        notes.extend(row.notes);
        nullifiers.extend(row.nullifiers);
    }
    tx.rollback().await?;
    let seed = Seed {
        scope: meta.scope,
        epoch: meta.base.cursor.epoch.0,
        state_root: meta.base.cursor.state_root.0,
        notes,
        nullifiers,
    };
    seed.check(meta.limits)?;
    ensure!(
        seed.digest()? == base.digest,
        "public pool seed digest differs"
    );
    Ok((
        PoolIndex::rebuild(&seed.notes, &seed.nullifiers)?,
        base.prior_updates,
    ))
}
impl Index {
    pub async fn bootstrap(
        path: &Path,
        key: Key,
        source: Arc<Pool>,
        seed: &Seed,
        limits: Limits,
    ) -> Result<Self> {
        let (head, index) = authenticate(&source, seed, limits).await?;
        Self::create_seeded(path, key, source, seed, limits, head, index).await
    }
    pub(super) async fn create_seeded(
        path: &Path,
        key: Key,
        source: Arc<Pool>,
        seed: &Seed,
        limits: Limits,
        head: Head,
        index: PoolIndex,
    ) -> Result<Self> {
        let scope = Self::scope(&source);
        let disk = Disk::open(path, key, scope, true).await?;
        let mut tx = disk.begin().await?;
        let base = save(&disk, &mut tx, seed, 0).await?;
        let meta = Meta {
            version: 2,
            scope,
            base: head.clone(),
            cursor: head,
            records: 0,
            updates: 0,
            limits,
            seed: Some(base),
        };
        disk.insert(&mut tx, META, &ZERO, &ZERO, &meta).await?;
        disk.commit(tx).await?;
        Ok(Self {
            source,
            disk,
            cache: Mutex::new(Cache { meta, index }),
        })
    }
    /// Explicit repair/rebase of public index data. Monetary wallet journals
    /// are separate. Accepted resource limits and consumed updates do not reset.
    pub async fn reanchor(path: &Path, key: Key, source: Arc<Pool>, seed: &Seed) -> Result<Self> {
        let scope = Self::scope(&source);
        let disk = Disk::open(path, key, scope, false).await?;
        let mut tx = disk.begin().await?;
        let mut meta: Meta = disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("public pool index metadata missing")?;
        tx.rollback().await?;
        meta.limits.check()?;
        ensure!(
            matches!((meta.version, meta.seed.is_some()), (1, false) | (2, true))
                && meta.scope == scope
                && meta.records <= meta.updates
                && meta.updates <= meta.limits.max_updates,
            "public pool index metadata differs"
        );
        ensure!(
            seed.epoch >= meta.cursor.cursor.epoch.0,
            "public pool seed regresses the saved cursor"
        );
        let (head, index) = authenticate(&source, seed, meta.limits).await?;
        let mut tx = disk.begin().await?;
        sqlx::query("DELETE FROM wallet_records WHERE kind IN (?,?)")
            .bind(i64::from(RECORD))
            .bind(i64::from(KIND))
            .execute(&mut *tx)
            .await?;
        let base = save(&disk, &mut tx, seed, meta.updates).await?;
        meta.version = 2;
        meta.base = head.clone();
        meta.cursor = head;
        meta.records = 0;
        meta.seed = Some(base);
        disk.replace(&mut tx, META, &ZERO, &meta).await?;
        disk.commit(tx).await?;
        Ok(Self {
            source,
            disk,
            cache: Mutex::new(Cache { meta, index }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seed_codec_bounds_counts_before_allocating_and_rejects_aliases() {
        let seed = Seed {
            scope: [1; 32],
            epoch: 7,
            state_root: [2; 32],
            notes: vec![[3; 32]],
            nullifiers: vec![[4; 32], [5; 32]],
        };
        let raw = seed.encode().unwrap();
        assert_eq!(
            Seed::decode(&raw, Limits::default())
                .unwrap()
                .encode()
                .unwrap(),
            raw
        );
        assert!(Seed::decode(&raw[..HEADER - 1], Limits::default()).is_err());
        let mut extra = raw.clone();
        extra.push(0);
        assert!(Seed::decode(&extra, Limits::default()).is_err());
        let mut huge = raw.clone();
        huge[80..88].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Seed::decode(&huge, Limits::default()).is_err());
        let mut alias = raw;
        alias[HEADER + 64..HEADER + 96].copy_from_slice(&[4; 32]);
        assert!(Seed::decode(&alias, Limits::default()).is_err());
    }
}
