//! Individually sealed, bounded chunks keep large public witnesses out of
//! financial rows. Descriptor and all replacement chunks commit atomically.
use super::{Proof, MAX_BYTES};
use crate::vpn::payments::shielded::storage::Disk;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, Transaction};
const WIDTH: usize = 48 * 1024;
const ZERO: [u8; 32] = [0; 32];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    epoch: u64,
    anchor: u64,
    bytes: usize,
    parts: usize,
    digest: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    part: usize,
    data: String,
}
fn tag(disk: &Disk, kind: u8, epoch: u64, part: usize) -> Result<[u8; 32]> {
    disk.tag(
        kind,
        &[epoch.to_be_bytes().as_slice(), &(part as u64).to_be_bytes()].concat(),
    )
}
pub(in crate::vpn::payments::shielded) async fn load(
    disk: &Disk,
    kind: u8,
    epoch: u64,
) -> Result<Option<Proof>> {
    disk.check()?;
    let key = disk.tag(kind, &epoch.to_be_bytes())?;
    let mut tx = disk.begin().await?;
    let descriptor: Option<Descriptor> = disk.load(&mut tx, kind, &key).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=? AND bucket=?")
            .bind(i64::from(kind + 1))
            .bind(key.as_slice())
            .fetch_one(&mut *tx)
            .await?;
    let Some(descriptor) = descriptor else {
        ensure!(count == 0, "orphan portable history chunks");
        tx.rollback().await?;
        return Ok(None);
    };
    ensure!(
        descriptor.epoch == epoch
            && (1..=MAX_BYTES).contains(&descriptor.bytes)
            && descriptor.parts == descriptor.bytes.div_ceil(WIDTH)
            && count == i64::try_from(descriptor.parts)?,
        "portable history descriptor/chunks differ"
    );
    let mut raw = Vec::with_capacity(descriptor.bytes);
    for part in 0..descriptor.parts {
        let chunk: Chunk = disk
            .load(&mut tx, kind + 1, &tag(disk, kind + 1, epoch, part)?)
            .await?
            .context("portable history chunk missing")?;
        ensure!(
            chunk.part == part && chunk.data.len() <= WIDTH.div_ceil(3) * 4,
            "portable history chunk shape differs"
        );
        let data = STANDARD.decode(&chunk.data)?;
        ensure!(
            STANDARD.encode(&data) == chunk.data
                && data.len() == (descriptor.bytes - part * WIDTH).min(WIDTH),
            "portable history chunk length differs"
        );
        raw.extend_from_slice(&data);
    }
    tx.rollback().await?;
    ensure!(
        <[u8; 32]>::from(Sha256::digest(&raw)) == descriptor.digest,
        "portable history checksum differs"
    );
    let proof = Proof::decode(&raw)?;
    ensure!(
        proof.epoch() == epoch && proof.anchor() == descriptor.anchor,
        "portable history identity differs"
    );
    Ok(Some(proof))
}
pub(in crate::vpn::payments::shielded) async fn save(
    disk: &Disk,
    tx: &mut Transaction<'_, Sqlite>,
    kind: u8,
    proof: &Proof,
) -> Result<()> {
    disk.check()?;
    let epoch = proof.epoch();
    let key = disk.tag(kind, &epoch.to_be_bytes())?;
    let previous: Option<Descriptor> = disk.load(tx, kind, &key).await?;
    if let Some(previous) = &previous {
        ensure!(
            proof.anchor() >= previous.anchor,
            "portable history anchor regressed"
        );
    }
    let raw = proof.encode()?;
    sqlx::query("DELETE FROM wallet_records WHERE kind=? AND bucket=?")
        .bind(i64::from(kind + 1))
        .bind(key.as_slice())
        .execute(&mut **tx)
        .await?;
    for (part, data) in raw.chunks(WIDTH).enumerate() {
        disk.insert(
            tx,
            kind + 1,
            &tag(disk, kind + 1, epoch, part)?,
            &key,
            &Chunk {
                part,
                data: STANDARD.encode(data),
            },
        )
        .await?;
    }
    let descriptor = Descriptor {
        epoch,
        anchor: proof.anchor(),
        bytes: raw.len(),
        parts: raw.len().div_ceil(WIDTH),
        digest: Sha256::digest(&raw).into(),
    };
    if previous.is_some() {
        disk.replace(tx, kind, &key, &descriptor).await?;
    } else {
        disk.insert(tx, kind, &key, &ZERO, &descriptor).await?;
    }
    Ok(())
}
