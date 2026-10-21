//! Portable execution evidence linked backwards from a node-authenticated
//! retained certificate. A peer's self-consistent QC is never its own authority.
mod image;
pub(super) mod storage;
use super::{Historical, Pool, PLAN_MAX_AGE};
use anyhow::{ensure, Context, Result};
use image::Image;
use octra_node_protocol::{
    consensus::{
        codec::{self, Wire},
        hash, qc, CatchupEpochRecord, ParentCommit, CURRENT_VERSION,
    },
    native_json::Document,
    oce1::{Reader, Writer},
    transaction::{RuleMode, Transaction},
    transaction_outcome,
};
use octra_node_runtime::{
    canonical::Head, circle_view, finality_queries::Range, state_batch::Snapshot,
};
use sha2::{Digest, Sha256};
pub(super) const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PART: usize = 8 * 1024 * 1024;
const MAX_LINKS: usize = 4096;
const MAGIC: &[u8; 8] = b"OVPNH001";

/// Public historical state and commitments only. Keep its association with a
/// private invoice or wallet encrypted. Decode does not authenticate evidence.
pub struct Proof {
    scope: [u8; 32],
    epoch: u64,
    chain: Vec<ParentCommit>,
    before: Image,
    after: Image,
    record: Vec<u8>,
}
pub struct Progress {
    pub prepared: usize,
    pub remaining: usize,
    pub anchor: u64,
}
/// Historical execution only. It cannot authorize a new payment or a current
/// service grant. The caller must supply this node's authenticated retained view.
pub(super) struct Verified {
    pub before: octra_node_runtime::state_batch::Snapshot,
    pub after: octra_node_runtime::state_batch::Snapshot,
    pub record: CatchupEpochRecord,
    pub paid_at: u64,
    pub now: u64,
}
/// A bounded authenticated application projection. This deliberately carries
/// no canonical-assets type and cannot be used as a complete execution tree.
pub(super) struct Projection {
    head: Head,
    snapshot: Snapshot,
    image: Image,
}
impl Projection {
    pub(super) async fn at(source: &Pool, head: Head) -> Result<Self> {
        let image = Image::at(source, &head).await?;
        let snapshot = image.restore(source, &head.cursor.state_root.0)?;
        ensure!(
            snapshot
                .get(&[b"meta", b"last_epoch"])
                .and_then(octra_node_protocol::native_integer::parse_int64)
                == i64::try_from(head.cursor.epoch.0).ok(),
            "private historical projection epoch differs"
        );
        Ok(Self {
            head,
            snapshot,
            image,
        })
    }
    pub(super) fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub(super) fn head(&self) -> &Head {
        &self.head
    }
}
fn scope(source: &Pool) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"Octranet portable execution v1\0");
    h.update(source.origin);
    h.update(source.address);
    h.update(source.code_hash.as_bytes());
    h.update(source.config.factory.as_bytes());
    h.update(source.factory_hash.as_bytes());
    h.update(source.directory.config.program.as_bytes());
    h.update(source.directory.config.code_hash.as_bytes());
    h.update(source.directory.config.factory.as_bytes());
    h.update(source.directory.config.factory_code_hash.as_bytes());
    h.finalize().into()
}
async fn record(source: &Pool, epoch: u64) -> Result<CatchupEpochRecord> {
    let (_, history) = source
        .directory
        .circle_authority
        .as_ref()
        .context("portable history authority missing")?;
    let Range::Found { mut records, .. } = history.range(epoch.try_into()?, 1).await? else {
        anyhow::bail!("portable finalized record missing");
    };
    ensure!(
        records.len() == 1 && records[0].epoch_id == i64::try_from(epoch)?,
        "portable finalized epoch differs"
    );
    Ok(records.remove(0))
}
fn parent(record: &CatchupEpochRecord) -> Result<ParentCommit> {
    let finality = record
        .finality
        .as_ref()
        .context("portable finality missing")?;
    Ok(ParentCommit {
        certificate: finality.finalize.certificate(),
        validator_set: finality.validator_set.clone(),
    })
}
async fn trusted(source: &Pool, epoch: u64) -> Result<ParentCommit> {
    if epoch == source.directory.history.anchor().epoch.0 {
        return source
            .directory
            .history
            .checkpoint_parent()
            .map(|p| p.as_ref().clone())
            .context("portable anchor has no finalized authority");
    }
    parent(&record(source, epoch).await?)
}
fn linked(chain: &[u8], child: &ParentCommit, older: &ParentCommit) -> Result<()> {
    let a = &child.certificate;
    let b = &older.certificate;
    ensure!(
        a.header.proto_version == CURRENT_VERSION,
        "portable ancestry lacks a signed parent commitment"
    );
    ensure!(
        a.epoch_id.checked_sub(1) == Some(b.epoch_id)
            && a.header.prev_state_root == b.header.proposed_state_root
            && a.header.parent_commit_hash == hash::parent_commit_hash(older)?,
        "portable parent link differs"
    );
    qc::validate_certificate(chain, &older.validator_set, b, false)?;
    Ok(())
}
async fn bridge(source: &Pool, anchor: u64, end: u64) -> Result<Vec<ParentCommit>> {
    ensure!(
        anchor >= end && anchor - end < MAX_LINKS as u64,
        "portable ancestry exceeds limit"
    );
    let mut chain = vec![trusted(source, anchor).await?];
    for epoch in (end + 1..=anchor).rev() {
        let current = record(source, epoch).await?;
        ensure!(
            parent(&current)?.encode()?
                == chain.last().context("portable chain empty")?.encode()?,
            "portable retained certificate differs"
        );
        let older = current
            .finality
            .context("portable finality missing")?
            .finalize
            .parent_commit
            .context("portable parent missing")?;
        linked(
            source.directory.history.chain().chain_id.as_bytes(),
            chain.last().context("portable chain empty")?,
            &older,
        )?;
        chain.push(older);
    }
    Ok(chain)
}
impl Proof {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn anchor(&self) -> u64 {
        self.chain
            .first()
            .map_or(0, |p| p.certificate.epoch_id as u64)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            !self.chain.is_empty() && self.chain.len() <= MAX_LINKS,
            "portable ancestry count differs"
        );
        let mut out = Writer::new();
        out.put_raw(MAGIC)?;
        out.put_hash32(&self.scope)?;
        out.put_u64(self.epoch)?;
        out.put_u32(self.chain.len().try_into()?)?;
        for parent in &self.chain {
            let raw = parent.encode()?;
            ensure!(raw.len() <= MAX_PART, "portable certificate exceeds limit");
            out.put_bytes(&raw)?;
        }
        self.before.put(&mut out)?;
        self.after.put(&mut out)?;
        out.put_bytes(&self.record)?;
        let raw = out.into_bytes();
        ensure!(raw.len() <= MAX_BYTES, "portable evidence exceeds limit");
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() <= MAX_BYTES, "portable evidence exceeds limit");
        let mut input = Reader::new(raw);
        ensure!(
            input.get_raw(8)? == MAGIC,
            "portable evidence header differs"
        );
        let scope = input.get_hash32()?;
        let epoch = input.get_u64()?;
        let count = input.get_u32()?;
        ensure!(
            (1..=MAX_LINKS as u32).contains(&count),
            "portable ancestry count differs"
        );
        let mut chain = Vec::new();
        for _ in 0..count {
            chain.push(ParentCommit::decode(input.get_bytes_bounded(MAX_PART)?)?);
        }
        let before = Image::get(&mut input)?;
        let after = Image::get(&mut input)?;
        let record = input.get_bytes_bounded(MAX_BYTES)?.to_vec();
        input.finish()?;
        ensure!(epoch > 0, "portable epoch is zero");
        Ok(Self {
            scope,
            epoch,
            chain,
            before,
            after,
            record,
        })
    }
    pub(super) async fn capture(
        source: &Pool,
        epoch: u64,
        anchor: u64,
        prior: Option<Self>,
    ) -> Result<Self> {
        let lease = crate::SnapshotLease::capture(source.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        ensure!(
            anchor <= lease.committed().head().cursor.epoch.0
                && epoch > 0
                && epoch <= anchor,
            "portable capture is not published"
        );
        let result = if epoch > source.directory.history.anchor().epoch.0 {
            let execution = source.epoch(epoch).await?;
            let before = execution.before.image;
            let after = execution.after.image;
            let mut out = Writer::new();
            codec::put_catchup_record(&mut out, &execution.record, true)?;
            Self {
                scope: scope(source),
                epoch,
                chain: bridge(source, anchor, epoch).await?,
                before,
                after,
                record: out.into_bytes(),
            }
        } else {
            let mut old =
                prior.context("portable evidence missing below retained history floor")?;
            ensure!(
                old.epoch == epoch && anchor >= old.anchor(),
                "portable evidence anchor regressed"
            );
            old.verify(source).await?;
            let mut prefix = bridge(source, anchor, old.anchor()).await?;
            ensure!(
                prefix.last().context("portable chain empty")?.encode()?
                    == old.chain[0].encode()?,
                "portable extension joins another certificate"
            );
            prefix.pop();
            prefix.append(&mut old.chain);
            old.chain = prefix;
            old
        };
        result.encode()?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(result)
    }
    pub(super) async fn verify(&self, source: &Pool) -> Result<Historical> {
        let lease = crate::SnapshotLease::capture(source.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        let verified = self.verify_at(source, lease.committed()).await?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(Historical {
            lease,
            before: verified.before,
            after: verified.after,
            record: verified.record,
            paid_at: verified.paid_at,
            now: verified.now,
        })
    }
    pub(super) async fn verify_at(
        &self,
        source: &Pool,
        committed: &crate::Committed,
    ) -> Result<Verified> {
        ensure!(
            self.scope == scope(source)
                && self.epoch > 0
                && !self.chain.is_empty()
                && self.chain.len() <= MAX_LINKS,
            "portable evidence scope/count differs"
        );
        ensure!(
            self.anchor() <= committed.head().cursor.epoch.0,
            "portable anchor is not published"
        );
        source.directory.check_value_effects(committed).await?;
        let now = source.directory.canonical_time(committed).await?;
        let current = source.state(committed.state())?;
        let expected = trusted(source, self.anchor()).await?;
        ensure!(
            expected.encode()? == self.chain[0].encode()?,
            "portable evidence is not linked to this node's canonical certificate"
        );
        for pair in self.chain.windows(2) {
            linked(
                source.directory.history.chain().chain_id.as_bytes(),
                &pair[0],
                &pair[1],
            )?;
        }
        let terminal = self.chain.last().context("portable terminal missing")?;
        ensure!(
            terminal.certificate.epoch_id == i64::try_from(self.epoch)?,
            "portable terminal epoch differs"
        );
        let before = self
            .before
            .restore(source, &terminal.certificate.header.prev_state_root)?;
        let after = self
            .after
            .restore(source, &terminal.certificate.header.proposed_state_root)?;
        source.state(&before)?;
        let paid = source.state(&after)?;
        ensure!(
            paid.count <= current.count,
            "portable pool history regressed"
        );
        let epoch = circle_view::epoch(
            before.get(&[b"meta", b"last_epoch"]),
            circle_view::ReadKind::View,
        )?;
        ensure!(
            epoch == i64::try_from(self.epoch)?,
            "portable before epoch differs"
        );
        let (graph, history) = source
            .directory
            .circle_authority
            .as_ref()
            .context("portable rule authority missing")?;
        let profile = circle_view::anchored(graph, epoch, self.epoch - 1, history.as_ref()).await?;
        ensure!(
            profile.math && profile.proof_exec == RuleMode::Active,
            "portable historical value rules are inactive"
        );
        let mut input = Reader::new(&self.record);
        let record = codec::get_catchup_record(&mut input, true)?;
        input.finish()?;
        ensure!(
            parent(&record)?.encode()? == terminal.encode()?,
            "portable execution certificate differs"
        );
        let expected_set = hash::validator_set_hash(&terminal.validator_set)?;
        let next = terminal
            .certificate
            .header
            .txid_hi
            .checked_add(1)
            .context("portable transaction counter overflow")?;
        octra_node_protocol::consensus::catchup::verify_record_finality(
            source.directory.history.chain().chain_id.as_bytes(),
            &expected_set,
            next,
            &record,
        )?;
        let parsed = record
            .txs_json
            .iter()
            .map(|raw| Ok::<_, anyhow::Error>(Transaction::from_document(&Document::parse(raw)?)?))
            .collect::<Result<Vec<_>>>()?;
        let hashes = parsed
            .iter()
            .map(|tx| tx.hash().map(|h| h.to_vec()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        octra_node_protocol::consensus::catchup::verify_record_hashes(&record, &hashes)?;
        octra_node_protocol::consensus::catchup::verify_record_receipts(&record)?;
        transaction_outcome::decode(&parsed, &record.receipts_json, false)?;
        let paid_at = u64::try_from(octra_node_protocol::consensus::policy::time_of_seconds(
            record.epoch_ts,
        )?)?;
        ensure!(
            paid_at <= now,
            "portable payment clock is ahead of canonical time"
        );
        Ok(Verified {
            before,
            after,
            record,
            paid_at,
            now,
        })
    }
}

#[cfg(test)]
pub(crate) async fn adversarial(proof: &Proof, source: &Pool) {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    let raw = proof.encode().unwrap();
    let mut bad = raw.clone();
    bad[8] ^= 1;
    assert!(Proof::decode(&bad).unwrap().verify(source).await.is_err());
    let mut bad = raw.clone();
    bad[48..52].copy_from_slice(&4097_u32.to_be_bytes());
    assert!(Proof::decode(&bad).is_err());
    let mut bad = Proof::decode(&raw).unwrap();
    bad.chain.pop();
    assert!(bad.verify(source).await.is_err());
    let mut bad = Proof::decode(&raw).unwrap();
    bad.before.corrupt();
    assert!(bad.verify(source).await.is_err());
    let mut bad = Proof::decode(&raw).unwrap();
    let last = bad.record.len() - 1;
    bad.record[last] ^= 1;
    assert!(bad.verify(source).await.is_err());
    // A valid quorum on another header with the same state root still cannot
    // substitute for the exact retained certificate chosen by this node.
    let mut bad = Proof::decode(&raw).unwrap();
    let certificate = &mut bad.chain[0].certificate;
    certificate.header.ts += 1.0;
    certificate.proposal_id = hash::proposal_id(&certificate.header).unwrap().to_vec();
    for vote in &mut certificate.precommits {
        vote.proposal_id = certificate.proposal_id.clone();
        let key = (1_u8..=4)
            .map(|n| SigningKey::from_bytes(&[n; 32]))
            .find(|key| {
                octra_node_protocol::transaction::address_from_public_key(
                    STANDARD.encode(key.verifying_key().as_bytes()).as_bytes(),
                ) == vote.validator
            })
            .unwrap();
        vote.signature = key
            .sign(&hash::vote_sign_bytes(vote).unwrap())
            .to_bytes()
            .to_vec();
    }
    qc::validate_certificate(
        source.directory.history.chain().chain_id.as_bytes(),
        &bad.chain[0].validator_set,
        &bad.chain[0].certificate,
        false,
    )
    .unwrap();
    assert!(bad.verify(source).await.is_err());
    let mut legacy = bad.chain[0].clone();
    legacy.certificate.header.proto_version = 3;
    assert!(linked(
        source.directory.history.chain().chain_id.as_bytes(),
        &legacy,
        &bad.chain[1]
    )
    .is_err());
}
