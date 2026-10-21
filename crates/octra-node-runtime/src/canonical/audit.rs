//! One captured retained record. Warm audits hash the persisted bytes before
//! decoding the archive; a cache miss authenticates these same captured bytes.
use super::{decode_head_parts, error, CanonicalStore, Head, Result};
use octra_exex::Sequence;
use sha2::{Digest as _, Sha256};
use sqlx::Row;

pub(crate) struct AuditRecord {
    pub base: Head,
    pub head: Head,
    pub certificate: Vec<u8>,
    pub receipts: Vec<u8>,
    pub proposal: Vec<u8>,
    pub reward: Vec<u8>,
    pub events: Vec<u8>,
}

impl AuditRecord {
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"octra:retained-audit-bytes:v1\0");
        for bytes in [
            &self.certificate,
            &self.receipts,
            &self.proposal,
            &self.reward,
            &self.events,
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    }
}

impl CanonicalStore {
    pub(crate) async fn audit_record(&self, sequence: Sequence) -> Result<AuditRecord> {
        let row = sqlx::query(
            r"SELECT b.sequence AS base_sequence,b.head AS base_head,b.root AS base_root,
                      h.sequence AS head_sequence,h.head AS head_head,h.root AS head_root,
                      h.certificate,r.receipts,w.proposal,w.source AS reward,
                      e.sequence AS event_sequence,e.epoch AS event_epoch,
                      e.parent_root AS event_parent,e.root AS event_root,e.events
               FROM node_epochs h
               JOIN node_epochs b ON b.sequence=h.sequence-1
               JOIN node_consensus_receipts r ON r.sequence=h.sequence
               JOIN node_epoch_rewards w ON w.sequence=h.sequence
               JOIN exex_committed_epoch e ON e.chain_id=? AND e.genesis=? AND e.sequence=?
               WHERE h.sequence=?",
        )
        .bind(&self.chain().chain_id)
        .bind(self.chain().namespace_key().as_slice())
        .bind(format!("{:016x}", sequence.0))
        .bind(i64::try_from(sequence.0).map_err(error)?)
        .fetch_one(&self.pool)
        .await
        .map_err(error)?;
        let head = |prefix: &str| -> Result<Head> {
            decode_head_parts(
                row.try_get(format!("{prefix}_sequence").as_str())
                    .map_err(error)?,
                row.try_get(format!("{prefix}_head").as_str())
                    .map_err(error)?,
                row.try_get(format!("{prefix}_root").as_str())
                    .map_err(error)?,
            )
        };
        let base = head("base")?;
        let head = head("head")?;
        self.chain()
            .bind_checkpoint(head.cursor.epoch.0, head.cursor.state_root)
            .map_err(error)?;
        if row.try_get::<String, _>("event_sequence").map_err(error)?
            != format!("{:016x}", head.cursor.sequence.0)
            || row.try_get::<String, _>("event_epoch").map_err(error)?
                != format!("{:016x}", head.cursor.epoch.0)
            || row.try_get::<Vec<u8>, _>("event_parent").map_err(error)? != base.cursor.state_root.0
            || row.try_get::<Vec<u8>, _>("event_root").map_err(error)? != head.cursor.state_root.0
        {
            return Err(error("canonical outbox binding differs"));
        }
        Ok(AuditRecord {
            base,
            head,
            certificate: row.try_get("certificate").map_err(error)?,
            receipts: row.try_get("receipts").map_err(error)?,
            proposal: row.try_get("proposal").map_err(error)?,
            reward: row.try_get("reward").map_err(error)?,
            events: row.try_get("events").map_err(error)?,
        })
    }
}
