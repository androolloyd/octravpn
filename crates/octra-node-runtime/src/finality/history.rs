//! Native peer query data built from revalidated canonical history.
use super::{invalid, Publisher, Result, ValidatorHistory};
use crate::{canonical::Head, consensus_bundle::RawBundle, finality_queries::Range};
use octra_exex::Sequence;
use octra_node_protocol::{
    consensus::{catchup, codec::Wire, reward, CatchupEpochRecord},
    oce1::Writer,
};

#[async_trait::async_trait]
pub trait History: Send + Sync {
    async fn head(&self) -> Result<Head>;
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>>;
    async fn range(&self, from_epoch: i64, max_epochs: i64) -> Result<Range>;
    async fn bundle(&self, proposal: &[u8; 32]) -> Result<Option<RawBundle>>;
}
fn record_size(record: &CatchupEpochRecord) -> Result<usize> {
    let source = record
        .reward_source
        .as_ref()
        .ok_or_else(|| invalid("archived reward source missing"))?;
    let proof = record
        .finality
        .as_ref()
        .ok_or_else(|| invalid("archived finality missing"))?;
    let mut writer = Writer::new();
    reward::put(&mut writer, source).map_err(invalid)?;
    let metadata = [
        136,
        writer.into_bytes().len(),
        proof.finalize.encode().map_err(invalid)?.len(),
        proof.validator_set.encode().map_err(invalid)?.len(),
    ];
    metadata
        .into_iter()
        .chain(
            record
                .txs_json
                .iter()
                .chain(&record.receipts_json)
                .map(|s| s.len() + 32),
        )
        .try_fold(0usize, |sum, size| {
            sum.checked_add(size)
                .ok_or_else(|| invalid("catch-up record size overflow"))
        })
}
#[async_trait::async_trait]
impl<A: ValidatorHistory> History for Publisher<A> {
    async fn head(&self) -> Result<Head> {
        Ok(self.store.head().await?)
    }
    async fn root(&self, epoch: i64) -> Result<Option<Vec<u8>>> {
        let Ok(number) = u64::try_from(epoch) else {
            return Ok(None);
        };
        let Some(sequence) = self.store.sequence_for_epoch(number).await? else {
            return Ok(self.store.checkpoint_root(epoch));
        };
        if sequence == Sequence(0) {
            return Ok(Some(self.store.anchor().cursor.state_root.0.to_vec()));
        }
        Ok(Some(self.record(sequence).await?.state_root))
    }

    async fn range(&self, from_epoch: i64, max_epochs: i64) -> Result<Range> {
        let maximum = max_epochs.min(catchup::RANGE_EPOCHS);
        if from_epoch < 1 || maximum <= 0 || from_epoch as u64 <= self.store.anchor().cursor.epoch.0
        {
            return Ok(Range::NotFound);
        }
        // A fixed committed prefix keeps concurrent publication out of this reply.
        let head = self.store.head().await?;
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut next = from_epoch;
        for _ in 0..maximum {
            if next as u64 > head.cursor.epoch.0 {
                break;
            }
            let sequence = self
                .store
                .sequence_for_epoch(next as u64)
                .await?
                .ok_or_else(|| invalid("canonical epoch unavailable"))?;
            let record = self.record(sequence).await?;
            let size = record_size(&record)?;
            let total = bytes
                .checked_add(size)
                .ok_or_else(|| invalid("catch-up range size overflow"))?;
            if total > 4_000_000 && !records.is_empty() {
                break;
            }
            records.push(record);
            bytes = total;
            next = next
                .checked_add(1)
                .ok_or_else(|| invalid("catch-up epoch overflow"))?;
        }
        Ok(if records.is_empty() {
            Range::NotFound
        } else {
            Range::Found {
                records,
                next_epoch: Some(next),
            }
        })
    }
    async fn bundle(&self, proposal: &[u8; 32]) -> Result<Option<RawBundle>> {
        let Some(sequence) = self.store.proposal_sequence(proposal).await? else {
            return Ok(None);
        };
        let record = self.record(sequence).await?;
        Ok(Some(RawBundle {
            tx_hashes: record.tx_hashes,
            txs_json: record.txs_json,
            receipts_json: record.receipts_json,
        }))
    }
}
