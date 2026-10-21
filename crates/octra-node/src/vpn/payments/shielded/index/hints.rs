//! Receipt events are recovery hints, never funding or finality authority.
use super::{pool, Pool, PoolIndex};
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{
    native_json::Document,
    transaction::{OpType, Transaction},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Delta {
    notes: [u8; 32],
    spent: [u8; 32],
    count: u64,
    nullifiers: [[u8; 32]; 2],
    outputs: [[u8; 32]; 2],
}
impl Delta {
    fn values(values: &[Value], direct: bool) -> Result<Self> {
        ensure!(
            values.len() == if direct { 16 } else { 11 },
            "pool hint field count differs"
        );
        let field = |i: usize| -> Result<[u8; 32]> {
            super::super::hash(values[i].as_str().context("pool hint field is not text")?)
        };
        let count = if direct {
            values[2].as_u64().context("pool hint count is not uint")?
        } else {
            let text = values[2].as_str().context("pool event count is not text")?;
            let count: u64 = text.parse()?;
            ensure!(
                count.to_string() == text,
                "pool event count is noncanonical"
            );
            count
        };
        ensure!(
            count <= 1_u64 << pool::NOTE_DEPTH,
            "pool hint exceeds note tree"
        );
        let at = if direct { 9 } else { 3 };
        Ok(Self {
            notes: field(0)?,
            spent: field(1)?,
            count,
            nullifiers: [field(at)?, field(at + 1)?],
            outputs: [field(at + 2)?, field(at + 3)?],
        })
    }
    pub(super) fn apply(&self, index: &PoolIndex, limit: u64) -> Result<PoolIndex> {
        ensure!(
            self.count <= limit,
            "public pool index note budget exhausted"
        );
        index.apply(
            [
                pool::decode_field(&self.nullifiers[0])?,
                pool::decode_field(&self.nullifiers[1])?,
            ],
            [
                pool::decode_field(&self.outputs[0])?,
                pool::decode_field(&self.outputs[1])?,
            ],
            (
                pool::decode_field(&self.notes)?,
                pool::decode_field(&self.spent)?,
                self.count,
            ),
        )
    }
}
fn events(raw: &[u8], circle: &str) -> Result<Vec<Delta>> {
    ensure!(
        raw.len() <= 1_048_576,
        "pool receipt hint exceeds byte budget"
    );
    let value: Value = serde_json::from_slice(raw)?;
    let events = value["events"]
        .as_array()
        .context("pool receipt events missing")?;
    ensure!(events.len() <= 4096, "pool receipt event budget exhausted");
    let mut result = Vec::new();
    for event in events {
        if event["contract"] == circle && event["event"] == "ShieldedTransition" {
            result.push(Delta::values(
                event["values"]
                    .as_array()
                    .context("pool event fields missing")?,
                false,
            )?);
        }
    }
    Ok(result)
}

pub(super) async fn read(source: &Pool, execution: &super::super::Execution) -> Result<Vec<Delta>> {
    let mut result = Vec::new();
    // Canonical successful transaction order also determines nested event order.
    for raw in &execution.record.txs_json {
        let tx = Transaction::from_document(&Document::parse(raw)?)?;
        if tx.to == source.address
            && tx.op_type == OpType::CircleCall
            && tx.encrypted_data.as_deref() == Some(b"exchange")
        {
            let values: Value =
                serde_json::from_slice(tx.message.as_deref().context("pool call data missing")?)?;
            result.push(Delta::values(
                values
                    .as_array()
                    .context("pool call data is not an array")?,
                true,
            )?);
        } else {
            let hash = hex::encode(tx.hash()?);
            let (head, archived) = source
                .directory
                .history
                .transaction(execution.after.head(), hash.as_bytes(), 16_777_216)
                .await?
                .context("pool execution hint transaction is unavailable")?;
            ensure!(
                head == *execution.after.head()
                    && Transaction::from_document(&Document::parse(&archived.transaction)?)? == tx,
                "pool hint archive transaction differs"
            );
            if let Some(receipt) = archived.receipt {
                result.extend(events(&receipt, source.circle())?);
            }
        }
        ensure!(result.len() <= 4096, "pool epoch hint budget exhausted");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forged_nullifiers_outputs_or_counts_cannot_reconstruct_the_tree() {
        let domain =
            pool::Domain::new(&[1; 32], b"oct11111111111111111111111111111111111111111111")
                .unwrap();
        let key = pool::SpendKey::random();
        let note = pool::Note::new(key.owner(domain), 1, &[2; 32]).unwrap();
        let empty = PoolIndex::default();
        let (circuit, next) = empty.prepare(domain, &[], &[note], 1, 0, [2; 32]).unwrap();
        let s = &circuit.statement;
        let delta = Delta {
            notes: pool::encode_field(s.new_notes),
            spent: pool::encode_field(s.new_spent),
            count: s.new_count,
            nullifiers: s.nullifiers.map(pool::encode_field),
            outputs: s.outputs.map(pool::encode_field),
        };
        assert_eq!(delta.apply(&empty, 10).unwrap().roots(), next.roots());
        let mut fake = delta.clone();
        fake.count += 1;
        assert!(fake.apply(&empty, 10).is_err());
        let mut fake = delta.clone();
        fake.nullifiers[0] = pool::encode_field(1.into());
        assert!(fake.apply(&empty, 10).is_err());
        let mut fake = delta;
        fake.outputs[0] = pool::encode_field(2.into());
        assert!(fake.apply(&empty, 10).is_err());
    }
    #[test]
    fn untrusted_event_shapes_are_bounded_and_filtered() {
        let raw=serde_json::to_vec(&serde_json::json!({"events":[{"contract":"other","event":"ShieldedTransition","values":null}]})).unwrap();
        assert!(events(&raw, "ours").unwrap().is_empty());
        assert!(events(b"{\"events\":[{\"contract\":\"ours\",\"event\":\"ShieldedTransition\",\"values\":[]}]}","ours").is_err());
        assert!(events(&vec![b' '; 1_048_577], "ours").is_err());
    }
}
