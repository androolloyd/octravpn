//! Only execution output belonging to the authenticated epoch may be retained.
use super::{invalid, ExecutedEpoch, Result};
use octra_node_protocol::transaction_outcome;
use std::collections::BTreeSet;

pub(super) fn validate(executed: &ExecutedEpoch) -> Result<()> {
    let mut hashes = executed
        .transactions
        .iter()
        .map(|tx| tx.hash.clone())
        .collect::<BTreeSet<_>>();
    let partition =
        transaction_outcome::split(&executed.consensus_receipts, false).map_err(invalid)?;
    for rejection in partition.rejections {
        hashes.insert(hex::encode(rejection.tx.hash().map_err(invalid)?));
    }
    for hash in executed.vm_receipts.keys() {
        if !hashes.contains(hash) {
            return Err(invalid(
                "VM receipt has no transaction in the authenticated epoch",
            ));
        }
    }
    for tx in &executed.transactions {
        if let (Some(archived), Some(recorded)) = (&tx.receipt, executed.vm_receipts.get(&tx.hash))
        {
            if archived != recorded {
                return Err(invalid(
                    "VM receipt differs from confirmed transaction archive",
                ));
            }
        }
    }
    Ok(())
}
