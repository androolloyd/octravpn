//! State bindings checked before the epoch changes the ledger or object tree.
use crate::state_batch::Snapshot;
use num_bigint::BigInt;
use octra_node_protocol::{
    preverify_commit::{self, Error, Gate},
    preverify_receipt::{self, Binding},
    state::Ledger,
    transaction::{decode_base64, OpType, Transaction},
};
use sha2::{Digest, Sha256};

fn invalid(reason: impl Into<Vec<u8>>) -> Error {
    Error::Invalid(reason.into())
}
fn source_cipher(tx: &Transaction, ledger: &Ledger) -> Result<Vec<u8>, &'static str> {
    let cipher = match tx.op_type {
        OpType::CircleBalanceCellPut | OpType::CircleRegisterCellPut => {
            let encoded = tx
                .encrypted_data
                .as_deref()
                .ok_or("circle cell ciphertext is required")?;
            decode_base64(encoded)
                .ok()
                .filter(|raw| !raw.is_empty())
                .ok_or("circle cell ciphertext is invalid")?
        }
        _ => ledger
            .account(&tx.from)
            .ok_or("sender_missing")?
            .encrypted_balance
            .as_deref()
            .unwrap_or(b"0")
            .to_vec(),
    };
    Ok(hex::encode(Sha256::digest(cipher)).into_bytes())
}

/// `root` is the native committed HEAD tree hash (hex bytes, or `empty` before
/// genesis), not a speculative ledger hash. Static receipt admission runs first.
pub fn check(
    gate: &Gate,
    transactions: &[Transaction],
    crypto_active: bool,
    minimum: &BigInt,
    root: &[u8],
    ledger: &Ledger,
    state: &Snapshot,
) -> Result<(), Error> {
    gate.check(transactions, crypto_active, minimum)?;
    let root = preverify_receipt::state_hash(root);
    for tx in transactions
        .iter()
        .filter(|tx| preverify_commit::managed(tx))
    {
        let receipt = gate.receipt(tx)?;
        let mismatch = |tag: &[u8]| invalid([tag, b":", &receipt.tx_hash].concat());
        match &receipt.binding {
            Binding::Unbound => (),
            Binding::Circle(circle) => {
                if circle.snapshot_hash != root {
                    return Err(mismatch(b"receipt_state_mismatch"));
                }
            }
            Binding::Private(binding) => {
                if binding.pre_state_hash != root {
                    return Err(mismatch(b"receipt_state_mismatch"));
                }
                let unavailable =
                    |reason: &str| invalid(format!("receipt_state_unavailable:{reason}"));
                let cipher = source_cipher(tx, ledger).map_err(unavailable)?;
                let key = state
                    .get(&[b"pvac_hashes", &tx.from])
                    .filter(|raw| *raw != b"none")
                    .or_else(|| (tx.op_type == OpType::KeySwitch).then_some(&[b'0'; 64]));
                let key = key.ok_or_else(|| unavailable("pvac_key_not_consensus_bound"))?;
                if binding.source_cipher_hash != cipher || binding.pvac_key_hash != key {
                    return Err(mismatch(b"receipt_source_mismatch"));
                }
            }
        }
    }
    Ok(())
}
