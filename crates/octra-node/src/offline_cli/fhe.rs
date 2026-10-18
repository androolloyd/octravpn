use anyhow::{ensure, Result};
use octra_node_protocol::{account_pack, state::valid_cipher};
use octra_node_runtime::{account_store, canonical::Head, state_batch::StateBatch};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) fn audit(head: &Head, state: &StateBatch) -> Result<i32> {
    let snapshot = state.snapshot();
    ensure!(
        snapshot.get(&[b"accounts"]).is_none(),
        "account root is not a directory"
    );
    println!(
        "event = audit state_root = {} commit = {} access = readonly classification = storage backend = canonical_sqlite",
        head.ledger_root, head.irmin_commit
    );
    let (mut accounts, mut rejected, mut clears, mut unsupported, mut review, mut bytes) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0u64);
    let mut kinds = BTreeMap::<&str, usize>::new();
    for address in snapshot.child_names(&[b"accounts"]) {
        accounts += 1;
        let id = digest(address);
        let root = hex::encode(
            snapshot
                .hash_at(&[b"accounts", address])?
                .expect("listed account subtree"),
        );
        let loaded = (|| -> Result<_> {
            let raw = state
                .get(&[b"accounts", address, b"data"])
                .ok_or_else(|| anyhow::anyhow!("account data is missing"))?;
            let layout = match account_pack::data(raw)? {
                account_pack::Data::Old(_) => "old",
                account_pack::Data::Parts(_, _) => "parts",
            };
            let account = account_store::load(state, address)?
                .ok_or_else(|| anyhow::anyhow!("account data is missing"))?;
            Ok((layout, digest(raw), account))
        })();
        let (layout, data_hash, account) = match loaded {
            Ok(value) => value,
            Err(error) => {
                // Account contents and addresses are never printed in diagnostics.
                let reason = serde_json::to_string(&error.to_string())?;
                println!(
                    "event = account account = {id} record_root = {root} status = rejected reason = {reason}"
                );
                rejected += 1;
                continue;
            }
        };
        let cipher = account.encrypted_balance.as_deref();
        let format = match cipher {
            None => "absent",
            Some(b"") => "empty_text",
            Some(b"0") => "zero_text",
            Some(value) if value.len() > 8 && value.starts_with(b"hfhe_v1|") => "hfhe_envelope",
            Some(_) => "other_text",
        };
        let clear = cipher == Some(b"0");
        let refuses = !clear && !valid_cipher(cipher);
        let size = cipher.map_or(0, <[u8]>::len);
        let hash = cipher.map_or_else(|| "none".to_owned(), digest);
        println!(
            "event = account account = {id} record_root = {root} data_hash = {data_hash} layout = {layout} format = {format} cipher_bytes = {size} cipher_hash = {hash} loader_clears = {clear} loader_refuses = {refuses}"
        );
        clears += usize::from(clear);
        unsupported += usize::from(refuses);
        review += usize::from(format == "other_text");
        bytes = bytes
            .checked_add(u64::try_from(size)?)
            .ok_or_else(|| anyhow::anyhow!("cipher byte total overflow"))?;
        *kinds.entry(format).or_default() += 1;
    }
    for (format, count) in kinds {
        println!("event = cipher_format format = {format} accounts = {count}");
    }
    let needs_review = rejected != 0 || clears != 0 || unsupported != 0 || review != 0;
    println!(
        "event = audit status = complete accounts = {accounts} rejected = {rejected} loader_clears = {clears} loader_refuses = {unsupported} cipher_bytes = {bytes} result = {}",
        if needs_review {
            "needs_review"
        } else {
            "storage_readable"
        }
    );
    Ok(if needs_review { 2 } else { 0 })
}
fn digest(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
