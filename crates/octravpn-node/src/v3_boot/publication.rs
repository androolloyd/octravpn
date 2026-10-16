//! Public discovery snapshots are immutable and readable before anchoring.
use super::{anyhow, sha256_hex, ChainCtxV3, OperatorPolicy, Result, StateRoot};
use crate::circle_update::{fetch_circle_asset_plain, min_fee_for_sealed_put, parse_fee_floor};
use octravpn_core::v3_state_root::snapshot_path;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn read(ctx: &ChainCtxV3, circle: &str, hash: &str, logical: &str) -> Result<Vec<u8>> {
    let path = snapshot_path(hash, logical)?;
    match fetch_circle_asset_plain(ctx, circle, &path).await? {
        Some(bytes) => Ok(bytes),
        None => fetch_circle_asset_plain(ctx, circle, logical)
            .await?
            .ok_or_else(|| anyhow!("operator snapshot {logical} is unavailable")),
    }
}

pub(crate) async fn load(
    ctx: &ChainCtxV3,
    circle: &str,
    anchor: &str,
) -> Result<(OperatorPolicy, StateRoot)> {
    let root = StateRoot::decode_lenient(&read(ctx, circle, anchor, "/state-root.json").await?)?;
    anyhow::ensure!(
        root.circle_id == circle && root.anchor_hex()? == anchor,
        "operator snapshot anchor differs"
    );
    let policy = OperatorPolicy::decode_lenient(
        &read(ctx, circle, &root.policy_hash, "/policy.json").await?,
    )?;
    anyhow::ensure!(
        policy.hash_hex()? == root.policy_hash,
        "operator policy hash differs"
    );
    Ok((policy, root))
}
pub(super) async fn inherit(
    ctx: &ChainCtxV3,
    circle: &str,
    anchor: &str,
    policy: &mut OperatorPolicy,
    root: &mut StateRoot,
) -> Result<()> {
    let (prior_policy, prior) = load(ctx, circle, anchor).await?;
    // Retain unrelated future extension fields. Epoch/time describe a policy
    // revision; merely restarting the daemon must not manufacture a revision.
    for (key, value) in &prior_policy.unknown {
        policy
            .unknown
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    let epoch = policy.effective_epoch;
    let timestamp = policy.timestamp_secs;
    policy.effective_epoch = prior_policy.effective_epoch;
    policy.timestamp_secs = prior_policy.timestamp_secs;
    if *policy == prior_policy {
        anyhow::ensure!(
            prior.wg_pubkey_hash == root.wg_pubkey_hash,
            "operator WG commitment differs"
        );
        *root = prior;
    } else {
        policy.effective_epoch = epoch;
        policy.timestamp_secs = timestamp;
        let mut next = prior;
        next.policy_hash = policy.hash_hex()?;
        next.wg_pubkey_hash.clone_from(&root.wg_pubkey_hash);
        next.region.clone_from(&policy.region);
        next.epoch = epoch;
        next.timestamp_secs = timestamp;
        *root = next;
    }
    root.validate()?;
    Ok(())
}

pub(crate) async fn publish(
    ctx: &ChainCtxV3,
    circle: &str,
    policy: &OperatorPolicy,
    root: &StateRoot,
) -> Result<()> {
    let policy_bytes = policy.canonical_bytes()?;
    anyhow::ensure!(
        sha256_hex(&policy_bytes) == root.policy_hash,
        "operator policy publication hash differs"
    );
    let _ = put(
        ctx,
        circle,
        &snapshot_path(&root.policy_hash, "/policy.json")?,
        &policy_bytes,
    )
    .await?;
    let root_bytes = root.canonical_bytes()?;
    let _ = put(
        ctx,
        circle,
        &snapshot_path(&root.anchor_hex()?, "/state-root.json")?,
        &root_bytes,
    )
    .await?;
    Ok(())
}

pub(crate) async fn put(
    ctx: &ChainCtxV3,
    circle: &str,
    path: &str,
    bytes: &[u8],
) -> Result<Option<String>> {
    if let Some(current) = fetch_circle_asset_plain(ctx, circle, path).await? {
        anyhow::ensure!(current == bytes, "immutable operator snapshot was replaced");
        return Ok(None);
    }
    let fee = ctx
        .fee("circle_asset_put")
        .await?
        .max(min_fee_for_sealed_put(bytes.len()));
    let mut transaction = json!({
        "from": ctx.wallet_addr.display(), "to_": circle, "amount":"0", "nonce":0,
        "ou":fee.to_string(), "timestamp":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
        "op_type":"circle_asset_put", "encrypted_data":octravpn_core::b64::encode(bytes),
        "message":json!({"path":path,"content_type":"application/json","encoding":"identity"}).to_string(),
    });
    let hash = match ctx.submit_call(transaction.clone()).await {
        Ok(hash) => hash,
        Err(error) => {
            let floor = parse_fee_floor(&error.to_string())
                .filter(|floor| *floor > fee)
                .ok_or(error)?;
            transaction["ou"] = json!(floor.to_string());
            ctx.submit_call(transaction).await?
        }
    };
    // A submitted transaction hash is not publication evidence. The exact
    // immutable bytes must be visible through a committed Circle read first.
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if let Some(current) = fetch_circle_asset_plain(ctx, circle, path).await? {
                anyhow::ensure!(current == bytes, "operator snapshot readback differs");
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("operator snapshot publication timeout: {hash}"))??;
    Ok(Some(hash))
}

pub(crate) async fn await_anchor(ctx: &ChainCtxV3, circle: &str, anchor: &str) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if ctx.get_circle_state_root(circle).await?.as_deref() == Some(anchor)
                && ctx.get_circle_active(circle).await?
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| anyhow!("operator registration/anchor confirmation timeout"))??;
    Ok(())
}

#[cfg(test)]
mod tests;
