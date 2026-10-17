//! Native status and light proofs from captured canonical heads.
use super::{rpc, Arc, Context, Document, Fault, SystemTime, Value, UNIX_EPOCH};
use octra_node_protocol::{light_rpc::EpochProof, status_rpc};
use octra_node_runtime::canonical::Head;
fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
fn fault(reason: impl std::fmt::Display) -> Fault {
    Fault::new(-32000, reason.to_string().as_bytes())
}
fn service(
    host: &Context,
) -> std::result::Result<&octra_node_runtime::status_read::Service, Fault> {
    host.status
        .as_deref()
        .ok_or_else(|| unavailable("status signer unavailable"))
}

pub(super) async fn read(
    host: &Arc<Context>,
    method: &[u8],
    doc: &Document,
    params: &Value,
) -> std::result::Result<Vec<u8>, Fault> {
    if method == b"node_version" {
        return Ok(status_rpc::node_version());
    }
    if method == b"node_metrics" {
        return host.node.native_metrics().map_err(unavailable);
    }
    if method == b"node_stats" {
        return node_stats(host).await;
    }
    if method == b"octra_epochTags" {
        return epoch_tags(&host.node.reader()).await;
    }
    if method == b"octra_validatorViewPubkey" {
        return service(host)?.validator_view_pubkey();
    }
    if method == b"octra_consensusPeerStates" {
        return service(host)?.consensus_peer_states(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(unavailable)?
                .as_secs_f64(),
        );
    }
    if method == b"octra_roundWitness" {
        let validator = rpc::require_address(doc, params, 0, "validator")?;
        return service(host)?.round_witness(validator);
    }
    let head = host.node.head().await.map_err(unavailable)?;
    match method {
        b"node_status" => {
            let legacy = host.node.legacy_status_at(&head).map_err(unavailable)?;
            let state_root = hex::encode(head.cursor.state_root.0);
            let head = status_rpc::Head {
                epoch: head.cursor.epoch.0 as i64,
                state_root: state_root.as_bytes(),
                txid_hi: head.txid_hi,
                irmin_commit: Some(head.irmin_commit.as_bytes()),
            };
            status_rpc::node_status(
                legacy.epoch,
                &host.address,
                legacy.roots,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(unavailable)?
                    .as_secs_f64(),
                Some(&head),
            )
        }
        b"octra_signedRoot" => service(host)?.signed_root(&head).await,
        b"octra_validatorSetProof" => service(host)?.validator_set_proof(&head).await,
        b"octra_runtimeVersion" => service(host)?.runtime_version(&head).await,
        b"octra_accountProof" => {
            let address = rpc::require_address(doc, params, 0, "address")?;
            service(host)?
                .account_proof(&head, address, rpc::MAX_SINGLE)
                .await
        }
        b"octra_validatorEnrollment" => {
            let active = octra_node_protocol::rules::at(
                host.node.chain().chain_id.as_bytes(),
                octra_node_protocol::rules::Rule::ReadyExecution,
                head.cursor.epoch.0 as i64 + 1,
            ) == octra_node_protocol::transaction::RuleMode::Active;
            let proposal = if active {
                head_proposal_id(host, &head).await.ok()
            } else {
                None
            };
            service(host)?
                .enrollment(&head, proposal.as_ref().map(String::as_bytes))
                .await
        }
        b"octra_epochProof" => {
            let epoch = rpc::require_int(doc, params, 0, "epoch_id")?;
            Ok(epoch_proof(host, &head, epoch).await?.proof_json())
        }
        b"octra_txInclusionProof" => {
            let hash = rpc::require_hash(doc, params, 0, "hash")?;
            let Some((epoch, record)) = host
                .node
                .reader()
                .transaction(&head, hash, (i64::MAX - 1) as usize)
                .await
                .map_err(unavailable)?
            else {
                return Err(Fault::new(112, b"not found").string_data(b"transaction not found"));
            };
            let proof = epoch_proof(host, &head, epoch.cursor.epoch.0 as i64).await?;
            let index = proof
                .tx_hashes
                .iter()
                .position(|v| v == hash)
                .ok_or_else(|| fault("transaction not present in epoch proof"))?
                as i64;
            if !proof.tx_position_ok(hash, index).map_err(fault)? {
                return Err(fault("tx inclusion verification failed"));
            }
            let public = public_tx_data(&record.transaction)?;
            Ok(proof.tx_inclusion_json(hash, index, public))
        }
        _ => Err(Fault::missing(method)),
    }
}

async fn epoch_tags(
    reader: &octra_node_runtime::canonical::Reader,
) -> std::result::Result<Vec<u8>, Fault> {
    let tags = reader.epoch_tag_stats().await.map_err(unavailable)?;
    Ok(status_rpc::EpochTags {
        count: tags.count,
        min_epoch: tags.min_epoch,
        max_epoch: tags.max_epoch,
        keep_epochs: tags.keep_epochs,
        split_epoch: tags.split_epoch,
        gc_enabled: tags.gc_enabled,
        gc_running: tags.gc_running,
        gc_need: tags.gc_need,
    }
    .to_json())
}

async fn head_proposal_id(host: &Arc<Context>, head: &Head) -> std::result::Result<String, Fault> {
    let finality = host
        .finality
        .as_ref()
        .ok_or_else(|| unavailable("Single history has no BFT certificate"))?;
    let certificate = if head.cursor.sequence.0 == 0 {
        finality
            .checkpoint_parent()
            .ok_or_else(|| fault("committed head certificate is unavailable"))?
            .certificate
    } else {
        finality
            .record(head.cursor.sequence)
            .await
            .map_err(unavailable)?
            .finality
            .ok_or_else(|| fault("committed head certificate is unavailable"))?
            .finalize
            .certificate()
    };
    if certificate.epoch_id != head.cursor.epoch.0 as i64
        || certificate.chain_id != host.node.chain().chain_id.as_bytes()
        || certificate.header.proposed_state_root != head.cursor.state_root.0
        || certificate.proposal_id.len() != 32
    {
        return Err(fault("committed head certificate does not match head"));
    }
    Ok(hex::encode(certificate.proposal_id))
}
async fn node_stats(host: &Arc<Context>) -> std::result::Result<Vec<u8>, Fault> {
    use num_bigint::BigInt;
    use octra_node_protocol::{native_integer::parse_integer, state::MAX_SUPPLY};
    let view = host.node.snapshot().map_err(unavailable)?;
    let legacy = host
        .node
        .legacy_status_at(view.head())
        .map_err(unavailable)?;
    let epochs = (0..legacy.epoch.clamp(0, 10))
        .map(|i| legacy.epoch - 1 - i)
        .collect::<Vec<_>>();
    let reader = host.node.reader();
    let mut recent = 0i64;
    for epoch in &epochs {
        let retained = reader
            .head_for_epoch_opt(*epoch as u64)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("recent epoch history unavailable"))?;
        if retained.cursor.sequence.0 == 0 {
            if retained.cursor.epoch.0 != 0 || retained.txid_hi != -1 {
                return Err(unavailable("recent anchor transaction count unavailable"));
            }
        } else {
            let record = host.node.epoch_data(&retained).await.map_err(unavailable)?;
            recent = recent
                .checked_add(record.hashes.len() as i64)
                .ok_or_else(|| unavailable("recent transaction count exhausted"))?;
        }
    }
    let pending = host.pending.clone();
    let executor = host.executor.clone();
    let policy = host.executor.emission_policy();
    let fallback = if policy.emission_guard {
        policy.legacy_total.clone()
    } else {
        None
    };
    host.executor
        .read(move || {
            let summary = executor
                .account_summary(view.state())
                .map_err(unavailable)?;
            let total = view
                .state()
                .get(&[b"meta", b"total_supply"])
                .or(fallback.as_deref())
                .and_then(parse_integer)
                .ok_or_else(|| unavailable("total supply unavailable"))?;
            let maximum = BigInt::from(MAX_SUPPLY);
            if total < *summary.total_supply() || total > maximum {
                return Err(Fault::new(111, b"supply violation"));
            }
            let encrypted = &total - summary.total_supply();
            let staging = pending
                .inspect(octra_node_runtime::staging::Pool::len)
                .map_err(unavailable)? as i64;
            let root = hex::encode(view.head().cursor.state_root.0);
            let head = status_rpc::Head {
                epoch: view.head().cursor.epoch.0 as i64,
                state_root: root.as_bytes(),
                txid_hi: view.head().txid_hi,
                irmin_commit: Some(view.head().irmin_commit.as_bytes()),
            };
            status_rpc::stats::Stats {
                current_epoch: legacy.epoch,
                total_accounts: summary.accounts() as i64,
                active_accounts: summary.active_accounts() as i64,
                true_total: summary.total_supply(),
                encrypted: &encrypted,
                max_supply: &maximum,
                total_confirmed: view.head().txid_hi.wrapping_add(1).wrapping_shl(1) >> 1,
                staging,
                recent_tx_count: recent,
                latest_epochs: &epochs,
                head: Some(&head),
            }
            .to_json()
            .map_err(unavailable)
        })
        .await
}
async fn epoch_proof(
    host: &Arc<Context>,
    prefix: &Head,
    epoch: i64,
) -> std::result::Result<EpochProof, Fault> {
    let number = u64::try_from(epoch).map_err(|_| fault("epoch header not found"))?;
    if number > prefix.cursor.epoch.0 {
        return Err(fault("epoch header not found"));
    }
    let reader = host.node.reader();
    let head = reader
        .head_for_epoch_opt(number)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| fault("epoch header not found"))?;
    // A snapshot anchor cannot reconstruct a pre-snapshot transaction list.
    let previous = head
        .cursor
        .sequence
        .0
        .checked_sub(1)
        .ok_or_else(|| fault("previous epoch index root missing"))?;
    let parent = reader
        .head_at(octra_exex::Sequence(previous))
        .await
        .map_err(unavailable)?;
    let record = host.node.epoch_data(&head).await.map_err(unavailable)?;
    if record.hashes.len() > octra_node_protocol::consensus::codec::MAX_TXS {
        return Err(fault("invalid epoch tx count"));
    }
    let start = parent
        .txid_hi
        .checked_add(1)
        .ok_or_else(|| fault("epoch txid range overflow"))?;
    let proof = EpochProof {
        chain_id: host.node.chain().chain_id.as_bytes().to_vec(),
        epoch_id: epoch,
        tx_hashes: record
            .hashes
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .collect(),
        start_txid: start,
        tx_count: record.hashes.len() as i64,
        prev_epoch_index_root: parent.index_root.into_bytes(),
        epoch_index_root: head.index_root.into_bytes(),
    };
    if !proof.verify().map_err(fault)? {
        return Err(fault("epoch proof verification failed"));
    }
    Ok(proof)
}
// Native public_tx_data hides private Circle code even in inclusion proofs.
fn public_tx_data(raw: &[u8]) -> std::result::Result<Vec<u8>, Fault> {
    let doc = Document::parse(raw).map_err(unavailable)?;
    let Value::Object(fields) = doc.root() else {
        return Ok(b"null".to_vec());
    };
    let values = |key: &[u8]| {
        fields
            .iter()
            .filter(|(name, _)| name == key)
            .filter_map(|(_, id)| doc.get(*id))
            .collect::<Vec<_>>()
    };
    let ops = values(b"op_type");
    if !ops
        .iter()
        .any(|v| matches!(v,Value::String(v)if v==b"deploy_circle"||v==b"circle_program_update"))
    {
        return Ok(raw.to_vec());
    }
    let messages = values(b"message");
    let ([Value::String(op)], [Value::String(message)]) = (ops.as_slice(), messages.as_slice())
    else {
        return Ok(b"null".to_vec());
    };
    if op != b"deploy_circle" {
        return Ok(b"null".to_vec());
    }
    let decoded = if message.len() % 2 == 0 && message.iter().all(u8::is_ascii_hexdigit) {
        hex::decode(message).map_err(unavailable)?
    } else {
        message.clone()
    };
    let Ok(message) = Document::parse(&decoded) else {
        return Ok(b"null".to_vec());
    };
    let Value::Object(fields) = message.root() else {
        return Ok(b"null".to_vec());
    };
    let privacy = fields
        .iter()
        .filter(|(name, _)| name == b"privacy_class")
        .filter_map(|(_, id)| message.get(*id))
        .collect::<Vec<_>>();
    if matches!(privacy.as_slice(),[Value::String(v)]if v==b"public") {
        Ok(raw.to_vec())
    } else {
        Ok(b"null".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{ChainIdentity, StateRoot};
    use octra_node_protocol::epoch_index;
    use octra_node_runtime::{canonical::CanonicalStore, state_batch::StateBatch};

    #[tokio::test]
    async fn epoch_tag_rpc_reads_actual_backend_metadata_without_serving_admission() {
        // Native Status_read_rpc.epoch_tags reads Store_irmin directly rather
        // than requiring an admitted ledger snapshot or a signing capability.
        let source: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/rust-node/source-map.json"
        ))
        .unwrap();
        assert_eq!(
            source["upstream_commit"],
            "7f9be4489870645cfcc95439638cde40f5da9f50"
        );
        assert_eq!(
            source["files"]["node_runtime/status_read_rpc.ml"],
            "5a2a25826e21f88a6c827683ba677bf6534d2504734513a933908295120d5870"
        );
        assert_eq!(
            source["files"]["node_runtime/rpc_view.ml"],
            "18b1b175d1699f3e327915738c4ec997199558c1fbe43c032e6650ba7b1cfbbf"
        );
        let directory = tempfile::tempdir().unwrap();
        let state = StateBatch::default().snapshot();
        let (_, index) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap();
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index).as_bytes(),
        )
        .unwrap();
        let store = CanonicalStore::create(
            &directory.path().join("node.db"),
            ChainIdentity::genesis("rpc-epoch-tags", StateRoot(root)),
            state,
            0,
        )
        .await
        .unwrap();
        let reader = store.reader();
        let tags = reader.epoch_tag_stats().await.unwrap();
        let raw = epoch_tags(&reader).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            result,
            serde_json::json!({
                "count":tags.count,
                "min_epoch":tags.min_epoch,
                "max_epoch":tags.max_epoch,
                "keep_epochs":tags.keep_epochs,
                "split_epoch":tags.split_epoch,
                "pack_gc_enabled":tags.gc_enabled,
                "pack_gc_running":tags.gc_running,
                "pack_gc_need_bytes":tags.gc_need.map(|value|value.to_string()),
            })
        );
        // These values describe the actual SQLite archive: no synthetic Irmin
        // pack split or running collector is substituted for missing metadata.
        assert_eq!(result["pack_gc_enabled"], false);
        assert_eq!(result["pack_gc_running"], false);
        assert!(result["split_epoch"].is_null());
        assert!(result["pack_gc_need_bytes"].is_null());
    }
}
