//! Native JSON field shapes; OCE1 hashes and signatures remain protocol-owned.
use anyhow::{ensure, Result};
use octra_node_protocol::{
    native_json::Document,
    state_sync::{checkpoint, manifest},
};
use serde_json::{json, Value};

fn string(value: &[u8]) -> Result<&str> {
    Ok(std::str::from_utf8(value)?)
}
fn optional(value: Option<&[u8]>) -> Result<Option<&str>> {
    value.map(string).transpose()
}
fn checkpoint(value: &checkpoint::Body) -> Result<Value> {
    Ok(json!({
        "chain_id":string(&value.chain_id)?, "epoch":value.epoch.to_string(),
        "state_root":string(&value.state_root)?, "ledger_state_root":string(&value.ledger_state_root)?,
        "txid_hi":value.txid_hi.to_string(), "config_hash":string(&value.config_hash)?,
        "validator_set_hash":string(&value.validator_set_hash)?,
        "quorum_cert_hash":optional(value.quorum_cert_hash.as_deref())?,
        "epoch_index_hash":optional(value.epoch_index_hash.as_deref())?,
        "epoch_index_root":optional(value.epoch_index_root.as_deref())?,
        "created_at":value.created_at.to_string(), "valid_until":value.valid_until.to_string()
    }))
}
fn manifest(value: &manifest::Body) -> Result<Value> {
    let files = value
        .files
        .iter()
        .map(|file| {
            let chunks = file
                .chunks
                .iter()
                .map(|chunk| {
                    Ok(json!({
                        "index":chunk.index,"offset":chunk.offset.to_string(),"size":chunk.size,
                        "sha256":string(&chunk.sha256)?
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(
                json!({"path":string(&file.path)?,"size":file.size.to_string(),
            "sha256":string(&file.sha256)?,"chunks":chunks}),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({"version":string(manifest::FORMAT)?,
        "checkpoint_hash":string(&value.checkpoint_hash)?,"snapshot_id":string(&value.snapshot_id)?,
        "irmin_commit":optional(value.irmin_commit.as_deref())?,"chunk_size":value.chunk_size,
        "total_size":value.total_size.to_string(),"file_count":value.file_count,
        "chunk_count":value.chunk_count,"chunks_root":string(&value.chunks_root)?,"files":files}))
}
fn draft_value(value: &manifest::Draft) -> Result<Value> {
    Ok(
        json!({"version":string(manifest::FORMAT)?,"checkpoint":checkpoint(&value.checkpoint)?,
        "checkpoint_hash":string(&value.checkpoint_hash)?,"manifest":manifest(&value.manifest)?,
        "manifest_hash":string(&value.manifest_hash)?}),
    )
}
pub(crate) fn draft(value: &manifest::Draft) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec_pretty(&draft_value(value)?)?;
    ensure!(
        parse_draft(&raw)? == *value,
        "native draft JSON round trip differs"
    );
    Ok(raw)
}
pub(crate) fn parse_draft(raw: &[u8]) -> Result<manifest::Draft> {
    ensure!(
        raw.len() <= manifest::MANIFEST_LIMIT,
        "draft exceeds size limit"
    );
    let document = Document::parse(raw)?;
    let value = manifest::Draft::parse(&document, document.root())?;
    value.verify()?;
    value.manifest.validate_reference()?;
    Ok(value)
}
pub(crate) fn signatures(raw: &[u8]) -> Result<Vec<checkpoint::Signature>> {
    let document = Document::parse(raw)?;
    let values = match document.root() {
        octra_node_protocol::native_json::Value::List(values) => values,
        value @ octra_node_protocol::native_json::Value::Object(_) => {
            return Ok(vec![checkpoint::Signature::parse(&document, value)?]);
        }
        _ => anyhow::bail!("signature file must contain a native signature object or array"),
    };
    ensure!(values.len() <= 1024, "signature count exceeds limit");
    values
        .iter()
        .map(|index| {
            Ok(checkpoint::Signature::parse(
                &document,
                document
                    .get(*index)
                    .ok_or_else(|| anyhow::anyhow!("signature value missing"))?,
            )?)
        })
        .collect()
}
pub(super) fn certificate(
    draft: &manifest::Draft,
    finality: &[u8],
    signatures: &[checkpoint::Signature],
) -> Result<Vec<u8>> {
    let mut value = draft_value(draft)?;
    let object = value.as_object_mut().expect("draft is object");
    object.insert("finality".into(), json!(string(finality)?));
    object.insert("exporter_signatures".into(),Value::Array(signatures.iter().map(|signature| {
        Ok(json!({"signer":string(&signature.signer)?,"signature":string(&signature.signature)?}))
    }).collect::<Result<Vec<_>>>()?));
    let raw = serde_json::to_vec_pretty(&value)?;
    let decoded = manifest::Certificate::parse(&raw)?;
    ensure!(
        decoded.draft == *draft && decoded.exporters == signatures,
        "native certificate JSON round trip differs"
    );
    Ok(raw)
}

/// Native legacy quorum certificate is an offline interchange, never a substitute
/// for finalized authority in the existing bootstrap/automatic publisher.
pub(super) fn quorum_certificate(
    draft: &manifest::Draft,
    signatures: &[checkpoint::Signature],
    exporter: &checkpoint::Signature,
) -> Result<Vec<u8>> {
    let mut value = draft_value(draft)?;
    let object = value.as_object_mut().expect("draft is object");
    let signature = |value: &checkpoint::Signature| -> Result<Value> {
        Ok(json!({"signer":string(&value.signer)?,"signature":string(&value.signature)?}))
    };
    object.insert(
        "checkpoint_signatures".into(),
        Value::Array(signatures.iter().map(signature).collect::<Result<_>>()?),
    );
    object.insert("exporter_signature".into(), signature(exporter)?);
    let raw = serde_json::to_vec_pretty(&value)?;
    let decoded = manifest::Certificate::parse(&raw)?;
    ensure!(
        decoded.draft == *draft && decoded.exporters == [exporter.clone()],
        "quorum certificate JSON differs"
    );
    Ok(raw)
}
