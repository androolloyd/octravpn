use crate::{Host, Node};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::state_sync::readiness::{Marker, MAX_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
static READERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// A retained, launch-signed observation. It never grants membership or replaces
/// the snapshot/QC authority checks performed when opening canonical history.
pub async fn read_verified<A: Host>(
    data: &Path,
    node: &Node<A>,
    public_key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let path = data.join("ready_to_vote.json");
    let permit = READERS
        .try_acquire()
        .context("readiness file readers are busy")?;
    let Some(raw) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            );
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= MAX_BYTES as u64,
            "readiness marker is not a bounded regular file"
        );
        let mut raw = Vec::new();
        file.take(MAX_BYTES as u64 + 1).read_to_end(&mut raw)?;
        Ok::<_, anyhow::Error>(Some(raw))
    })
    .await??
    else {
        return Ok(None);
    };
    let marker = Marker::parse(&raw)?;
    let address = octra_node_protocol::transaction::address_from_public_key(
        STANDARD.encode(public_key).as_bytes(),
    );
    let epoch = marker.verify(node.store.chain().chain_id.as_bytes(), &address, public_key)?;
    let captured = node.head().await?;
    ensure!(
        epoch as u64 <= captured.cursor.epoch.0,
        "readiness marker is ahead of canonical history"
    );
    let Some(head) = node.store.reader().head_for_epoch_opt(epoch as u64).await? else {
        return Ok(None);
    };
    ensure!(
        marker.state_root == hex::encode(head.cursor.state_root.0),
        "readiness marker root differs from retained history"
    );
    // A later callback cannot cause an older captured request to attest a new
    // marker. The durable retained record above remains the only bound epoch.
    Ok(Some(raw))
}

pub(super) async fn write<A: Host>(
    data: &Path,
    node: &Node<A>,
    key: &SigningKey,
    source: &str,
    voting: bool,
    records: i64,
) -> Result<()> {
    ensure!(records > 0, "cannot attest a join that imported no records");
    let head = node.head().await?;
    let epoch = i64::try_from(head.cursor.epoch.0)?;
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address = String::from_utf8(octra_node_protocol::transaction::address_from_public_key(
        public.as_bytes(),
    ))?;
    let chain = node.store.chain().chain_id.clone();
    let root = hex::encode(head.cursor.state_root.0);
    let payload = Marker::payload(&chain, &address, epoch, &root, records);
    let marker = Marker {
        version: "octra-observer-ready".into(),
        status: "observer_ready".into(),
        consensus_role: if voting { "validator" } else { "observer" }.into(),
        leader_rpc: source.into(),
        chain_id: chain,
        validator: address,
        validator_pubkey: public,
        ready_epoch: epoch.to_string(),
        state_root: root,
        catchup_records_verified: records,
        signature: STANDARD.encode(key.sign(payload.as_bytes()).to_bytes()),
        sign_payload: payload,
        generated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64(),
    };
    marker.verify(
        node.store.chain().chain_id.as_bytes(),
        marker.validator.as_bytes(),
        key.verifying_key().as_bytes(),
    )?;
    let mut raw = serde_json::to_vec_pretty(&marker)?;
    raw.push(b'\n');
    ensure!(
        raw.len() <= MAX_BYTES,
        "readiness marker exceeds byte limit"
    );
    let data = data.to_path_buf();
    tokio::task::spawn_blocking(move || {
        fs::create_dir_all(&data)?;
        let mut staged = tempfile::NamedTempFile::new_in(&data)?;
        staged.write_all(&raw)?;
        staged.as_file().sync_all()?;
        staged
            .persist(data.join("ready_to_vote.json"))
            .context("publish readiness marker")?;
        File::open(&data)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
