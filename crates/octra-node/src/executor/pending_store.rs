//! Local queue write-ahead journal. Frames are atomic recovery units; only an
//! incomplete final frame may be truncated. Hash or chain conflicts fail closed.
//! Saved transactions are candidates for fresh admission, never trusted proofs.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::{ChainIdentity, Cursor};
use octra_node_protocol::{
    native_integer::parse_integer,
    native_json::{Document, Value},
    transaction::{json_string, native_float, Nonce, OpType, Transaction},
};
use octra_node_runtime::{
    canonical::CanonicalStore,
    staging::{DropReason, DropRecord, Pool, PreviewState, MAX_DROPS, MAX_TRANSACTIONS},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
const MAX_FRAME: u64 = 128 * 1024 * 1024;
const MAX_FILE: u64 = 512 * 1024 * 1024;
const MAGIC: &[u8] = b"octra-pending-v1\n";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    pub raw: String,
    pub added_at: f64,
}
impl Saved {
    pub(super) fn transaction(&self) -> Result<Transaction> {
        ensure!(
            self.added_at.is_finite() && self.added_at >= 0.,
            "invalid queue timestamp"
        );
        Ok(Transaction::from_document(&Document::parse(
            &STANDARD.decode(&self.raw)?,
        )?)?)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    chain: ChainIdentity,
    anchor: Cursor,
    base: Cursor,
    #[serde(default)]
    drop_history: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    cursor: Cursor,
    upsert: Vec<Saved>,
    remove: Vec<String>,
    preview: PreviewState,
    #[serde(default)]
    drop_upsert: Vec<SavedDrop>,
    #[serde(default)]
    drop_remove: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedDrop {
    raw: String,
}
impl SavedDrop {
    fn encode(row: &DropRecord) -> Result<Self> {
        let mut raw = vec![b'['];
        for (index, value) in [row.hash.as_slice(), row.from.as_slice(), row.to.as_slice()]
            .into_iter()
            .enumerate()
        {
            if index != 0 {
                raw.push(b',');
            }
            json_string(&mut raw, value);
        }
        raw.extend_from_slice(format!(",{},", row.nonce.get()).as_bytes());
        json_string(&mut raw, row.ou.to_string().as_bytes());
        raw.push(b',');
        json_string(&mut raw, row.operation.as_str().as_bytes());
        raw.push(b',');
        json_string(
            &mut raw,
            match row.reason {
                DropReason::Evicted => b"evicted",
                DropReason::Expired => b"expired",
            },
        );
        raw.push(b',');
        json_string(&mut raw, row.detail.as_bytes());
        raw.push(b',');
        raw.extend_from_slice(native_float(row.timestamp)?.as_bytes());
        raw.push(b']');
        let saved = Self {
            raw: STANDARD.encode(raw),
        };
        saved.record()?;
        Ok(saved)
    }
    fn record(&self) -> Result<DropRecord> {
        ensure!(
            self.raw.len() <= 65_536_usize.div_ceil(3) * 4,
            "local drop record exceeds size limit"
        );
        let raw = STANDARD.decode(&self.raw)?;
        ensure!(raw.len() <= 65_536, "local drop record exceeds size limit");
        let doc = Document::parse(&raw)?;
        let Value::List(values) = doc.root() else {
            anyhow::bail!("invalid local drop encoding")
        };
        ensure!(values.len() == 9, "invalid local drop encoding");
        let text = |index: usize| -> Result<Vec<u8>> {
            match doc.get(values[index]) {
                Some(Value::String(value)) => Ok(value.clone()),
                _ => anyhow::bail!("invalid local drop encoding"),
            }
        };
        let hash = text(0)?;
        let from = text(1)?;
        let to = text(2)?;
        let nonce = match doc.get(values[3]) {
            Some(Value::Int(value)) => *value,
            _ => anyhow::bail!("invalid local drop nonce"),
        };
        let ou = parse_integer(&text(4)?).context("invalid local drop fee")?;
        let operation = OpType::parse(&text(5)?)?;
        let reason = match text(6)?.as_slice() {
            b"evicted" => DropReason::Evicted,
            b"expired" => DropReason::Expired,
            _ => anyhow::bail!("invalid local drop reason"),
        };
        let detail = text(7)?;
        let timestamp = match doc.get(values[8]) {
            Some(Value::Float(value)) => *value,
            _ => anyhow::bail!("invalid local drop timestamp"),
        };
        ensure!(
            hash.len() == 64
                && hash
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
                && from.len() <= 256
                && to.len() <= 256
                && nonce.get() >= 0
                && ou >= 0.into()
                && detail.len() <= 65_536
                && timestamp.is_finite()
                && timestamp >= 0.,
            "invalid local drop record"
        );
        Ok(DropRecord {
            hash,
            from,
            to,
            nonce: Nonce::new(nonce.get())?,
            ou,
            operation,
            reason,
            detail: String::from_utf8(detail)?,
            timestamp,
        })
    }
}
#[derive(Clone)]
pub(super) struct Recovery {
    pub cursor: Cursor,
    pub entries: BTreeMap<String, Arc<Saved>>,
    pub preview: PreviewState,
}
pub(super) struct Disk {
    path: PathBuf,
    file: File,
    header: Header,
    cursor: Cursor,
    entries: BTreeMap<String, Arc<Saved>>,
    preview: PreviewState,
    drops: BTreeMap<String, Arc<SavedDrop>>,
    frames: usize,
}
fn frame(file: &mut File, raw: &[u8]) -> Result<()> {
    ensure!(
        raw.len() as u64 <= MAX_FRAME,
        "queue journal frame exceeds limit"
    );
    file.write_all(&(raw.len() as u64).to_le_bytes())?;
    file.write_all(&Sha256::digest(raw))?;
    file.write_all(raw)?;
    Ok(())
}
fn read_frame(file: &mut File, end: u64) -> Result<Option<Vec<u8>>> {
    let at = file.stream_position()?;
    if end - at < 40 {
        return Ok(None);
    }
    let mut size = [0; 8];
    file.read_exact(&mut size)?;
    let size = u64::from_le_bytes(size);
    ensure!(size <= MAX_FRAME, "queue journal frame exceeds limit");
    if end - at - 40 < size {
        return Ok(None);
    }
    let mut expected = [0; 32];
    file.read_exact(&mut expected)?;
    let mut raw = vec![0; size as usize];
    file.read_exact(&mut raw)?;
    ensure!(
        Sha256::digest(&raw).as_slice() == expected,
        "queue journal checksum mismatch"
    );
    Ok(Some(raw))
}
#[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
fn open(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600).custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        );
        let file = options.open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0,
            "queue journal must be a private regular file"
        );
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = options;
        anyhow::bail!("queue journal requires Unix file permissions")
    }
}
impl Disk {
    /// The caller already owns the node's exclusive canonical-writer lock.
    pub(super) async fn load(path: PathBuf, store: &CanonicalStore) -> Result<(Self, Recovery)> {
        let chain = store.chain().clone();
        let anchor = store.anchor().cursor;
        let head = store.head().await?.cursor;
        let (disk, cursors) =
            tokio::task::spawn_blocking(move || Self::read(path, chain, anchor, head)).await??;
        for cursor in cursors {
            ensure!(
                cursor.sequence <= head.sequence,
                "queue journal is ahead of canonical history"
            );
            ensure!(
                store.retained_head(cursor.sequence).await?.cursor == cursor,
                "queue journal canonical cursor differs"
            );
        }
        let recovery = Recovery {
            cursor: disk.cursor,
            entries: disk.entries.clone(),
            preview: disk.preview.clone(),
        };
        Ok((disk, recovery))
    }
    fn read(
        path: PathBuf,
        chain: ChainIdentity,
        anchor: Cursor,
        head: Cursor,
    ) -> Result<(Self, Vec<Cursor>)> {
        let mut file = open(&path)?;
        let end = file.metadata()?.len();
        ensure!(end <= MAX_FILE, "queue journal exceeds byte limit");
        let header = if end == 0 {
            let header = Header {
                chain,
                anchor,
                base: head,
                drop_history: true,
            };
            file.write_all(MAGIC)?;
            frame(&mut file, &serde_json::to_vec(&header)?)?;
            file.sync_all()?;
            File::open(path.parent().context("queue path has no parent")?)?.sync_all()?;
            header
        } else {
            let mut magic = vec![0; MAGIC.len()];
            file.read_exact(&mut magic)?;
            ensure!(magic == MAGIC, "invalid queue journal version");
            let header: Header = serde_json::from_slice(
                &read_frame(&mut file, end)?.context("incomplete queue journal header")?,
            )?;
            ensure!(
                header.chain == chain && header.anchor == anchor,
                "queue journal chain or history floor differs"
            );
            header
        };
        let mut cursor = header.base;
        let mut cursors = vec![cursor];
        let mut entries = BTreeMap::new();
        let mut preview = Pool::default().preview_state();
        let mut drops = BTreeMap::new();
        let mut frames = 0;
        while file.stream_position()? < end {
            let at = file.stream_position()?;
            let Some(raw) = read_frame(&mut file, end)? else {
                file.set_len(at)?;
                file.seek(SeekFrom::Start(at))?;
                file.sync_all()?;
                break;
            };
            let change: Change = serde_json::from_slice(&raw)?;
            ensure!(
                change.cursor.sequence >= cursor.sequence && change.cursor.epoch >= cursor.epoch,
                "queue journal cursor moved backwards"
            );
            if change.cursor.sequence == cursor.sequence {
                ensure!(change.cursor == cursor, "conflicting queue journal cursor");
            } else {
                ensure!(
                    change.cursor.epoch > cursor.epoch,
                    "queue journal epoch did not advance"
                );
                cursors.push(change.cursor);
            }
            ensure!(
                change.upsert.len() <= MAX_TRANSACTIONS && change.remove.len() <= MAX_TRANSACTIONS,
                "queue journal change exceeds capacity"
            );
            ensure!(
                change.drop_upsert.len() <= MAX_DROPS && change.drop_remove.len() <= MAX_DROPS,
                "local drop change exceeds capacity"
            );
            for hash in change.drop_remove {
                drops.remove(&hash);
            }
            for saved in change.drop_upsert {
                let row = saved.record()?;
                drops.insert(String::from_utf8(row.hash)?, Arc::new(saved));
            }
            ensure!(
                drops.len() <= MAX_DROPS,
                "saved local drops exceed capacity"
            );
            for hash in change.remove {
                entries.remove(&hash);
            }
            for saved in change.upsert {
                let tx = saved.transaction()?;
                entries.insert(hex::encode(tx.hash()?), Arc::new(saved));
            }
            ensure!(
                entries.len() <= MAX_TRANSACTIONS,
                "saved queue exceeds capacity"
            );
            // Validate even metadata which will expire before recovery.
            Pool::default()
                .restore_preview(change.preview.clone(), -1)
                .map_err(anyhow::Error::msg)?;
            cursor = change.cursor;
            preview = change.preview;
            frames += 1;
        }
        file.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                path,
                file,
                header,
                cursor,
                entries,
                preview,
                drops,
                frames,
            },
            cursors,
        ))
    }
    pub(super) fn save(&mut self, pool: &Pool, cursor: Cursor) -> Result<()> {
        ensure!(
            cursor.sequence >= self.cursor.sequence,
            "queue publication precedes retained cursor"
        );
        ensure!(
            cursor.sequence == self.cursor.sequence || cursor.epoch > self.cursor.epoch,
            "queue publication epoch did not advance"
        );
        ensure!(
            cursor.sequence != self.cursor.sequence || cursor == self.cursor,
            "queue publication cursor differs"
        );
        let mut upsert = Vec::new();
        let mut retained = BTreeMap::new();
        for entry in pool.sample(MAX_TRANSACTIONS) {
            let hash = String::from_utf8(entry.hash.clone())?;
            let saved = if let Some(saved) = self
                .entries
                .get(&hash)
                .filter(|v| v.added_at.to_bits() == entry.added_at.to_bits())
            {
                saved.clone()
            } else {
                let saved = Saved {
                    raw: STANDARD.encode(entry.tx.to_json_bytes()?),
                    added_at: entry.added_at,
                };
                upsert.push(saved.clone());
                Arc::new(saved)
            };
            retained.insert(hash, saved);
        }
        let remove = self
            .entries
            .keys()
            .filter(|h| !retained.contains_key(*h))
            .cloned()
            .collect::<Vec<_>>();
        let preview = pool.preview_state();
        let mut drops = self.drops.clone();
        for row in pool.drops() {
            drops.insert(
                String::from_utf8(row.hash.clone())?,
                Arc::new(SavedDrop::encode(row)?),
            );
        }
        let mut ordered = drops
            .iter()
            .map(|(hash, saved)| saved.record().map(|row| (row.timestamp, hash.clone())))
            .collect::<Result<Vec<_>>>()?;
        ordered.sort_by(|left, right| {
            left.0
                .partial_cmp(&right.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(left.1.cmp(&right.1))
        });
        for (_, hash) in ordered
            .into_iter()
            .take(drops.len().saturating_sub(MAX_DROPS))
        {
            drops.remove(&hash);
        }
        let drop_upsert = drops
            .iter()
            .filter(|(hash, row)| self.drops.get(*hash) != Some(*row))
            .map(|(_, row)| row.as_ref().clone())
            .collect::<Vec<_>>();
        let drop_remove = self
            .drops
            .keys()
            .filter(|hash| !drops.contains_key(*hash))
            .cloned()
            .collect::<Vec<_>>();
        if cursor == self.cursor
            && upsert.is_empty()
            && remove.is_empty()
            && preview == self.preview
            && drop_upsert.is_empty()
            && drop_remove.is_empty()
        {
            return Ok(());
        }
        let change = Change {
            cursor,
            upsert,
            remove,
            preview: preview.clone(),
            drop_upsert,
            drop_remove,
        };
        let raw = serde_json::to_vec(&change)?;
        if self.frames >= 1024
            || raw.len() as u64 > MAX_FRAME
            || self.file.metadata()?.len() + raw.len() as u64 + 40 > MAX_FILE
        {
            self.compact(&retained, &preview, &drops, cursor)?;
        } else {
            frame(&mut self.file, &raw)?;
            self.file.sync_all()?;
            self.frames += 1;
        }
        self.entries = retained;
        self.preview = preview;
        self.drops = drops;
        self.cursor = cursor;
        Ok(())
    }
    fn compact(
        &mut self,
        entries: &BTreeMap<String, Arc<Saved>>,
        preview: &PreviewState,
        drops: &BTreeMap<String, Arc<SavedDrop>>,
        cursor: Cursor,
    ) -> Result<()> {
        let parent = self.path.parent().context("queue path has no parent")?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        let header = Header {
            chain: self.header.chain.clone(),
            anchor: self.header.anchor,
            base: cursor,
            drop_history: self.header.drop_history,
        };
        temp.write_all(MAGIC)?;
        frame(temp.as_file_mut(), &serde_json::to_vec(&header)?)?;
        // A bounded frame per transaction avoids serializing the entire queue.
        // Preview metadata is written once at the end.
        let empty = Pool::default().preview_state();
        for saved in entries.values() {
            frame(
                temp.as_file_mut(),
                &serde_json::to_vec(&Change {
                    cursor,
                    upsert: vec![saved.as_ref().clone()],
                    remove: vec![],
                    preview: empty.clone(),
                    drop_upsert: vec![],
                    drop_remove: vec![],
                })?,
            )?;
            ensure!(
                temp.as_file().metadata()?.len() <= MAX_FILE,
                "durable queue exceeds byte limit"
            );
        }
        for saved in drops.values() {
            frame(
                temp.as_file_mut(),
                &serde_json::to_vec(&Change {
                    cursor,
                    upsert: vec![],
                    remove: vec![],
                    preview: empty.clone(),
                    drop_upsert: vec![saved.as_ref().clone()],
                    drop_remove: vec![],
                })?,
            )?;
            ensure!(
                temp.as_file().metadata()?.len() <= MAX_FILE,
                "durable queue exceeds byte limit"
            );
        }
        frame(
            temp.as_file_mut(),
            &serde_json::to_vec(&Change {
                cursor,
                upsert: vec![],
                remove: vec![],
                preview: preview.clone(),
                drop_upsert: vec![],
                drop_remove: vec![],
            })?,
        )?;
        ensure!(
            temp.as_file().metadata()?.len() <= MAX_FILE,
            "durable queue exceeds byte limit"
        );
        temp.as_file().sync_all()?;
        self.file = temp.persist(&self.path).map_err(|e| e.error)?;
        File::open(parent)?.sync_all()?;
        self.header = header;
        self.frames = 0;
        Ok(())
    }
    pub(super) fn dropped(&self, hash: &[u8]) -> Result<Option<DropRecord>> {
        let hash = std::str::from_utf8(hash)?;
        if let Some(row) = self.drops.get(hash) {
            return row.record().map(Some);
        }
        ensure!(
            self.header.drop_history,
            "legacy local drop history unavailable"
        );
        Ok(None)
    }
    pub(super) fn drops(&self, address: &[u8]) -> Result<Vec<DropRecord>> {
        ensure!(
            self.header.drop_history,
            "legacy local drop history unavailable"
        );
        self.drops
            .values()
            .map(|saved| saved.record())
            .filter_map(|record| match record {
                Ok(row) if row.from == address || row.to == address => Some(Ok(row)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
}
