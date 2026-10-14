// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native pending-precommit WAL records, owned by the validator journal lock.
use super::{journal_io as io, Bytes, Error};
use crate::{
    native_integer,
    native_json::{Document, Value},
    transaction::{json_optional, json_string, native_float},
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub const MAX_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq)]
pub struct PendingCommit {
    pub epoch_id: i64,
    pub round: i64,
    pub proposal_id: Bytes,
    pub proposed_state_root: Bytes,
    pub txid_hi: i64,
    pub ts: f64,
    pub validator_addr: Bytes,
    pub proposal_b64: Option<Bytes>,
    pub vote_b64: Option<Bytes>,
    pub tx_hashes: Vec<Bytes>,
    pub txs_json: Vec<Bytes>,
    pub receipts_json: Vec<Bytes>,
}
impl PendingCommit {
    /// Native idempotency ignores the local write timestamp.
    pub fn same(&self, other: &Self) -> bool {
        self.epoch_id == other.epoch_id
            && self.round == other.round
            && self.proposal_id == other.proposal_id
            && self.proposed_state_root == other.proposed_state_root
            && self.txid_hi == other.txid_hi
            && self.validator_addr == other.validator_addr
            && self.proposal_b64 == other.proposal_b64
            && self.vote_b64 == other.vote_b64
            && self.tx_hashes == other.tx_hashes
            && self.txs_json == other.txs_json
            && self.receipts_json == other.receipts_json
    }
    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut out =
            format!("{{\"epoch_id\":{},\"round\":{}", self.epoch_id, self.round).into_bytes();
        for (name, value) in [
            (b"proposal_id".as_slice(), self.proposal_id.as_slice()),
            (b"proposed_state_root", &self.proposed_state_root),
        ] {
            field(&mut out, name);
            json_string(&mut out, value);
        }
        field(&mut out, b"txid_hi");
        json_string(&mut out, self.txid_hi.to_string().as_bytes());
        field(&mut out, b"ts");
        let time =
            native_float(self.ts).map_err(|e| Error::from(format!("invalid native JSON: {e}")))?;
        out.extend_from_slice(time.as_bytes());
        field(&mut out, b"validator_addr");
        json_string(&mut out, &self.validator_addr);
        field(&mut out, b"proposal_b64");
        json_optional(&mut out, self.proposal_b64.as_deref());
        field(&mut out, b"vote_b64");
        json_optional(&mut out, self.vote_b64.as_deref());
        for (name, values) in [
            (b"tx_hashes".as_slice(), &self.tx_hashes),
            (b"txs_json", &self.txs_json),
            (b"receipts_json", &self.receipts_json),
        ] {
            field(&mut out, name);
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                json_string(&mut out, value);
            }
            out.push(b']');
        }
        out.push(b'}');
        Ok(out)
    }
    #[allow(clippy::cast_precision_loss)] // Native Yojson.to_number uses float_of_int.
    pub fn decode(wire: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(wire).map_err(|e| Error::from(e.to_string()))?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err("pending commit JSON object required".into());
        }
        let field = |name: &str| {
            doc.field(doc.root(), name.as_bytes())
                .unwrap_or(&Value::Null)
        };
        let text = |name: &str| match field(name) {
            Value::String(v) => Ok(v.clone()),
            _ => Err(Error::from(format!("pending commit text required: {name}"))),
        };
        let int = |name: &str| match field(name) {
            Value::Int(v) => Ok(v.get()),
            _ => Err(Error::from(format!(
                "pending commit integer required: {name}"
            ))),
        };
        let optional = |name: &str| match field(name) {
            Value::String(v) => Ok(Some(v.clone())),
            Value::Null => Ok(None),
            _ => Err(Error::from(format!(
                "pending commit field is invalid: {name}"
            ))),
        };
        let list = |name: &str| match field(name) {
            Value::Null => Ok(vec![]),
            Value::List(ids) => ids
                .iter()
                .map(|id| match doc.get(*id).expect("JSON child") {
                    Value::String(v) => Ok(v.clone()),
                    _ => Err(Error::from("pending commit list text required")),
                })
                .collect(),
            _ => Err(Error::from(format!(
                "pending commit field is invalid: {name}"
            ))),
        };
        // OCaml record expressions evaluate fields in reverse source order.
        let receipts_json = list("receipts_json")?;
        let txs_json = list("txs_json")?;
        let tx_hashes = list("tx_hashes")?;
        let vote_b64 = optional("vote_b64")?;
        let proposal_b64 = optional("proposal_b64")?;
        let validator_addr = text("validator_addr")?;
        let ts = match field("ts") {
            Value::Float(v) => *v,
            Value::Int(v) => v.get() as f64,
            _ => return Err("pending commit number required: ts".into()),
        };
        let txid_hi = native_integer::parse_int64(&text("txid_hi")?)
            .ok_or("pending commit txid is invalid")?;
        let proposed_state_root = text("proposed_state_root")?;
        let proposal_id = text("proposal_id")?;
        let round = int("round")?;
        let epoch_id = int("epoch_id")?;
        Ok(Self {
            epoch_id,
            round,
            proposal_id,
            proposed_state_root,
            txid_hi,
            ts,
            validator_addr,
            proposal_b64,
            vote_b64,
            tx_hashes,
            txs_json,
            receipts_json,
        })
    }
}
fn field(out: &mut Bytes, name: &[u8]) {
    out.push(b',');
    json_string(out, name);
    out.push(b':');
}
pub fn name(epoch: i64, round: i64) -> String {
    format!("{epoch:010}_{round:04}.pending")
}
pub(super) struct PendingLog {
    data_dir: PathBuf,
    root: PathBuf,
}
impl PendingLog {
    pub(super) fn disk(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_owned(),
            root: data_dir.join("wal"),
        }
    }
    fn exists(&self) -> Result<bool, Error> {
        match fs::symlink_metadata(&self.root) {
            Ok(m) if m.is_dir() => Ok(true),
            Ok(_) => Err("WAL directory is not a directory".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io::io_error(e)),
        }
    }
    pub(super) fn keep(&self, record: &PendingCommit) -> Result<(), Error> {
        if !self.exists()? {
            io::directory(&self.root, "WAL")?;
        }
        io::sync_directory(&self.data_dir)?;
        let path = self.root.join(name(record.epoch_id, record.round));
        if path.exists() {
            let prior = read(&path)?;
            if !prior.same(record) {
                return Err("conflicting pending commit record".into());
            }
            File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(io::io_error)?;
        } else {
            let wire = record.encode()?;
            if wire.len() as u64 > MAX_BYTES {
                return Err("pending commit exceeds size limit".into());
            }
            let mut staged = path.as_os_str().to_owned();
            staged.push(".staged");
            let staged = PathBuf::from(staged);
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
            let mut file = options.open(&staged).map_err(io::io_error)?;
            file.write_all(&wire)
                .and_then(|()| file.sync_all())
                .map_err(io::io_error)?;
            drop(file);
            fs::rename(staged, path).map_err(io::io_error)?;
        }
        io::sync_directory(&self.root)
    }
    pub(super) fn read(&self) -> Result<Vec<PendingCommit>, Error> {
        if !self.exists()? {
            return Ok(vec![]);
        }
        let mut records = io::names(&self.root, ".pending")?
            .iter()
            .map(|p| read(p))
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|p| (p.epoch_id, p.round));
        Ok(records)
    }
    pub(super) fn delete(&self, epoch: i64, round: i64) -> Result<(), Error> {
        self.unlink(&self.root.join(name(epoch, round)))
    }
    pub(super) fn delete_epoch(&self, epoch: i64) -> Result<(), Error> {
        if self.exists()? {
            let prefix = format!("{epoch:010}_");
            for path in io::names(&self.root, ".pending")? {
                if path
                    .file_name()
                    .expect("journal entry")
                    .as_encoded_bytes()
                    .starts_with(prefix.as_bytes())
                {
                    self.unlink(&path)?;
                }
            }
        }
        Ok(())
    }
    fn unlink(&self, path: &Path) -> Result<(), Error> {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(io::io_error(e)),
        }
        io::sync_directory(&self.root)
    }
}
fn read(path: &Path) -> Result<PendingCommit, Error> {
    let record = PendingCommit::decode(&io::regular(path, MAX_BYTES, "pending commit")?)?;
    if record.epoch_id < 0
        || record.round < 0
        || path.file_name().expect("journal entry").as_encoded_bytes()
            != name(record.epoch_id, record.round).as_bytes()
    {
        return Err("pending commit position differs from filename".into());
    }
    Ok(record)
}
