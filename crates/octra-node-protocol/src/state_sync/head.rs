// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Strict native HEAD record decoding before snapshot installation.
use super::{checkpoint, field, optional, require, text, Result};
use crate::{
    native_integer,
    native_json::{Document, Value},
};
pub const MAX_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq)]
pub struct Head {
    pub schema_version: i64,
    pub generation: i64,
    pub epoch_id: i64,
    pub state_root: Vec<u8>,
    pub ledger_state_root: Option<Vec<u8>>,
    pub irmin_commit: Option<Vec<u8>>,
    pub txid_hi: i64,
    pub txlog_seg: Option<i64>,
    pub txlog_off: Option<i64>,
    pub epochlog_off: Option<i64>,
    pub commit_id: Vec<u8>,
    pub ts: f64,
    pub quorum_cert_hash: Option<Vec<u8>>,
    pub epoch_index_hash: Option<Vec<u8>>,
    pub epoch_index_root: Option<Vec<u8>>,
}
fn integer(v: &Value) -> Result<i64> {
    match v {
        Value::Int(n) => Ok(n.get()),
        _ => Err("HEAD expected integer".into()),
    }
}
fn opt_int(v: &Value) -> Result<Option<i64>> {
    if matches!(v, Value::Null) {
        Ok(None)
    } else {
        integer(v).map(Some)
    }
}
impl Head {
    // Match the native integer-to-float projection and rounding exactly.
    #[allow(clippy::cast_precision_loss)]
    pub fn parse(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= MAX_BYTES, "HEAD exceeds size limit")?;
        let doc = Document::parse(raw).map_err(|e| super::Error::from(e.to_string()))?;
        let Value::Object(rows) = doc.root() else {
            return Err("HEAD is not an object".into());
        };
        let version = doc
            .field(doc.root(), b"schema_version")
            .map(integer)
            .transpose()?
            .unwrap_or(1);
        require((1..=3).contains(&version), "HEAD schema is unsupported")?;
        let base: Vec<&[u8]> = vec![
            b"generation",
            b"epoch_id",
            b"state_root",
            b"txid_hi",
            b"txlog_seg",
            b"txlog_off",
            b"epochlog_off",
            b"commit_id",
            b"ts",
        ];
        let has_version = doc.field(doc.root(), b"schema_version").is_some();
        let mut known = base.clone();
        if has_version {
            known.push(b"schema_version");
        }
        if version >= 2 {
            known.push(b"irmin_commit");
        }
        if version >= 3 {
            known.push(b"quorum_cert_hash");
        }
        let mut full = base;
        full.extend([
            b"schema_version".as_slice(),
            b"irmin_commit",
            b"quorum_cert_hash",
            b"ledger_state_root",
            b"epoch_index_hash",
            b"epoch_index_root",
        ]);
        let mut actual = rows.iter().map(|(k, _)| k.as_slice()).collect::<Vec<_>>();
        known.sort_unstable();
        full.sort_unstable();
        actual.sort_unstable();
        require(
            actual == known || (has_version && actual == full),
            "HEAD fields are missing, repeated or unknown",
        )?;
        let get = |key: &[u8]| field(&doc, doc.root(), key);
        let opt = |key: &[u8]| optional(doc.field(doc.root(), key).unwrap_or(&Value::Null));
        let txid = text(get(b"txid_hi")?)?;
        let ts = match get(b"ts")? {
            Value::Int(n) => n.get() as f64,
            Value::Float(n) => *n,
            _ => return Err("HEAD expected timestamp".into()),
        };
        let head = Self {
            schema_version: version,
            generation: integer(get(b"generation")?)?,
            epoch_id: integer(get(b"epoch_id")?)?,
            state_root: text(get(b"state_root")?)?,
            ledger_state_root: opt(b"ledger_state_root")?,
            irmin_commit: opt(b"irmin_commit")?,
            txid_hi: native_integer::parse_int64(&txid)
                .ok_or("HEAD invalid transaction high-water encoding")?,
            txlog_seg: opt_int(get(b"txlog_seg")?)?,
            txlog_off: opt_int(get(b"txlog_off")?)?,
            epochlog_off: opt_int(get(b"epochlog_off")?)?,
            commit_id: text(get(b"commit_id")?)?,
            ts,
            quorum_cert_hash: opt(b"quorum_cert_hash")?,
            epoch_index_hash: opt(b"epoch_index_hash")?,
            epoch_index_root: opt(b"epoch_index_root")?,
        };
        head.validate()?;
        Ok(head)
    }
    pub fn validate(&self) -> Result<()> {
        require(
            (1..=3).contains(&self.schema_version),
            "HEAD schema is unsupported",
        )?;
        require(self.generation >= 0, "HEAD generation is negative")?;
        require(self.epoch_id >= 0, "HEAD epoch is negative")?;
        require(self.txid_hi >= -1, "HEAD transaction high-water is invalid")?;
        require(!self.state_root.is_empty(), "HEAD state root is empty")?;
        require(!self.commit_id.is_empty(), "HEAD commit identity is empty")?;
        require(
            self.ts.is_finite() && self.ts >= 0.,
            "HEAD timestamp is invalid",
        )?;
        for (name, value) in [
            ("ledger root", &self.ledger_state_root),
            ("Irmin commit", &self.irmin_commit),
            ("quorum hash", &self.quorum_cert_hash),
            ("epoch hash", &self.epoch_index_hash),
            ("epoch root", &self.epoch_index_root),
        ] {
            require(
                value.as_ref().is_none_or(|v| !v.is_empty()),
                &format!("HEAD {name} is empty"),
            )?;
        }
        for (name, value) in [
            ("segment", self.txlog_seg),
            ("transaction offset", self.txlog_off),
            ("epoch offset", self.epochlog_off),
        ] {
            require(
                value.is_none_or(|v| v >= 0),
                &format!("HEAD {name} is negative"),
            )?;
        }
        require(
            self.txlog_seg.is_some() == self.txlog_off.is_some(),
            "HEAD transaction position is incomplete",
        )?;
        require(
            self.epoch_index_hash.is_some() == self.epoch_index_root.is_some(),
            "HEAD epoch commitment is incomplete",
        )
    }
    // These intentionally compare distinct native fields/length units.
    #[allow(clippy::suspicious_operation_groupings)]
    pub fn matches_checkpoint(&self, checkpoint: &checkpoint::Body) -> bool {
        self.epoch_id == checkpoint.epoch
            && self.state_root == checkpoint.state_root
            && self.ledger_state_root.as_ref().unwrap_or(&self.state_root)
                == &checkpoint.ledger_state_root
            && self.txid_hi == checkpoint.txid_hi
            && self.quorum_cert_hash == checkpoint.quorum_cert_hash
            && self.epoch_index_hash == checkpoint.epoch_index_hash
            && self.epoch_index_root == checkpoint.epoch_index_root
    }
}
