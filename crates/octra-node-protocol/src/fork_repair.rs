// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native legacy repair records and finality completion. These types grant no
//! permission to rewind protected canonical history or bypass a backend lease.
mod head;
#[cfg(test)]
mod tests;

use crate::{
    native_integer,
    native_json::{Document, Value},
    transaction::json_string,
};
pub use crate::{oce1::Error, state_sync::head::Head};
pub use head::{encode_head, parse_head};
pub type Result<T> = std::result::Result<T, Error>;
pub const SCHEMA: i64 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub source: Head,
    pub target_root: Vec<u8>,
    pub next_txid: i64,
    pub head: Head,
}

impl Plan {
    /// Exact Fork_repair_log.of_json field selection. Unknown outer fields and
    /// repeated outer keys follow native first-key selection; HEAD stays strict.
    /// The caller bounds file I/O; the native record codec adds no size limit.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let document = Document::parse(raw).map_err(|error| Error::from(error.to_string()))?;
        let field = |name: &[u8]| {
            document
                .field(document.root(), name)
                .unwrap_or(&Value::Null)
        };
        if head::integer(field(b"schema"))? != SCHEMA {
            return Err("fork repair log schema mismatch".into());
        }
        let source = head::read(&document, field(b"source"))?;
        let target_root = head::text(field(b"target_root"))?;
        let next_txid = native_integer::parse_int64(&head::text(field(b"next_txid"))?)
            .ok_or("Failure(\"Int64.of_string\")")?;
        let head = head::read(&document, field(b"head"))?;
        let plan = Self {
            source,
            target_root,
            next_txid,
            head,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Exact native plan validation, without strengthening legacy field rules.
    /// File decoding separately validates both embedded native HEAD records.
    pub fn validate(&self) -> Result<()> {
        let head = &self.head;
        let target = head.epoch_id;
        let source = &self.source;
        let reason = if source.schema_version != 3 {
            Some("fork repair source HEAD schema mismatch")
        } else if source.generation != source.epoch_id {
            Some("fork repair source HEAD generation mismatch")
        } else if source.epoch_id <= target {
            Some("fork repair source is not ahead of target")
        } else if head.schema_version != 3 {
            Some("fork repair HEAD schema mismatch")
        } else if head.generation != target {
            Some("fork repair HEAD generation mismatch")
        } else if self.target_root.len() != 64
            || !self
                .target_root
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            Some("fork repair target root is invalid")
        } else if head.state_root != self.target_root {
            Some("fork repair HEAD root mismatch")
        } else if head.ledger_state_root.is_none() {
            Some("fork repair ledger root is missing")
        } else if head.irmin_commit.is_none() {
            Some("fork repair Irmin commit is missing")
        } else if head.txlog_seg.is_none() || head.txlog_off.is_none() {
            Some("fork repair txlog boundary is missing")
        } else if head.epochlog_off.is_none() {
            Some("fork repair epochlog boundary is missing")
        } else if head.epoch_index_hash.is_none() || head.epoch_index_root.is_none() {
            Some("fork repair epoch commitment is missing")
        } else if self.next_txid < 0 {
            Some("fork repair next txid is invalid")
        } else if head.txid_hi == i64::MAX || self.next_txid != head.txid_hi.wrapping_add(1) {
            Some("fork repair transaction boundary mismatch")
        } else {
            None
        };
        reason.map_or(Ok(()), |reason| Err(reason.into()))
    }

    /// Native compact JSON, without the filesystem writer's trailing newline.
    /// Persistence, atomic rename/fsync and exclusive ownership belong to host.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut raw = b"{\"schema\":1,\"source\":".to_vec();
        raw.extend_from_slice(&encode_head(&self.source)?);
        raw.extend_from_slice(b",\"target_root\":");
        json_string(&mut raw, &self.target_root);
        raw.extend_from_slice(b",\"next_txid\":");
        json_string(&mut raw, self.next_txid.to_string().as_bytes());
        raw.extend_from_slice(b",\"head\":");
        raw.extend_from_slice(&encode_head(&self.head)?);
        raw.push(b'}');
        Ok(raw)
    }

    /// Native source HEAD compatibility only. The host must independently
    /// recheck journal protection and the physical target binding before writes.
    pub fn accepts_source(&self, current: &Head) -> bool {
        same_source(current, &self.source) || *current == self.head
    }
}

/// Native equivalent rewrite deliberately ignores irmin_commit and commit_id.
#[allow(clippy::float_cmp)] // Exact native Float.equal, including NaN equality.
pub fn same_source(left: &Head, right: &Head) -> bool {
    left.schema_version == right.schema_version
        && left.generation == right.generation
        && left.epoch_id == right.epoch_id
        && left.state_root == right.state_root
        && left.ledger_state_root == right.ledger_state_root
        && left.txid_hi == right.txid_hi
        && left.txlog_seg == right.txlog_seg
        && left.txlog_off == right.txlog_off
        && left.epochlog_off == right.epochlog_off
        // Native Float.equal considers all NaNs equal; valid decoded HEADs are finite.
        && (left.ts == right.ts || left.ts.is_nan() && right.ts.is_nan())
        && left.quorum_cert_hash == right.quorum_cert_hash
        && left.epoch_index_hash == right.epoch_index_hash
        && left.epoch_index_root == right.epoch_index_root
}

/// A lease-owning native backend supplies complete finality records, including
/// any proof used by committed_for/rewind_journal. A root projection is not proof.
/// read_plan must decode and validate the durable record with Plan::parse.
pub trait Finality {
    type Entry;
    fn read_plan(&mut self) -> Result<Option<Plan>>;
    fn head(&mut self) -> Result<Option<Head>>;
    fn finality_at(&mut self, epoch: i64) -> Result<Option<Self::Entry>>;
    fn entry_root<'a>(&self, entry: &'a Self::Entry) -> &'a [u8];
    fn entry_txid_hi(&self, entry: &Self::Entry) -> i64;
    fn journal_committed(&mut self) -> Result<bool>;
    fn committed_for(&mut self, entry: &Self::Entry) -> Result<()>;
    fn rewind_journal(&mut self, entry: &Self::Entry) -> Result<()>;
    fn drop_after(&mut self, target: i64) -> Result<i64>;
    fn clear(&mut self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    Idle,
    Resumed {
        target: i64,
        head: i64,
        dropped: i64,
    },
}

fn head_matches<B: Finality>(backend: &B, head: &Head, entry: &B::Entry) -> bool {
    backend.entry_root(entry) == head.state_root && backend.entry_txid_hi(entry) == head.txid_hi
}

/// Exact Fork_repair_boot.run ordering. The host invokes this only after
/// physical store and chain recovery/integrity checks have succeeded.
pub fn finish<B: Finality>(backend: &mut B) -> Result<Finish> {
    let Some(plan) = backend.read_plan()? else {
        return Ok(Finish::Idle);
    };
    let target = plan.head.epoch_id;
    let current = backend.head()?.ok_or("HEAD is missing")?;
    if current.epoch_id < target {
        return Err("HEAD is behind fork repair target".into());
    }
    let entry = backend
        .finality_at(target)?
        .ok_or("target finality entry is missing")?;
    if backend.entry_root(&entry) != plan.target_root {
        return Err("target finality root mismatch".into());
    }
    if backend.entry_txid_hi(&entry) != plan.head.txid_hi {
        return Err("target finality txid mismatch".into());
    }
    let dropped = if current.epoch_id == target {
        if !head_matches(backend, &current, &entry) {
            return Err("HEAD differs from target finality".into());
        }
        if backend.journal_committed()? {
            backend.rewind_journal(&entry)?;
        }
        backend.drop_after(target)?
    } else {
        let entry = backend
            .finality_at(current.epoch_id)?
            .ok_or("current finality entry is missing")?;
        if !head_matches(backend, &current, &entry) {
            return Err("HEAD differs from current finality".into());
        }
        backend.committed_for(&entry)?;
        0
    };
    backend.clear()?;
    Ok(Finish::Resumed {
        target,
        head: current.epoch_id,
        dropped,
    })
}
