// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native object membership and atomic transition planning. A plan never mutates
//! storage; the VM meters every write before applying the complete ordered list.
use crate::{
    circle_storage::StorageTable, circles::normalize_state_ref, native_integer::parse_int64,
    network::endpoint::native_trim as trim,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub mod query;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Quorum {
    /// Historical OCaml Int64.to_int conversion, including its 63-bit wrap.
    #[default]
    Machine,
    Exact,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    Set(Vec<u8>, Vec<u8>),
    Del(Vec<u8>),
}
pub struct Transition {
    pub version: i64,
    pub writes: Vec<Write>,
    pub active_member_count: usize,
}
#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub transition_ref: &'a [u8],
    pub object_ref: &'a [u8],
    pub previous_state_ref: &'a [u8],
    pub next_state_ref: &'a [u8],
    pub member_bundle: &'a [u8],
    pub touched_members_hash: &'a [u8],
    pub proof_kind: &'a [u8],
    pub proof_receipt_hash: &'a [u8],
    pub status: &'a [u8],
    pub intent_id: &'a [u8],
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct Error(pub String);
type Result<T> = std::result::Result<T, Error>;

fn key(prefix: &[u8], id: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, b":", id, b":", suffix].concat()
}
fn member_key(object: &[u8], member: &[u8], suffix: &[u8]) -> Vec<u8> {
    key(b"object_member", &[object, b":", member].concat(), suffix)
}
fn hex(field: &str, raw: &[u8]) -> Result<Vec<u8>> {
    normalize_state_ref(raw).map_err(|_| Error(format!("{field} must be a 64-char hex string")))
}
fn non_empty<'a>(field: &str, raw: &'a [u8]) -> Result<&'a [u8]> {
    let value = trim(raw);
    if value.is_empty() {
        Err(Error(format!("{field} must not be empty")))
    } else {
        Ok(value)
    }
}
fn natural(raw: Option<&Vec<u8>>) -> Option<i64> {
    raw.and_then(|v| parse_int64(trim(v))).filter(|v| *v >= 0)
}
fn boolean(raw: Option<&Vec<u8>>) -> Option<bool> {
    match trim(raw?).to_ascii_lowercase().as_slice() {
        b"1" | b"true" | b"yes" => Some(true),
        b"0" | b"false" | b"no" => Some(false),
        _ => None,
    }
}
fn proof(raw: &[u8]) -> Result<Option<&[u8]>> {
    match raw {
        b"none" => Ok(None),
        b"zero_receipt_v1"
        | b"range_v1"
        | b"range_receipt_v1"
        | b"bound_zero_v1"
        | b"bound_zero_receipt_v1" => Ok(Some(raw)),
        _ => Err(Error(format!(
            "unknown hfhe proof kind: {}",
            String::from_utf8_lossy(raw)
        ))),
    }
}

/// Keys, rather than the extracted member strings, determine native ordering.
/// A member's stored value need not be a valid state reference to appear here.
pub fn members(storage: &StorageTable, object: &[u8]) -> Vec<Vec<u8>> {
    let prefix = [b"object_member:".as_slice(), object, b":"].concat();
    storage
        .values()
        .keys()
        .filter_map(|key| {
            let member = key
                .strip_prefix(prefix.as_slice())?
                .strip_suffix(b":state_ref")?;
            (!member.is_empty()).then(|| member.to_vec())
        })
        .collect()
}
pub fn has_member(storage: &StorageTable, object: &[u8], member: &[u8]) -> bool {
    storage
        .get(&member_key(object, member, b"state_ref"))
        .is_some_and(|raw| normalize_state_ref(raw).is_ok())
}

struct Delta<'a> {
    member: &'a [u8],
    /// state_ref, member_kind, state_class, codec, status for an attachment.
    fields: Option<[Vec<u8>; 5]>,
}
const MEMBER_FIELDS: [&[u8]; 5] = [
    b"state_ref",
    b"member_kind",
    b"state_class",
    b"codec",
    b"status",
];
fn fragment(field: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let value = non_empty(field, raw)?;
    if value.contains(&b'|') || value.contains(&b';') {
        Err(Error(format!("{field} must not contain bundle separators")))
    } else {
        Ok(value.to_vec())
    }
}
fn delta(raw: &[u8]) -> Result<Delta<'_>> {
    let fields: Vec<_> = trim(raw).split(|v| *v == b'|').map(trim).collect();
    let attach = match fields[0] {
        b"attach" => true,
        b"detach" => false,
        _ => {
            return Err(Error(
                "object member delta entry must start with attach or detach".into(),
            ))
        }
    };
    if fields.len() != if attach { 7 } else { 2 } {
        return Err(Error(
            if attach {
                "attach entry must have 7 fields"
            } else {
                "detach entry must have 2 fields"
            }
            .into(),
        ));
    }
    let member = non_empty("member_ref", fields[1])?;
    if member.contains(&b':') {
        return Err(Error("member_ref must not contain ':'".into()));
    }
    let values = if attach {
        Some([
            hex("state_ref", fields[2])?,
            fragment("member_kind", fields[3])?,
            fragment("state_class", fields[4])?,
            fragment("codec", fields[5])?,
            fragment("status", fields[6])?,
        ])
    } else {
        None
    };
    Ok(Delta {
        member,
        fields: values,
    })
}

/// The callback is deliberately lazy. The VM's historical member index uses the
/// raw object operand even though policy/binding keys use its normalized value.
pub fn apply(
    storage: &StorageTable,
    epoch: i64,
    quorum: Quorum,
    input: Input<'_>,
    load_members: impl FnOnce(&[u8]) -> Vec<Vec<u8>>,
) -> Result<Transition> {
    let transition = hex("transition_ref", input.transition_ref)?;
    let object = hex("object_ref", input.object_ref)?;
    let previous = hex("state_ref", input.previous_state_ref)?;
    let next = hex("state_ref", input.next_state_ref)?;
    let touched = hex("touched_members_hash", input.touched_members_hash)?;
    let status = non_empty("status", input.status)?;
    let intent = hex("intent_id", input.intent_id)?;
    let proof = proof(trim(input.proof_kind))?;
    let receipt = if trim(input.proof_receipt_hash).is_empty() {
        None
    } else {
        Some(hex("proof_receipt_hash", input.proof_receipt_hash)?)
    };
    let requires_receipt = matches!(
        proof,
        Some(b"zero_receipt_v1" | b"range_receipt_v1" | b"bound_zero_receipt_v1")
    );
    if requires_receipt != receipt.is_some() {
        return Err(Error(
            if requires_receipt {
                "proof_receipt_hash required for receipt proof kind"
            } else {
                "proof_receipt_hash requires a receipt proof kind"
            }
            .into(),
        ));
    }
    let mut deltas = Vec::new();
    for entry in trim(input.member_bundle)
        .split(|b| *b == b';')
        .map(trim)
        .filter(|e| !e.is_empty())
    {
        deltas.push(delta(entry)?);
    }
    let mut seen = BTreeSet::new();
    for delta in &deltas {
        if !seen.insert(delta.member) {
            return Err(Error(
                "object member bundle contains duplicate member_ref".into(),
            ));
        }
    }
    if hex::encode(Sha256::digest(input.member_bundle)).as_bytes() != touched {
        return Err(Error("object member bundle hash mismatch".into()));
    }
    let binding = |suffix| storage.get(&key(b"object_binding", &object, suffix));
    let current = binding(b"current_state_ref").and_then(|v| normalize_state_ref(v).ok());
    let version = natural(binding(b"version")).unwrap_or(0).wrapping_add(1);
    let policy = |suffix| storage.get(&key(b"object_policy", &object, suffix));
    let before = load_members(&object);
    let mut after: BTreeSet<_> = before.iter().cloned().collect();
    for delta in &deltas {
        if delta.fields.is_some() {
            after.insert(delta.member.to_vec());
        } else {
            after.remove(delta.member);
        }
    }
    if boolean(policy(b"tombstone")) == Some(true) {
        return Err(Error("object policy is tombstoned".into()));
    }
    if boolean(policy(b"revoked")) == Some(true) {
        return Err(Error("object policy is revoked".into()));
    }
    if natural(policy(b"activate_after_epoch")).is_some_and(|v| epoch < v) {
        return Err(Error("object policy is not active yet".into()));
    }
    if natural(policy(b"expire_after_epoch")).is_some_and(|v| epoch >= v) {
        return Err(Error("object policy has expired".into()));
    }
    let mode = policy(b"transition_mode")
        .map(|v| trim(v))
        .filter(|v| matches!(*v, b"open" | b"proof_required" | b"frozen"));
    let detach = boolean(policy(b"allow_detach"));
    let rotate = boolean(policy(b"allow_root_state_rotation"));
    if mode.is_none() || detach.is_none() || rotate.is_none() {
        return Err(Error("object transition policy is incomplete".into()));
    }
    if detach == Some(false) && deltas.iter().any(|d| d.fields.is_none()) {
        return Err(Error("object policy forbids member detach".into()));
    }
    if rotate == Some(false) && current.as_ref().is_some_and(|v| v != &next) {
        return Err(Error("object policy forbids root state rotation".into()));
    }
    match mode {
        Some(b"frozen") => return Err(Error("object policy is frozen".into())),
        Some(b"proof_required") if proof.is_none() => {
            return Err(Error("object policy requires a transition proof".into()))
        }
        _ => (),
    }
    if policy(b"required_proof_kind")
        .and_then(|v| self::proof(trim(v)).ok().flatten())
        .is_some_and(|v| Some(v) != proof)
    {
        return Err(Error("object policy proof kind mismatch".into()));
    }
    if let Some(required) = natural(policy(b"member_quorum")) {
        let count = if current.is_none() && before.is_empty() {
            after.len()
        } else {
            before.len()
        };
        let required = match quorum {
            Quorum::Machine => (required << 1) >> 1,
            Quorum::Exact => required,
        };
        if (count as i128) < i128::from(required) {
            return Err(Error("object member quorum not met".into()));
        }
    }
    if current.as_ref().is_some_and(|v| v != &previous) {
        return Err(Error(
            "object transition previous_state_ref mismatch".into(),
        ));
    }
    let mut writes = Vec::new();
    let mut snapshot = vec![
        (b"object_ref".as_slice(), object.as_slice()),
        (b"previous_state_ref", previous.as_slice()),
        (b"next_state_ref", next.as_slice()),
        (b"touched_members_hash", touched.as_slice()),
        (b"status", status),
        (b"intent_id", intent.as_slice()),
    ];
    if let Some(proof) = proof {
        snapshot.push((b"proof_kind", proof));
    }
    if let Some(receipt) = &receipt {
        snapshot.push((b"proof_receipt_hash", receipt));
    }
    snapshot.sort_unstable_by(|a, b| a.0.cmp(b.0));
    writes.extend(snapshot.into_iter().map(|(suffix, value)| {
        Write::Set(
            key(b"object_transition", &transition, suffix),
            value.to_vec(),
        )
    }));
    let version_text = version.to_string();
    let mut snapshot = [
        (b"current_state_ref".as_slice(), next.as_slice()),
        (b"version", version_text.as_bytes()),
        (b"status", status),
        (b"last_transition_ref", transition.as_slice()),
    ];
    snapshot.sort_unstable_by(|a, b| a.0.cmp(b.0));
    writes.extend(snapshot.into_iter().map(|(suffix, value)| {
        Write::Set(key(b"object_binding", &object, suffix), value.to_vec())
    }));
    for delta in deltas {
        if let Some(fields) = delta.fields {
            let mut snapshot: Vec<_> = MEMBER_FIELDS
                .into_iter()
                .zip(fields)
                .map(|(suffix, value)| (member_key(&object, delta.member, suffix), value))
                .collect();
            snapshot.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            writes.extend(
                snapshot
                    .into_iter()
                    .map(|(key, value)| Write::Set(key, value)),
            );
        } else {
            writes.extend(
                MEMBER_FIELDS
                    .into_iter()
                    .map(|suffix| Write::Del(member_key(&object, delta.member, suffix))),
            );
        }
    }
    Ok(Transition {
        version,
        writes,
        active_member_count: after.len(),
    })
}
