// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    admission::{self, Candidate, Parameters, Snapshot},
    evidence::Verified,
    policy, put_string, Error,
};
use crate::{
    control_payload::Bond,
    native_integer::{parse_int64, parse_integer},
    native_json::{Document, Value},
    network::verify_ed25519,
    transaction::{address_from_public_key, decode_base64, is_valid_address, json_string, Nonce},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::Signed;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const META_KEY: &[u8] = b"bft.validator_registry";
pub fn escrow_address() -> Vec<u8> {
    address_from_public_key(
        STANDARD
            .encode(Sha256::digest(b"octra:validator_bond:escrow"))
            .as_bytes(),
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slash {
    pub id: Vec<u8>,
    pub offender: Vec<u8>,
    pub evidence_epoch: i64,
    pub applied_epoch: i64,
    pub amount: BigInt,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    candidates: Vec<Candidate>,
    slashes: Vec<Slash>,
}
pub fn bond_message(
    chain: &[u8],
    address: &[u8],
    amount: &BigInt,
    nonce: Nonce,
    pubkey: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        b"octra:validator_bond:v1".as_slice(),
        chain,
        address,
        amount.to_string().as_bytes(),
        nonce.get().to_string().as_bytes(),
        pubkey,
    ] {
        put_string(&mut bytes, value);
    }
    bytes
}
pub fn raw_pubkey(value: &[u8]) -> Result<Vec<u8>, Error> {
    let bytes =
        decode_base64(value).map_err(|_| Error::from("invalid validator consensus public key"))?;
    if bytes.len() != 32 {
        return Err("validator consensus public key must contain 32 bytes".into());
    }
    Ok(bytes)
}
pub fn verify_bond_proof(
    chain: &[u8],
    address: &[u8],
    amount: &BigInt,
    nonce: Nonce,
    payload: &Bond,
) -> Result<Vec<u8>, Error> {
    let pubkey = raw_pubkey(&payload.consensus_public_key)?;
    let signature =
        decode_base64(&payload.proof).map_err(|_| Error::from("invalid validator bond proof"))?;
    if !verify_ed25519(
        &pubkey,
        &bond_message(chain, address, amount, nonce, &pubkey),
        &signature,
    ) {
        return Err("invalid validator bond proof".into());
    }
    Ok(pubkey)
}
impl Registry {
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    pub fn slashes(&self) -> &[Slash] {
        &self.slashes
    }
    pub fn find(&self, address: &[u8]) -> Option<&Candidate> {
        self.candidates.iter().find(|c| c.address == address)
    }
    pub fn validate(&self) -> Result<(), Error> {
        for candidate in &self.candidates {
            if !is_valid_address(&candidate.address) {
                return Err("invalid validator address".into());
            }
            candidate.validate()?;
        }
        admission::validate_unique(&self.candidates, "duplicate validator consensus public key")?;
        let mut ids = BTreeSet::new();
        for record in &self.slashes {
            if !decode_base64(&record.id)
                .is_ok_and(|raw| raw.len() == 32 && STANDARD.encode(raw).as_bytes() == record.id)
            {
                return Err("invalid validator evidence id".into());
            }
            if !is_valid_address(&record.offender) {
                return Err("invalid slashed validator address".into());
            }
            if record.evidence_epoch < 0 {
                return Err("validator evidence epoch is negative".into());
            }
            if record.applied_epoch < record.evidence_epoch {
                return Err("validator evidence application predates evidence".into());
            }
            if !record.amount.is_positive() {
                return Err("validator slash amount must be positive".into());
            }
            if !ids.insert(&record.id) {
                return Err("duplicate validator evidence id".into());
            }
        }
        Ok(())
    }
    fn replace(&self, candidate: Candidate) -> Self {
        let mut next = self.clone();
        next.candidates.retain(|c| c.address != candidate.address);
        next.candidates.insert(0, candidate);
        next.candidates.sort_by(|a, b| a.address.cmp(&b.address));
        next
    }
    #[allow(clippy::too_many_arguments)] // Native bond proof binds all transaction fields.
    pub fn apply_bond(
        &self,
        parameters: &Parameters,
        chain: &[u8],
        epoch: i64,
        address: &[u8],
        sender_pubkey: &[u8],
        amount: &BigInt,
        nonce: Nonce,
        payload: &Bond,
    ) -> Result<Self, Error> {
        if !is_valid_address(address) {
            return Err("invalid validator address".into());
        }
        if amount < &parameters.min_bond {
            return Err("validator bond is below minimum".into());
        }
        if epoch < 0 {
            return Err("validator bond epoch is negative".into());
        }
        let sender = raw_pubkey(sender_pubkey)
            .map_err(|_| Error::from("invalid validator sender public key"))?;
        let pubkey = verify_bond_proof(chain, address, amount, nonce, payload)?;
        if sender != pubkey {
            return Err("validator consensus public key must match sender public key".into());
        }
        if self
            .candidates
            .iter()
            .any(|c| c.pubkey == pubkey && c.address != address)
        {
            return Err("validator consensus public key is already bonded".into());
        }
        let candidate = match self.find(address) {
            Some(c) if c.exit_epoch.is_some() => {
                return Err("exiting validator cannot add bond".into())
            }
            Some(c) if c.pubkey != pubkey => {
                return Err("validator consensus key rotation requires withdrawal".into())
            }
            Some(c) => Candidate {
                bond: &c.bond + amount,
                ..c.clone()
            },
            None => Candidate {
                address: address.to_vec(),
                pubkey,
                bond: amount.clone(),
                bonded_epoch: epoch,
                ready_epoch: None,
                exit_epoch: None,
            },
        };
        let next = self.replace(candidate);
        next.validate()?;
        Ok(next)
    }
    pub fn mark_ready(
        &self,
        epoch: i64,
        address: &[u8],
        encoded_key: &[u8],
    ) -> Result<Self, Error> {
        if epoch < 0 {
            return Err("validator ready epoch is negative".into());
        }
        let key = raw_pubkey(encoded_key)?;
        let candidate = self.find(address).ok_or("validator bond not found")?;
        if candidate.exit_epoch.is_some() {
            return Err("exiting validator cannot become ready".into());
        }
        if candidate.pubkey != key {
            return Err("validator ready consensus key mismatch".into());
        }
        Ok(self.replace(Candidate {
            ready_epoch: Some(candidate.ready_epoch.map_or(epoch, |v| v.min(epoch))),
            ..candidate.clone()
        }))
    }
    pub fn request_exit(&self, epoch: i64, address: &[u8]) -> Result<Self, Error> {
        if epoch < 0 {
            return Err("validator exit epoch is negative".into());
        }
        let candidate = self.find(address).ok_or("validator bond not found")?;
        if candidate.exit_epoch.is_some() {
            return Err("validator exit already requested".into());
        }
        Ok(self.replace(Candidate {
            exit_epoch: Some(epoch),
            ..candidate.clone()
        }))
    }
    pub fn withdraw(
        &self,
        parameters: &Parameters,
        epoch: i64,
        active: &[Vec<u8>],
        address: &[u8],
    ) -> Result<(Self, BigInt), Error> {
        let candidate = self.find(address).ok_or("validator bond not found")?;
        if active.iter().any(|a| a == address) {
            return Err("active validator cannot withdraw".into());
        }
        if epoch < parameters.withdraw_epoch(candidate)? {
            return Err("validator unbonding period is not complete".into());
        }
        let mut next = self.clone();
        next.candidates.retain(|c| c.address != address);
        Ok((next, candidate.bond.clone()))
    }
    pub fn apply_slash(
        &self,
        epoch: i64,
        window: i64,
        evidence: &Verified,
    ) -> Result<(Self, BigInt), Error> {
        let mut retained: Vec<_> = self
            .slashes
            .iter()
            .filter(|s| s.evidence_epoch <= epoch && epoch.wrapping_sub(s.evidence_epoch) < window)
            .cloned()
            .collect();
        if retained.iter().any(|r| r.id == evidence.id) {
            return Err("validator evidence already applied".into());
        }
        let candidate = self
            .find(&evidence.offender)
            .ok_or("validator bond not found")?;
        retained.push(Slash {
            id: evidence.id.clone(),
            offender: evidence.offender.clone(),
            evidence_epoch: evidence.evidence_epoch,
            applied_epoch: epoch,
            amount: candidate.bond.clone(),
        });
        retained.sort_by(|a, b| a.id.cmp(&b.id));
        let next = Self {
            candidates: self
                .candidates
                .iter()
                .filter(|c| c.address != evidence.offender)
                .cloned()
                .collect(),
            slashes: retained,
        };
        next.validate()?;
        Ok((next, candidate.bond.clone()))
    }
    pub fn snapshot(
        &self,
        parameters: &Parameters,
        activate_epoch: i64,
    ) -> Result<Snapshot, Error> {
        admission::snapshot(parameters, activate_epoch, &self.candidates, &[])
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut candidates: Vec<_> = self.candidates.iter().collect();
        candidates.sort_by(|a, b| a.address.cmp(&b.address));
        let mut slashes: Vec<_> = self.slashes.iter().collect();
        slashes.sort_by(|a, b| a.id.cmp(&b.id));
        let mut out = b"{\"standard\":\"bonded_stake\",\"candidates\":[".to_vec();
        for (index, c) in candidates.into_iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"address\":");
            json_string(&mut out, &c.address);
            field(
                &mut out,
                b"consensus_pubkey",
                STANDARD.encode(&c.pubkey).as_bytes(),
            );
            field(&mut out, b"bond", c.bond.to_string().as_bytes());
            field(
                &mut out,
                b"bonded_epoch",
                c.bonded_epoch.to_string().as_bytes(),
            );
            epoch_field(&mut out, b"ready_epoch", c.ready_epoch);
            epoch_field(&mut out, b"exit_epoch", c.exit_epoch);
            out.push(b'}');
        }
        out.extend_from_slice(b"],\"slashes\":[");
        for (index, s) in slashes.into_iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"id\":");
            json_string(&mut out, &s.id);
            field(&mut out, b"offender", &s.offender);
            field(
                &mut out,
                b"evidence_epoch",
                s.evidence_epoch.to_string().as_bytes(),
            );
            field(
                &mut out,
                b"applied_epoch",
                s.applied_epoch.to_string().as_bytes(),
            );
            field(&mut out, b"amount", s.amount.to_string().as_bytes());
            out.push(b'}');
        }
        out.extend_from_slice(b"]}");
        out
    }
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let doc =
            Document::parse(raw).map_err(|_| Error::from("invalid validator registry JSON"))?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err("validator registry must be object".into());
        }
        let (Some(Value::String(standard)), Some(Value::List(items))) = (
            doc.field(doc.root(), b"standard"),
            doc.field(doc.root(), b"candidates"),
        ) else {
            return Err(
                if matches!(doc.field(doc.root(), b"standard"), Some(Value::String(_))) {
                    "validator registry standard mismatch"
                } else {
                    "invalid validator registry"
                }
                .into(),
            );
        };
        if standard != policy::STANDARD_NAME {
            return Err("validator registry standard mismatch".into());
        }
        let mut candidates = items
            .iter()
            .map(|id| parse_candidate(&doc, doc.get(*id).expect("JSON child")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut slashes = match doc.field(doc.root(), b"slashes") {
            None => Vec::new(),
            Some(Value::List(items)) => items
                .iter()
                .map(|id| parse_slash(&doc, doc.get(*id).expect("JSON child")))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("validator slashes must be list".into()),
        };
        // Native fold prepends before stable sorting. This determines which
        // duplicate record's validation error wins when keys are equal.
        candidates.reverse();
        slashes.reverse();
        candidates.sort_by(|a, b| a.address.cmp(&b.address));
        slashes.sort_by(|a, b| a.id.cmp(&b.id));
        let registry = Self {
            candidates,
            slashes,
        };
        registry.validate()?;
        Ok(registry)
    }
}
fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b',');
    json_string(out, name);
    out.push(b':');
    json_string(out, value);
}
fn epoch_field(out: &mut Vec<u8>, name: &[u8], value: Option<i64>) {
    out.push(b',');
    json_string(out, name);
    out.push(b':');
    match value {
        Some(v) => json_string(out, v.to_string().as_bytes()),
        None => out.extend_from_slice(b"null"),
    }
}
fn integer(label: &str, value: &Value) -> Result<i64, Error> {
    match value {
        Value::String(raw) => parse_int64(raw).ok_or_else(|| format!("invalid {label}").into()),
        Value::Int(v) => Ok(v.get()),
        _ => Err(format!("{label} must be string or int").into()),
    }
}
fn optional_integer(label: &str, value: &Value) -> Result<Option<i64>, Error> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        integer(label, value).map(Some)
    }
}
fn bond(value: &Value) -> Result<BigInt, Error> {
    let Value::String(raw) = value else {
        return Err("validator bond must be string".into());
    };
    let value = parse_integer(raw).ok_or("invalid validator bond")?;
    if !value.is_positive() {
        return Err("validator bond must be positive".into());
    }
    Ok(value)
}
fn parse_candidate(doc: &Document, value: &Value) -> Result<Candidate, Error> {
    if !matches!(value, Value::Object(_)) {
        return Err("validator registry candidate must be object".into());
    }
    let f = |name| doc.field(value, name);
    let (
        Some(Value::String(address)),
        Some(Value::String(key)),
        Some(amount),
        Some(bonded),
        Some(ready),
        Some(exit),
    ) = (
        f(b"address"),
        f(b"consensus_pubkey"),
        f(b"bond"),
        f(b"bonded_epoch"),
        f(b"ready_epoch"),
        f(b"exit_epoch"),
    )
    else {
        return Err("invalid validator registry candidate".into());
    };
    Ok(Candidate {
        address: address.clone(),
        pubkey: raw_pubkey(key)?,
        bond: bond(amount)?,
        bonded_epoch: integer("validator bonded epoch", bonded)?,
        ready_epoch: optional_integer("validator ready epoch", ready)?,
        exit_epoch: optional_integer("validator exit epoch", exit)?,
    })
}
fn parse_slash(doc: &Document, value: &Value) -> Result<Slash, Error> {
    if !matches!(value, Value::Object(_)) {
        return Err("validator slash record must be object".into());
    }
    let f = |name| doc.field(value, name);
    let (
        Some(Value::String(id)),
        Some(Value::String(offender)),
        Some(evidence),
        Some(applied),
        Some(amount),
    ) = (
        f(b"id"),
        f(b"offender"),
        f(b"evidence_epoch"),
        f(b"applied_epoch"),
        f(b"amount"),
    )
    else {
        return Err("invalid validator slash record".into());
    };
    Ok(Slash {
        id: id.clone(),
        offender: offender.clone(),
        evidence_epoch: integer("validator evidence epoch", evidence)?,
        applied_epoch: integer("validator evidence applied epoch", applied)?,
        amount: bond(amount)?,
    })
}
