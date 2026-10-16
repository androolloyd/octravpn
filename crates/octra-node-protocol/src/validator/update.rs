// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Canonical pending-set and legacy-readiness metadata.
use super::{admission::Member, put_string, Error};
use crate::{
    control_payload::{LegacyReady, ValidatorEntry, ValidatorUpdate},
    transaction::json_string,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub const PENDING_KEY: &[u8] = b"bft.validator_set.pending";
pub const ACTIVE_KEY: &[u8] = b"bft.validator_set.active";
pub fn snapshot_slot(epoch: i64, pending: Option<&ValidatorUpdate>) -> bool {
    pending.is_none_or(|p| p.activate_epoch <= epoch)
}
pub fn ready_key(fingerprint: &[u8], address: &[u8]) -> Vec<u8> {
    [b"bft.validator_set.ready.", fingerprint, b".", address].concat()
}
fn field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if out.len() > 1 {
        out.push(b',');
    }
    json_string(out, name);
    out.push(b':');
    json_string(out, value);
}
impl ValidatorUpdate {
    pub fn make_weighted(source: i64, activate: i64, members: &[Member]) -> Result<Self, Error> {
        if source >= activate {
            return Err("weighted validator source epoch must precede activation".into());
        }
        let mut validators: Vec<_> = members
            .iter()
            .map(|m| ValidatorEntry {
                address: m.address.clone(),
                public_key: STANDARD.encode(&m.pubkey).into_bytes(),
                weight: m.weight.clone(),
            })
            .collect();
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for v in &validators {
            if !addresses.insert(&v.address) {
                return Err("duplicate validator address".into());
            }
            if !keys.insert(&v.public_key) {
                return Err("duplicate validator public key".into());
            }
        }
        if validators.is_empty() {
            return Err("validator set cannot be empty".into());
        }
        let mut preimage = Vec::new();
        for v in [
            b"octra:validator_set_update:bonded".as_slice(),
            source.to_string().as_bytes(),
            activate.to_string().as_bytes(),
        ] {
            put_string(&mut preimage, v);
        }
        for v in &validators {
            put_string(&mut preimage, &v.address);
            put_string(&mut preimage, &v.public_key);
            put_string(&mut preimage, v.weight.to_string().as_bytes());
        }
        Ok(Self {
            activate_epoch: activate,
            source_epoch: Some(source),
            weighted: true,
            fingerprint: hex::encode(Sha256::digest(preimage)),
            validators,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        field(
            &mut out,
            b"activate_epoch",
            self.activate_epoch.to_string().as_bytes(),
        );
        field(&mut out, b"fingerprint", self.fingerprint.as_bytes());
        out.extend_from_slice(b",\"validators\":[");
        for (i, v) in self.validators.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            let mut entry = vec![b'{'];
            field(&mut entry, b"address", &v.address);
            field(&mut entry, b"pubkey", &v.public_key);
            if self.weighted {
                field(&mut entry, b"weight", v.weight.to_string().as_bytes());
            }
            entry.push(b'}');
            out.extend(entry);
        }
        out.push(b']');
        if self.weighted {
            field(&mut out, b"standard", b"bonded_stake");
            out.extend_from_slice(b",\"weighted\":true");
            field(
                &mut out,
                b"source_epoch",
                self.source_epoch
                    .expect("weighted source epoch")
                    .to_string()
                    .as_bytes(),
            );
        }
        out.push(b'}');
        out
    }
}
impl LegacyReady {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        // Native ready_ext reverses the base fields after prepending extras.
        field(&mut out, b"state_root", &self.state_root);
        field(
            &mut out,
            b"head_epoch",
            self.head_epoch.to_string().as_bytes(),
        );
        field(&mut out, b"fingerprint", &self.fingerprint);
        for (name, value) in [
            (b"chain_id".as_slice(), self.extra.chain_id.as_deref()),
            (b"binary_hash", self.extra.binary_hash.as_deref()),
            (b"config_hash", self.extra.config_hash.as_deref()),
        ] {
            if let Some(v) = value {
                field(&mut out, name, v);
            }
        }
        for (name, value) in [
            (
                b"catchup_head_epoch".as_slice(),
                self.extra.catchup_head_epoch,
            ),
            (b"shadow_epochs", self.extra.shadow_epochs),
        ] {
            if let Some(v) = value {
                field(&mut out, name, v.to_string().as_bytes());
            }
        }
        out.push(b'}');
        out
    }
}
