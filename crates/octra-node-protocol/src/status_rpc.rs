// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native status projections. Every measurement is supplied by its owning host.
pub mod consensus;
pub mod stats;
use crate::{
    light_rpc::json::{self, boolean, number, object, optional, string},
    rpc::Fault,
    validator::{admission::Candidate, set_fold},
};

pub fn node_version() -> Vec<u8> {
    object(&[
        ("node", string(b"octra")),
        ("version", string(b"3.0.0")),
        ("protocol", string(b"json-rpc-2.0")),
    ])
}
pub fn release_hash(raw: Option<&[u8]>, length: usize) -> Option<Vec<u8>> {
    let v = crate::network::endpoint::native_trim(raw?);
    (v.len() == length
        && v.iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
    .then(|| v.to_vec())
}
pub struct RuntimeVersion<'a> {
    pub source_commit: Option<&'a [u8]>,
    pub binary_hash: Option<&'a [u8]>,
    pub consensus_standard: &'a [u8],
    pub consensus_standard_hash: &'a [u8],
    pub activation_graph_hash: &'a [u8],
    pub compat_wire_profile: i64,
    pub compat_wire_rules_id: &'a [u8],
    pub runtime_profile_hash: Option<&'a [u8]>,
    pub config_hash: &'a [u8],
    pub chain_id: &'a [u8],
    pub validator: &'a [u8],
}
impl RuntimeVersion<'_> {
    pub fn to_json(&self) -> Vec<u8> {
        object(&[
            ("schema", string(b"octra-runtime-release-v1")),
            ("schema_version", number(1)),
            ("node", string(b"octra")),
            ("node_version", string(b"3.0.0")),
            ("source_commit", optional(self.source_commit)),
            ("binary_hash", optional(self.binary_hash)),
            ("consensus_standard", string(self.consensus_standard)),
            (
                "consensus_standard_hash",
                string(hex::encode(self.consensus_standard_hash)),
            ),
            (
                "activation_graph_hash",
                string(hex::encode(self.activation_graph_hash)),
            ),
            ("consensus_profile", number(self.compat_wire_profile)),
            ("consensus_rules_id", string(self.compat_wire_rules_id)),
            (
                "runtime_profile_hash",
                self.runtime_profile_hash
                    .map_or_else(json::null, |v| string(hex::encode(v))),
            ),
            ("config_hash", string(hex::encode(self.config_hash))),
            ("chain_id", string(self.chain_id)),
            ("validator", string(self.validator)),
            ("self_reported", boolean(true)),
        ])
    }
}
pub fn validator_view_pubkey(key: &[u8], address: &[u8]) -> Vec<u8> {
    object(&[
        ("validator_view_pubkey", string(json::base64(key))),
        ("validator_address", string(address)),
    ])
}
pub struct EpochTags {
    pub count: i64,
    pub min_epoch: i64,
    pub max_epoch: i64,
    pub keep_epochs: i64,
    pub split_epoch: Option<i64>,
    pub gc_enabled: bool,
    pub gc_running: bool,
    pub gc_need: Option<i64>,
}
impl EpochTags {
    pub fn to_json(&self) -> Vec<u8> {
        object(&[
            ("count", number(self.count)),
            ("min_epoch", number(self.min_epoch)),
            ("max_epoch", number(self.max_epoch)),
            ("keep_epochs", number(self.keep_epochs)),
            (
                "split_epoch",
                self.split_epoch.map_or_else(json::null, number),
            ),
            ("pack_gc_enabled", boolean(self.gc_enabled)),
            ("pack_gc_running", boolean(self.gc_running)),
            (
                "pack_gc_need_bytes",
                self.gc_need
                    .map_or_else(json::null, |v| string(v.to_string())),
            ),
        ])
    }
}
pub struct Head<'a> {
    pub epoch: i64,
    pub state_root: &'a [u8],
    pub txid_hi: i64,
    pub irmin_commit: Option<&'a [u8]>,
}
fn head_fields(head: Option<&Head<'_>>) -> Vec<(&'static str, Vec<u8>)> {
    match head {
        None => vec![
            ("head_epoch", json::null()),
            ("state_root", json::null()),
            ("txid_hi", json::null()),
            ("irmin_commit", json::null()),
        ],
        Some(h) => vec![
            ("head_epoch", number(h.epoch)),
            ("state_root", string(h.state_root)),
            ("txid_hi", string(h.txid_hi.to_string())),
            ("irmin_commit", optional(h.irmin_commit)),
        ],
    }
}
pub fn node_status(
    epoch: i64,
    validator: &[u8],
    roots: i64,
    timestamp: f64,
    head: Option<&Head<'_>>,
) -> Result<Vec<u8>, Fault> {
    let mut fields = vec![
        ("epoch", number(epoch)),
        ("current_epoch", number(epoch)),
        ("validator", string(validator)),
        ("roots", number(roots)),
        (
            "timestamp",
            crate::transaction::native_float(timestamp)
                .map(String::into_bytes)
                .map_err(|_| Fault::new(110, b"service unavailable"))?,
        ),
        ("network_version", string(b"v3.0.0-irmin")),
    ];
    fields.extend(head_fields(head));
    Ok(object(&fields))
}
pub fn enrollment_epoch(epoch: Option<i64>) -> Vec<u8> {
    epoch.map_or_else(json::null, |v| string(v.to_string()))
}

/// Native Enroll_members: committed metadata is checked independently of the
/// launcher's fallback validator environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub epoch: i64,
    pub active: bool,
    pub scheduled: bool,
    pub activate_epoch: Option<i64>,
    pub next_set_epoch: Option<i64>,
    pub set_hash: [u8; 32],
}
impl Membership {
    pub fn of_values(
        head_epoch: i64,
        address: &[u8],
        pubkey: &[u8],
        active: Option<&[u8]>,
        pending: Option<&[u8]>,
    ) -> Result<Option<Self>, crate::oce1::Error> {
        use crate::control_payload::ValidatorUpdate;
        if head_epoch < 0 {
            return Err("invalid committed validator head".into());
        }
        let read = |v: Option<&[u8]>| -> Result<Option<ValidatorUpdate>, crate::oce1::Error> {
            let Some(v) = v else { return Ok(None) };
            let update = ValidatorUpdate::parse(Some(v))
                .map_err(|e| crate::oce1::Error::from(e.to_string()))?;
            if update.activate_epoch < 0 || update.source_epoch.is_some_and(|e| e > head_epoch) {
                return Err("validator set epoch exceeds committed view".into());
            }
            Ok(Some(update))
        };
        let active = read(active)?;
        let pending = read(pending)?;
        if active
            .as_ref()
            .is_some_and(|v| v.activate_epoch > head_epoch)
        {
            return Err("active validator set exceeds committed head".into());
        }
        if let (Some(a), Some(p)) = (&active, &pending) {
            if a.activate_epoch == p.activate_epoch && a.fingerprint != p.fingerprint {
                return Err("committed validator sets conflict".into());
            }
        }
        let selected = match (&active, &pending) {
            (a, Some(p)) if p.activate_epoch <= head_epoch => Some(match a {
                Some(a) if a.activate_epoch > p.activate_epoch => a,
                _ => p,
            }),
            (a, _) => a.as_ref(),
        };
        let Some(selected) = selected else {
            return Ok(None);
        };
        let contains = |set: &ValidatorUpdate| -> Result<bool, crate::oce1::Error> {
            match set.validators.iter().find(|v| v.address == address) {
                None => Ok(false),
                Some(v) if v.public_key == pubkey => Ok(true),
                Some(_) => Err("committed validator set public key differs".into()),
            }
        };
        let next = pending.as_ref().filter(|v| v.activate_epoch > head_epoch);
        let active = contains(selected)?;
        let scheduled = next.map(contains).transpose()?.unwrap_or(false);
        let next_set_epoch = next.map(|v| v.activate_epoch);
        Ok(Some(Self {
            epoch: head_epoch,
            active,
            scheduled,
            activate_epoch: if scheduled { next_set_epoch } else { None },
            next_set_epoch,
            set_hash: crate::consensus::hash::validator_set_hash(&selected.validator_set()?)?,
        }))
    }
    pub fn to_json(&self) -> Vec<u8> {
        object(&[
            ("epoch", string(self.epoch.to_string())),
            ("active", boolean(self.active)),
            ("scheduled", boolean(self.scheduled)),
            ("activate_epoch", enrollment_epoch(self.activate_epoch)),
            ("next_set_epoch", enrollment_epoch(self.next_set_epoch)),
            ("validator_set_hash", string(hex::encode(self.set_hash))),
        ])
    }
}
pub struct Enrollment<'a> {
    pub chain_id: &'a [u8],
    pub head_epoch: i64,
    pub address: &'a [u8],
    pub pubkey: &'a [u8],
    pub candidate: Option<&'a Candidate>,
    pub state_root: &'a [u8],
    pub config_hash: &'a [u8],
    pub duty: Option<&'a set_fold::Receipt>,
    pub membership: Option<&'a Membership>,
    pub head_proposal_id: Option<&'a [u8]>,
    pub ready_exec_active: bool,
    pub withdraw_epoch: Option<i64>,
    pub local_control: Option<std::result::Result<Option<String>, Vec<u8>>>,
}
impl Enrollment<'_> {
    pub fn to_json(&self) -> Result<Vec<u8>, Fault> {
        let fault = |message: &'static [u8]| Fault::new(-32000, message);
        if self.head_epoch < 0 {
            return Err(fault(b"invalid committed validator head"));
        }
        let (state, bond, bonded, ready, exit) = match self.candidate {
            None => (
                b"absent".as_slice(),
                json::null(),
                json::null(),
                json::null(),
                json::null(),
            ),
            Some(c) => {
                if c.address != self.address {
                    return Err(fault(b"validator enrollment address differs"));
                }
                if json::base64(&c.pubkey).as_bytes() != self.pubkey {
                    return Err(fault(b"validator enrollment public key differs"));
                }
                (
                    if c.exit_epoch.is_some() {
                        b"exiting".as_slice()
                    } else if c.ready_epoch.is_some() {
                        b"ready".as_slice()
                    } else {
                        b"bonded".as_slice()
                    },
                    string(c.bond.to_string()),
                    string(c.bonded_epoch.to_string()),
                    enrollment_epoch(c.ready_epoch),
                    enrollment_epoch(c.exit_epoch),
                )
            }
        };
        let mut ready_fields = vec![
            ("consensus_pubkey", string(self.pubkey)),
            ("head_epoch", string(self.head_epoch.to_string())),
            ("state_root", string(self.state_root)),
            ("chain_id", string(self.chain_id)),
            ("config_hash", string(self.config_hash)),
            ("catchup_head_epoch", string(self.head_epoch.to_string())),
        ];
        if self.head_proposal_id.is_some() || self.ready_exec_active {
            ready_fields.push(("head_proposal_id", optional(self.head_proposal_id)));
        }
        let duty = self.duty.map_or_else(json::null, |r| {
            let cfg = set_fold::Config::default();
            object(&[
                ("automatic", boolean(true)),
                ("head_epoch", string(self.head_epoch.to_string())),
                ("last_pulse", enrollment_epoch(r.pulse)),
                ("required_span", string(cfg.rejoin_span.to_string())),
                ("max_gap", string(cfg.pulse_gap.to_string())),
            ])
        });
        let mut fields = vec![
            ("head_epoch", number(self.head_epoch)),
            ("address", string(self.address)),
            ("consensus_pubkey", string(self.pubkey)),
            ("identity", string(b"self_reported")),
            ("state", string(state)),
            ("bond", bond),
            ("bonded_epoch", bonded),
            ("ready_epoch", ready),
            ("exit_epoch", exit),
            ("withdraw_epoch", enrollment_epoch(self.withdraw_epoch)),
            (
                "withdraw_remaining_epochs",
                enrollment_epoch(
                    self.withdraw_epoch
                        .map(|v| v.wrapping_sub(self.head_epoch).max(0)),
                ),
            ),
            ("state_root", string(self.state_root)),
            ("chain_id", string(self.chain_id)),
            (
                "membership",
                self.membership.map_or_else(json::null, Membership::to_json),
            ),
            ("ready", object(&ready_fields)),
            ("duty", duty),
        ];
        if let Some(control) = &self.local_control {
            fields.push((
                "local_control",
                match control {
                    Ok(id) => object(&[
                        ("exit_intent", boolean(true)),
                        ("exit_requested", boolean(id.is_some())),
                        (
                            "intent_id",
                            optional(id.as_ref().map(std::string::String::as_bytes)),
                        ),
                    ]),
                    Err(error) => {
                        object(&[("exit_intent", boolean(true)), ("error", string(error))])
                    }
                },
            ));
        }
        Ok(object(&fields))
    }
}
