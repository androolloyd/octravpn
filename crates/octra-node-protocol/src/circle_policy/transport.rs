// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{fields::Fields, native_enum, string_list, Result, Snapshot};
use crate::{
    circle_program::Refusal,
    native_json::Document,
    transaction::{is_valid_address, json_string},
};
use crate::{
    circle_transport::Claim, native_integer::parse_int64, native_json::Value,
    network::endpoint::native_trim,
};
pub const NAMES: [&[u8]; 16] = [
    b"relay_mode",
    b"lease_class",
    b"claim_strategy",
    b"claim_topology",
    b"quorum_mode",
    b"ingress_strategy",
    b"quorum_threshold",
    b"quorum_weight_threshold",
    b"max_active_claims",
    b"relay_allowlist",
    b"relay_weights",
    b"max_claim_window_epochs",
    b"max_response_bytes",
    b"require_response_ciphertext",
    b"require_external_receipt",
    b"accepted_result_codes",
];
native_enum!(RelayMode, b"unknown relay mode: ", { Registered => b"any_registered", Allowlist => b"allowlist" });
native_enum!(Lease, b"unknown lease class: ", { Reopen => b"reopen_on_expiry", Terminal => b"terminal_on_expiry", Cancel => b"cancel_on_expiry" });
native_enum!(Replacement, b"unknown claim strategy: ", { Any => b"any_replacement", SameRelay => b"same_relay_only", None => b"no_replacement" });
native_enum!(Topology, b"unknown claim topology: ", { Single => b"single_relay", Parallel => b"parallel_relays", Quorum => b"quorum_relays" });
native_enum!(Quorum, b"unknown quorum mode: ", { Count => b"count_quorum", Weighted => b"weighted_quorum" });
native_enum!(Ingress, b"unknown ingress strategy: ", {
    AnyReady => b"any_ready_relay", Oldest => b"primary_oldest", Newest => b"primary_newest", Heaviest => b"primary_heaviest",
    HeaviestOldest => b"primary_heaviest_oldest", HeaviestNewest => b"primary_heaviest_newest",
});
#[derive(Clone, Debug)]
pub struct Policy {
    pub relay_mode: RelayMode,
    pub lease: Lease,
    pub replacement: Replacement,
    pub topology: Topology,
    pub quorum: Quorum,
    pub ingress: Ingress,
    pub threshold: Option<i64>,
    pub weight_threshold: Option<i64>,
    pub max_active: Option<i64>,
    pub allowlist: Vec<Vec<u8>>,
    pub weights: Vec<(Vec<u8>, i64)>,
    pub max_window: Option<i64>,
    pub max_response: Option<i64>,
    pub require_ciphertext: bool,
    pub require_receipt: bool,
    pub result_codes: Option<Vec<i64>>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            relay_mode: RelayMode::Registered,
            lease: Lease::Reopen,
            replacement: Replacement::Any,
            topology: Topology::Single,
            quorum: Quorum::Count,
            ingress: Ingress::AnyReady,
            threshold: None,
            weight_threshold: None,
            max_active: None,
            allowlist: vec![],
            weights: vec![],
            max_window: None,
            max_response: None,
            require_ciphertext: false,
            require_receipt: false,
            result_codes: None,
        }
    }
}
impl Policy {
    pub fn from_stored(mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Self {
        let mut out = Self::default();
        if let Some(value) = get(b"relay_mode").and_then(|raw| RelayMode::parse(&raw).ok()) {
            out.relay_mode = value;
        }
        if let Some(value) = get(b"lease_class").and_then(|raw| Lease::parse(&raw).ok()) {
            out.lease = value;
        }
        if let Some(value) = get(b"claim_strategy").and_then(|raw| Replacement::parse(&raw).ok()) {
            out.replacement = value;
        }
        if let Some(value) = get(b"claim_topology").and_then(|raw| Topology::parse(&raw).ok()) {
            out.topology = value;
        }
        if let Some(value) = get(b"quorum_mode").and_then(|raw| Quorum::parse(&raw).ok()) {
            out.quorum = value;
        }
        if let Some(value) = get(b"ingress_strategy").and_then(|raw| Ingress::parse(&raw).ok()) {
            out.ingress = value;
        }
        let integer = |raw: Option<Vec<u8>>| raw.and_then(|raw| parse_int64(native_trim(&raw)));
        // Native Int64.to_int truncates to a signed 63-bit machine integer.
        let machine = |raw| integer(raw).map(|v| v.wrapping_shl(1) >> 1);
        out.threshold = machine(get(b"quorum_threshold"));
        out.weight_threshold = machine(get(b"quorum_weight_threshold"));
        out.max_active = machine(get(b"max_active_claims"));
        if let Some(doc) = get(b"relay_allowlist").and_then(|raw| Document::parse(&raw).ok()) {
            if let Value::List(values) = doc.root() {
                out.allowlist = values
                    .iter()
                    .filter_map(|id| match doc.get(*id) {
                        Some(Value::String(raw)) => Some(raw.clone()),
                        _ => None,
                    })
                    .collect();
            }
        }
        if let Some(doc) = get(b"relay_weights").and_then(|raw| Document::parse(&raw).ok()) {
            if let Value::Object(values) = doc.root() {
                out.weights = values
                    .iter()
                    .filter_map(|(key, id)| {
                        Some((key.clone(), super::fields::integer(doc.get(*id)?)?))
                    })
                    .collect();
            }
        }
        out.max_window = integer(get(b"max_claim_window_epochs"));
        out.max_response = integer(get(b"max_response_bytes"));
        let flag = |raw: Option<Vec<u8>>| {
            raw.is_some_and(|raw| {
                matches!(
                    native_trim(&raw).to_ascii_lowercase().as_slice(),
                    b"1" | b"true" | b"yes"
                )
            })
        };
        out.require_ciphertext = flag(get(b"require_response_ciphertext"));
        out.require_receipt = flag(get(b"require_external_receipt"));
        if let Some(doc) = get(b"accepted_result_codes").and_then(|raw| Document::parse(&raw).ok())
        {
            if let Value::List(values) = doc.root() {
                out.result_codes = Some(
                    values
                        .iter()
                        .filter_map(|id| super::fields::integer(doc.get(*id)?))
                        .collect(),
                );
            }
        }
        out
    }
    pub fn relay_allowed(&self, relay: &[u8]) -> bool {
        self.relay_mode == RelayMode::Registered || self.allowlist.iter().any(|id| id == relay)
    }
    pub fn active_limit(&self) -> i64 {
        if self.topology == Topology::Single {
            1
        } else {
            self.max_active.unwrap_or((1i64 << 62) - 1)
        }
    }
    pub fn weight(&self, relay: &[u8]) -> i64 {
        self.weights
            .iter()
            .find(|(id, _)| id == relay)
            .map_or(1, |(_, w)| if *w > 0 { *w } else { 1 })
    }
    pub fn ready(&self, claims: &[Claim]) -> bool {
        let quorum = self.topology == Topology::Quorum;
        if quorum && self.quorum == Quorum::Weighted {
            let weight = claims.iter().fold(0i64, |sum, claim| {
                sum.wrapping_add(self.weight(&claim.relay)).wrapping_shl(1) >> 1
            });
            weight >= self.weight_threshold.unwrap_or(2)
        } else {
            (claims.len() as i64)
                >= if quorum {
                    self.threshold.unwrap_or(2)
                } else {
                    1
                }
        }
    }
    pub fn ingress_relay_allowed(&self, claims: &[Claim], relay: &[u8]) -> bool {
        if self.ingress == Ingress::AnyReady {
            return claims.iter().any(|c| c.relay == relay);
        }
        let newest = |left: &Claim, right: &Claim| {
            right
                .epoch
                .cmp(&left.epoch)
                .then(right.expiry.cmp(&left.expiry))
                .then(left.relay.cmp(&right.relay))
        };
        claims
            .iter()
            .min_by(|left, right| match self.ingress {
                Ingress::AnyReady | Ingress::Newest => newest(left, right),
                Ingress::Oldest => newest(right, left),
                Ingress::Heaviest | Ingress::HeaviestNewest => self
                    .weight(&right.relay)
                    .cmp(&self.weight(&left.relay))
                    .then_with(|| newest(left, right)),
                Ingress::HeaviestOldest => self
                    .weight(&right.relay)
                    .cmp(&self.weight(&left.relay))
                    .then_with(|| newest(right, left)),
            })
            .is_some_and(|claim| claim.relay == relay)
    }
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::new(doc, "transport policy")?;
        fields.integer_exceptions(&[
            ("quorum_threshold", true),
            ("quorum_weight_threshold", true),
            ("max_active_claims", true),
            ("max_claim_window_epochs", false),
            ("max_response_bytes", false),
        ])?;
        let names = [
            "relay_mode",
            "lease_class",
            "claim_strategy",
            "claim_topology",
            "quorum_mode",
            "ingress_strategy",
        ];
        let raw = names
            .iter()
            .map(|name| fields.text(name))
            .collect::<Result<Vec<_>>>()?;
        let threshold = fields.number("quorum_threshold", true)?;
        let weight_threshold = fields.number("quorum_weight_threshold", true)?;
        let max_active = fields.number("max_active_claims", true)?;
        let allowlist = fields.strings("relay_allowlist")?.unwrap_or_default();
        let weights = fields.weights("relay_weights")?.unwrap_or_default();
        let max_window = fields.number("max_claim_window_epochs", false)?;
        let max_response = fields.number("max_response_bytes", false)?;
        let require_ciphertext = fields.flag("require_response_ciphertext")?.unwrap_or(false);
        let require_receipt = fields.flag("require_external_receipt")?.unwrap_or(false);
        let result_codes = fields.integers("accepted_result_codes")?;
        let default = Self::default();
        Ok(Self {
            relay_mode: raw[0]
                .as_deref()
                .map(RelayMode::parse)
                .transpose()?
                .unwrap_or(default.relay_mode),
            lease: raw[1]
                .as_deref()
                .map(Lease::parse)
                .transpose()?
                .unwrap_or(default.lease),
            replacement: raw[2]
                .as_deref()
                .map(Replacement::parse)
                .transpose()?
                .unwrap_or(default.replacement),
            topology: raw[3]
                .as_deref()
                .map(Topology::parse)
                .transpose()?
                .unwrap_or(default.topology),
            quorum: raw[4]
                .as_deref()
                .map(Quorum::parse)
                .transpose()?
                .unwrap_or(default.quorum),
            ingress: raw[5]
                .as_deref()
                .map(Ingress::parse)
                .transpose()?
                .unwrap_or(default.ingress),
            threshold,
            weight_threshold,
            max_active,
            allowlist,
            weights,
            max_window,
            max_response,
            require_ciphertext,
            require_receipt,
            result_codes,
        })
    }
    pub fn validate(&self) -> Result<()> {
        let invalid = |tag, reason: &'static [u8]| Err(Refusal::new(tag, reason));
        if !self.allowlist.iter().all(|id| is_valid_address(id)) {
            return invalid(
                "invalid_circle_relay_allowlist",
                b"invalid_circle_relay_allowlist must contain valid octra addresses",
            );
        }
        if self.max_window.is_some_and(|v| v <= 0) {
            return invalid(
                "invalid_circle_claim_window",
                b"max_claim_window_epochs must be positive",
            );
        }
        if self.max_response.is_some_and(|v| v <= 0) {
            return invalid(
                "invalid_circle_response_limit",
                b"max_response_bytes must be positive",
            );
        }
        if self.weights.iter().any(|(_, weight)| *weight <= 0) {
            return invalid(
                "invalid_circle_transport_relay_weight",
                b"relay weights must be positive",
            );
        }
        if self.threshold.is_some_and(|v| v <= 0) {
            return invalid(
                "invalid_circle_transport_quorum_threshold",
                b"quorum_threshold must be positive",
            );
        }
        if self.max_active.is_some_and(|v| v <= 0) {
            return invalid(
                "invalid_circle_transport_max_active_claims",
                b"max_active_claims must be positive",
            );
        }
        if self.weight_threshold.is_some_and(|v| v <= 0) {
            return invalid(
                "invalid_circle_transport_quorum_weight_threshold",
                b"quorum_weight_threshold must be positive",
            );
        }
        match self.topology {
            Topology::Single => {
                if self.threshold.is_some_and(|v| v != 1) {
                    return invalid(
                        "invalid_circle_transport_quorum_threshold",
                        b"single_relay topology requires quorum_threshold = 1",
                    );
                }
                if self.weight_threshold.is_some_and(|v| v != 1) {
                    return invalid(
                        "invalid_circle_transport_quorum_weight_threshold",
                        b"single_relay topology requires quorum_weight_threshold = 1 when provided",
                    );
                }
                if self.max_active.is_some_and(|v| v != 1) {
                    return invalid(
                        "invalid_circle_transport_max_active_claims",
                        b"single_relay topology requires max_active_claims = 1",
                    );
                }
            }
            Topology::Parallel => {
                if self.threshold.is_some_and(|v| v != 1) {
                    return invalid(
                        "invalid_circle_transport_quorum_threshold",
                        b"parallel_relays topology requires quorum_threshold = 1 when provided",
                    );
                }
                if self.weight_threshold.is_some_and(|v| v != 1) {
                    return invalid("invalid_circle_transport_quorum_weight_threshold", b"parallel_relays topology requires quorum_weight_threshold = 1 when provided");
                }
            }
            Topology::Quorum => {
                let threshold = self.threshold.unwrap_or(2);
                if threshold < 2 {
                    return invalid(
                        "invalid_circle_transport_quorum_threshold",
                        b"quorum_relays topology requires quorum_threshold >= 2",
                    );
                }
                if self.quorum == Quorum::Weighted && self.weight_threshold.unwrap_or(2) < 2 {
                    return invalid(
                        "invalid_circle_transport_quorum_weight_threshold",
                        b"weighted quorum requires quorum_weight_threshold >= 2",
                    );
                }
                if self.max_active.is_some_and(|max| threshold > max) {
                    return invalid(
                        "invalid_circle_transport_quorum_threshold",
                        b"quorum_threshold must not exceed max_active_claims",
                    );
                }
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Snapshot {
        let mut out = Snapshot::default();
        let default = Self::default();
        let prefix = b"transport_policy";
        for (name, raw, default) in [
            (
                b"relay_mode".as_slice(),
                self.relay_mode.as_bytes(),
                default.relay_mode.as_bytes(),
            ),
            (
                b"lease_class",
                self.lease.as_bytes(),
                default.lease.as_bytes(),
            ),
            (
                b"claim_strategy",
                self.replacement.as_bytes(),
                default.replacement.as_bytes(),
            ),
            (
                b"claim_topology",
                self.topology.as_bytes(),
                default.topology.as_bytes(),
            ),
            (
                b"quorum_mode",
                self.quorum.as_bytes(),
                default.quorum.as_bytes(),
            ),
            (
                b"ingress_strategy",
                self.ingress.as_bytes(),
                default.ingress.as_bytes(),
            ),
        ] {
            out.nondefault(prefix, name, raw, default);
        }
        for (name, value) in [
            (b"quorum_threshold".as_slice(), self.threshold),
            (b"quorum_weight_threshold", self.weight_threshold),
            (b"max_active_claims", self.max_active),
            (b"max_claim_window_epochs", self.max_window),
            (b"max_response_bytes", self.max_response),
        ] {
            out.set(prefix, name, value.map(|v| v.to_string().into_bytes()));
        }
        out.set(
            prefix,
            b"relay_allowlist",
            (!self.allowlist.is_empty()).then(|| string_list(&self.allowlist)),
        );
        out.set(
            prefix,
            b"relay_weights",
            (!self.weights.is_empty()).then(|| {
                let mut raw = vec![b'{'];
                for (index, (key, weight)) in self.weights.iter().enumerate() {
                    if index != 0 {
                        raw.push(b',');
                    }
                    json_string(&mut raw, key);
                    raw.push(b':');
                    raw.extend_from_slice(weight.to_string().as_bytes());
                }
                raw.push(b'}');
                raw
            }),
        );
        out.set(
            prefix,
            b"require_response_ciphertext",
            self.require_ciphertext.then(|| b"true".to_vec()),
        );
        out.set(
            prefix,
            b"require_external_receipt",
            self.require_receipt.then(|| b"true".to_vec()),
        );
        out.set(
            prefix,
            b"accepted_result_codes",
            self.result_codes.as_ref().map(|codes| {
                let mut raw = vec![b'['];
                for (i, code) in codes.iter().enumerate() {
                    if i != 0 {
                        raw.push(b',');
                    }
                    raw.extend_from_slice(code.to_string().as_bytes());
                }
                raw.push(b']');
                raw
            }),
        );
        out
    }
}
