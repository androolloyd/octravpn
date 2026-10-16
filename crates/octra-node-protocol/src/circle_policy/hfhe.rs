// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{fields::Fields, native_enum, string_list, Result, Snapshot};
use crate::native_json::Document;
use crate::{
    native_json::Value,
    network::endpoint::native_trim,
    transaction::{is_valid_address, json_string},
};
use sha2::{Digest, Sha256};
native_enum!(Access, b"unknown hfhe access mode: ", {
    Deny => b"deny", Owner => b"owner_only", Caller => b"caller_self", OwnerCaller => b"owner_or_caller",
    Registered => b"any_registered", Relay => b"active_relay", OwnerRelay => b"owner_or_active_relay",
});
native_enum!(Proof, b"unknown hfhe proof kind: ", {
    None => b"none", ZeroReceipt => b"zero_receipt_v1", Range => b"range_v1", RangeReceipt => b"range_receipt_v1",
    BoundZero => b"bound_zero_v1", BoundZeroReceipt => b"bound_zero_receipt_v1",
});
native_enum!(Receipt, b"unknown hfhe receipt class: ", {
    Detached => b"detached", TransportBound => b"transport_bound", RelayWitnessed => b"relay_witnessed",
});
impl Access {
    pub const fn relay_scoped(self) -> bool {
        matches!(self, Self::Relay | Self::OwnerRelay)
    }
    pub fn allows(self, owner: &[u8], caller: &[u8], subject: &[u8], relays: &[Vec<u8>]) -> bool {
        let relay = relays.iter().any(|relay| relay == caller);
        match self {
            Self::Deny => false,
            Self::Owner => owner == caller,
            Self::Caller => caller == subject,
            Self::OwnerCaller => owner == caller || caller == subject,
            Self::Registered => is_valid_address(caller),
            Self::Relay => relay,
            Self::OwnerRelay => owner == caller || relay,
        }
    }
}
impl Proof {
    pub const fn receipt_required(self) -> bool {
        matches!(
            self,
            Self::ZeroReceipt | Self::RangeReceipt | Self::BoundZeroReceipt
        )
    }
}
pub const MODE_NAMES: [&str; 12] = [
    "load_pk_mode",
    "encrypt_mode",
    "decrypt_mode",
    "cipher_arithmetic_mode",
    "commit_mode",
    "pedersen_mode",
    "cipher_serde_mode",
    "pubkey_serde_mode",
    "verify_zero_mode",
    "verify_range_mode",
    "verify_bound_mode",
    "proof_receipt_signer_mode",
];
#[derive(Clone, Debug)]
pub struct Policy {
    pub modes: [Access; 12],
    pub receipt: Receipt,
    pub pk_allowlist: Option<Vec<Vec<u8>>>,
    pub require_live_key: bool,
    pub require_transport_binding: bool,
    pub encrypt_proof: Proof,
    pub decrypt_proof: Proof,
}
impl Default for Policy {
    fn default() -> Self {
        let mut modes = [Access::Owner; 12];
        modes[0] = Access::Caller;
        modes[11] = Access::Caller;
        Self {
            modes,
            receipt: Receipt::Detached,
            pk_allowlist: None,
            require_live_key: true,
            require_transport_binding: false,
            encrypt_proof: Proof::BoundZero,
            decrypt_proof: Proof::None,
        }
    }
}
impl Policy {
    pub fn from_stored(mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Self {
        let mut out = Self::default();
        for (i, name) in MODE_NAMES.iter().enumerate() {
            if let Some(raw) = get(name.as_bytes()) {
                out.modes[i] = Access::parse(&raw).unwrap_or(Access::Deny);
            }
        }
        let flag = |raw: Option<Vec<u8>>, default| {
            raw.map_or(default, |raw| {
                !matches!(
                    native_trim(&raw).to_ascii_lowercase().as_slice(),
                    b"0" | b"false" | b"no"
                )
            })
        };
        out.require_live_key = flag(get(b"require_live_key_policy"), true);
        out.require_transport_binding = flag(get(b"require_receipt_transport_binding"), false);
        let strict_proof = if out.require_transport_binding {
            Proof::BoundZeroReceipt
        } else {
            Proof::BoundZero
        };
        if let Some(raw) = get(b"encrypt_proof") {
            out.encrypt_proof = Proof::parse(native_trim(&raw)).unwrap_or(strict_proof);
        }
        if let Some(raw) = get(b"decrypt_proof") {
            out.decrypt_proof = Proof::parse(native_trim(&raw)).unwrap_or(strict_proof);
        }
        out.receipt = get(b"proof_receipt_class").map_or(
            if out.require_transport_binding {
                Receipt::TransportBound
            } else {
                Receipt::Detached
            },
            |raw| Receipt::parse(native_trim(&raw)).unwrap_or(Receipt::TransportBound),
        );
        out.pk_allowlist = get(b"pk_allowlist").map(|raw| {
            Document::parse(native_trim(&raw))
                .ok()
                .map_or_else(Vec::new, |doc| match doc.root() {
                    Value::List(values) => values
                        .iter()
                        .filter_map(|id| match doc.get(*id) {
                            Some(Value::String(raw)) => Some(native_trim(raw).to_vec()),
                            _ => None,
                        })
                        .collect(),
                    _ => vec![],
                })
        });
        out
    }
    pub fn hash(&self) -> Vec<u8> {
        let quoted = |raw: &[u8]| {
            let mut out = vec![];
            json_string(&mut out, raw);
            out
        };
        let mut fields = std::collections::BTreeMap::new();
        for (i, name) in MODE_NAMES.iter().enumerate() {
            fields.insert(name.as_bytes(), quoted(self.modes[i].as_bytes()));
        }
        fields.insert(b"proof_receipt_class", quoted(self.receipt.as_bytes()));
        fields.insert(
            b"pk_allowlist",
            self.pk_allowlist
                .as_ref()
                .map_or_else(|| b"null".to_vec(), |v| string_list(v)),
        );
        fields.insert(
            b"require_live_key_policy",
            if self.require_live_key {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            },
        );
        fields.insert(
            b"require_receipt_transport_binding",
            if self.require_transport_binding {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            },
        );
        fields.insert(b"encrypt_proof", quoted(self.encrypt_proof.as_bytes()));
        fields.insert(b"decrypt_proof", quoted(self.decrypt_proof.as_bytes()));
        let mut out = vec![b'{'];
        for (i, (key, value)) in fields.iter().enumerate() {
            if i != 0 {
                out.push(b',');
            }
            json_string(&mut out, key);
            out.push(b':');
            out.extend_from_slice(value);
        }
        out.push(b'}');
        hex::encode(Sha256::digest(out)).into_bytes()
    }
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::new(doc, "hfhe policy")?;
        let raw = MODE_NAMES
            .iter()
            .map(|name| fields.text(name))
            .collect::<Result<Vec<_>>>()?;
        let receipt = fields.text("proof_receipt_class")?;
        let pk_allowlist = fields.strings("pk_allowlist")?;
        let live = fields.flag("require_live_key_policy")?;
        let transport = fields.flag("require_receipt_transport_binding")?;
        let encrypt = fields.text("encrypt_proof")?;
        let decrypt = fields.text("decrypt_proof")?;
        let mut policy = Self::default();
        for (index, raw) in raw.iter().enumerate() {
            if let Some(raw) = raw {
                policy.modes[index] = Access::parse(raw)?;
            }
        }
        if let Some(raw) = receipt {
            policy.receipt = Receipt::parse(&raw)?;
        }
        if let Some(raw) = encrypt {
            policy.encrypt_proof = Proof::parse(&raw)?;
        }
        if let Some(raw) = decrypt {
            policy.decrypt_proof = Proof::parse(&raw)?;
        }
        policy.pk_allowlist = pk_allowlist;
        policy.require_live_key = live.unwrap_or(true);
        policy.require_transport_binding = transport.unwrap_or(false);
        Ok(policy)
    }
    pub fn snapshot(&self) -> Snapshot {
        let mut out = Snapshot::default();
        let default = Self::default();
        let prefix = b"hfhe_policy";
        for (i, name) in MODE_NAMES.iter().enumerate() {
            out.nondefault(
                prefix,
                name.as_bytes(),
                self.modes[i].as_bytes(),
                default.modes[i].as_bytes(),
            );
        }
        out.nondefault(
            prefix,
            b"proof_receipt_class",
            self.receipt.as_bytes(),
            default.receipt.as_bytes(),
        );
        out.set(
            prefix,
            b"pk_allowlist",
            self.pk_allowlist
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| string_list(v)),
        );
        out.set(
            prefix,
            b"require_live_key_policy",
            (!self.require_live_key).then(|| b"false".to_vec()),
        );
        out.set(
            prefix,
            b"require_receipt_transport_binding",
            self.require_transport_binding.then(|| b"true".to_vec()),
        );
        out.nondefault(
            prefix,
            b"encrypt_proof",
            self.encrypt_proof.as_bytes(),
            default.encrypt_proof.as_bytes(),
        );
        out.nondefault(
            prefix,
            b"decrypt_proof",
            self.decrypt_proof.as_bytes(),
            default.decrypt_proof.as_bytes(),
        );
        out
    }
}
