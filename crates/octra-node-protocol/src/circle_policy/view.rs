// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native policy JSON keeps field order and arbitrary OCaml string bytes.
use super::{hfhe, key, string_list, transport};
use crate::transaction::json_string;

pub(crate) fn string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    json_string(&mut out, value);
    out
}
pub(crate) fn optional(value: Option<&[u8]>) -> Vec<u8> {
    value.map_or_else(|| b"null".to_vec(), string)
}
pub(crate) fn boolean(value: bool) -> Vec<u8> {
    if value {
        b"true".to_vec()
    } else {
        b"false".to_vec()
    }
}
pub(crate) fn epoch(value: Option<i64>) -> Vec<u8> {
    value.map_or_else(
        || b"null".to_vec(),
        |value| string(value.to_string().as_bytes()),
    )
}
fn integer(value: Option<i64>) -> Vec<u8> {
    value.map_or_else(|| b"null".to_vec(), |value| value.to_string().into_bytes())
}
pub(crate) fn object(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        out.extend_from_slice(value);
    }
    out.push(b'}');
    out
}
impl transport::Policy {
    pub fn encode(&self) -> Vec<u8> {
        let weights = self
            .weights
            .iter()
            .map(|(key, value)| (key.as_slice(), value.to_string().into_bytes()))
            .collect::<Vec<_>>();
        let codes = self.result_codes.as_ref().map_or_else(
            || b"null".to_vec(),
            |values| {
                let mut out = vec![b'['];
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(value.to_string().as_bytes());
                }
                out.push(b']');
                out
            },
        );
        object(&[
            (b"relay_mode", string(self.relay_mode.as_bytes())),
            (b"lease_class", string(self.lease.as_bytes())),
            (b"claim_strategy", string(self.replacement.as_bytes())),
            (b"claim_topology", string(self.topology.as_bytes())),
            (b"quorum_mode", string(self.quorum.as_bytes())),
            (b"ingress_strategy", string(self.ingress.as_bytes())),
            (b"quorum_threshold", integer(self.threshold)),
            (b"quorum_weight_threshold", integer(self.weight_threshold)),
            (b"max_active_claims", integer(self.max_active)),
            (b"relay_allowlist", string_list(&self.allowlist)),
            (b"relay_weights", object(&weights)),
            (b"max_claim_window_epochs", epoch(self.max_window)),
            (b"max_response_bytes", epoch(self.max_response)),
            (
                b"require_response_ciphertext",
                boolean(self.require_ciphertext),
            ),
            (b"require_external_receipt", boolean(self.require_receipt)),
            (b"accepted_result_codes", codes),
        ])
    }
}
impl hfhe::Policy {
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = hfhe::MODE_NAMES
            .iter()
            .zip(self.modes)
            .map(|(name, mode)| (name.as_bytes(), string(mode.as_bytes())))
            .collect::<Vec<_>>();
        fields.extend([
            (
                b"proof_receipt_class".as_slice(),
                string(self.receipt.as_bytes()),
            ),
            (
                b"pk_allowlist",
                self.pk_allowlist
                    .as_ref()
                    .map_or_else(|| b"null".to_vec(), |values| string_list(values)),
            ),
            (b"require_live_key_policy", boolean(self.require_live_key)),
            (
                b"require_receipt_transport_binding",
                boolean(self.require_transport_binding),
            ),
            (b"encrypt_proof", string(self.encrypt_proof.as_bytes())),
            (b"decrypt_proof", string(self.decrypt_proof.as_bytes())),
        ]);
        object(&fields)
    }
}
impl key::Policy {
    pub fn encode(&self, key: &[u8]) -> Vec<u8> {
        object(&[
            (b"key_id", string(key)),
            (b"activate_after_epoch", epoch(self.activate)),
            (b"expire_after_epoch", epoch(self.expire)),
            (b"revoked", boolean(self.revoked)),
            (b"erased", boolean(self.erased)),
        ])
    }
}
