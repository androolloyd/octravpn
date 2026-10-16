// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle read authentication and byte-framed signature subjects.
use crate::{
    native_json::{Document, Value},
    network::{public_key_safe, verify_ed25519},
    rpc::{require_address, require_string, Fault},
    transaction::{address_from_public_key, decode_base64},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub enum Gate {
    Any,
    Owner,
    PrivateOwner,
    OwnerPrivate,
    StorageOwner,
}
pub fn private_view_required(privacy: &[u8]) -> bool {
    privacy != b"public"
}
pub fn public_info_allowed(privacy: &[u8]) -> bool {
    matches!(privacy, b"public" | b"sealed")
}
pub fn check_gate(privacy: &[u8], owner: &[u8], address: &[u8], gate: Gate) -> Result<(), Fault> {
    let required = match gate {
        Gate::Any => false,
        Gate::Owner | Gate::StorageOwner => true,
        Gate::PrivateOwner => private_view_required(privacy),
        Gate::OwnerPrivate => !public_info_allowed(privacy),
    };
    if required && owner != address {
        Err(Fault::new(
            -32000,
            match gate {
                Gate::StorageOwner => {
                    b"circle owner authorization required for storage snapshot".as_slice()
                }
                _ => b"circle owner authorization required",
            },
        ))
    } else {
        Ok(())
    }
}
pub fn message(op: &[u8], circle: &[u8], address: &[u8], subject: &[u8]) -> Vec<u8> {
    let mut out = b"octra_circle_auth_v2".to_vec();
    for field in [op, circle, address, subject] {
        out.push(b'|');
        out.extend_from_slice(field.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(field);
    }
    out
}
pub fn legacy_message(op: &[u8], circle: &[u8], address: &[u8], subject: &[u8]) -> Vec<u8> {
    let mut out = [op, b"|", circle, b"|", address].concat();
    if !subject.is_empty() {
        out.push(b'|');
        out.extend_from_slice(subject);
    }
    out
}
pub fn view_subject(
    method: &[u8],
    params: &Document,
    storage: bool,
) -> Result<Vec<u8>, crate::native_json::Error> {
    let bytes = params.write(params.root(), false)?;
    Ok([
        method,
        b"|",
        hex::encode(Sha256::digest(bytes)).as_bytes(),
        if storage { b"|1" } else { b"|0" },
    ]
    .concat())
}
pub fn asset_subject(kind: &[u8], subject: &[u8]) -> Vec<u8> {
    [kind, b"|", subject].concat()
}
pub struct Auth<'a> {
    pub address: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}
impl<'a> Auth<'a> {
    pub fn parse(
        document: &'a Document,
        params: &Value,
        indexes: [usize; 3],
    ) -> Result<Self, Fault> {
        Ok(Self {
            address: require_address(document, params, indexes[0], "address")?,
            public_key: require_string(document, params, indexes[1], "public_key")?,
            signature: require_string(document, params, indexes[2], "signature")?,
        })
    }
    fn verify(&self, message: &[u8]) -> Result<&'a [u8], Fault> {
        let fail = |reason: &[u8]| Fault::new(-32000, reason);
        if self.address != address_from_public_key(self.public_key) {
            return Err(fail(b"public key does not match address"));
        }
        let public = decode_base64(self.public_key).map_err(|_| fail(b"invalid public key"))?;
        if !public_key_safe(&public) {
            return Err(fail(b"invalid public key"));
        }
        let signature = decode_base64(self.signature).map_err(|_| fail(b"invalid signature"))?;
        if verify_ed25519(&public, message, &signature) {
            Ok(self.address)
        } else {
            Err(fail(b"signature verification failed"))
        }
    }
    pub fn authenticate(
        &self,
        op: &[u8],
        circle: &[u8],
        subject: &[u8],
    ) -> Result<&'a [u8], Fault> {
        let result = self.verify(&message(op, circle, self.address, subject));
        if result.is_ok() || [op, circle, self.address].iter().any(|v| v.contains(&b'|')) {
            result
        } else {
            self.verify(&legacy_message(op, circle, self.address, subject))
        }
    }
    pub fn authorize(
        &self,
        privacy: &[u8],
        owner: &[u8],
        gate: Gate,
        op: &[u8],
        circle: &[u8],
        subject: &[u8],
    ) -> Result<&'a [u8], Fault> {
        let address = self.authenticate(op, circle, subject)?;
        check_gate(privacy, owner, address, gate)?;
        Ok(address)
    }
}
