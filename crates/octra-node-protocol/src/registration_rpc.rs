// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native local queue authorization and BFT registration compatibility routes.
use crate::{
    native_base64, native_exception,
    native_json::{Document, Value},
    network::{public_key_safe, verify_ed25519},
    rpc::{self, Fault},
    transaction::{address_from_public_key, json_string},
};

pub struct Removal {
    pub hash: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}
impl Removal {
    pub fn parse(doc: &Document, params: &Value) -> Result<Self, Fault> {
        Ok(Self {
            hash: rpc::require_hash(doc, params, 0, "tx_hash")?.to_vec(),
            signature: rpc::require_string(doc, params, 1, "signature")?.to_vec(),
            public_key: rpc::require_string(doc, params, 2, "pubkey")?.to_vec(),
        })
    }
    pub fn authorize(&self, sender: &[u8]) -> Result<(), Fault> {
        let message = [b"staging_remove|".as_slice(), &self.hash].concat();
        verify_address_signature(
            sender,
            &self.public_key,
            &self.signature,
            &message,
            b"pubkey does not match tx sender",
        )
    }
    pub fn response(&self) -> Vec<u8> {
        let mut raw = b"{\"removed\":true,\"tx_hash\":".to_vec();
        json_string(&mut raw, &self.hash);
        raw.push(b'}');
        raw
    }
}
pub fn verify_address_signature(
    address: &[u8],
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    mismatch: &[u8],
) -> Result<(), Fault> {
    let fail = |reason: &[u8]| Fault::new(-32000, reason);
    if address_from_public_key(public_key) != address {
        return Err(fail(mismatch));
    }
    let public = native_base64::decode(public_key).map_err(|_| fail(b"invalid pubkey b64"))?;
    if !public_key_safe(&public) {
        return Err(fail(b"invalid pubkey"));
    }
    let signature = native_base64::decode(signature).map_err(|_| fail(b"invalid signature b64"))?;
    if !verify_ed25519(&public, message, &signature) {
        return Err(fail(b"signature verification failed"));
    }
    Ok(())
}
pub fn staging_missing() -> Fault {
    Fault::new(112, b"not found").string_data(b"tx not in staging")
}

/// Native BFT ignores the complete registration request, including malformed
/// address/key/signature fields. Canonical transactions carry their own key.
pub fn public_key_bft(doc: &Document, params: &Value) -> Vec<u8> {
    let address = rpc::require_address(doc, params, 0, "address").unwrap_or(b"");
    let mut raw = b"{\"ok\":true,\"address\":".to_vec();
    json_string(&mut raw, address);
    raw.extend_from_slice(b",\"status\":\"ignored_in_bft\",\"note\":\"public key registration is a no-op in BFT mode; tx.public_key must be carried in canonical transactions\"}");
    raw
}

/// An authenticated native Single registration request. This grants no storage
/// authority: the host updates only an existing, temporary Ledger account.
pub struct PublicKey {
    address: Vec<u8>,
    public_key: Vec<u8>,
}
impl PublicKey {
    pub fn address(&self) -> &[u8] {
        &self.address
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn parse(doc: &Document, params: &Value) -> Result<Self, Fault> {
        let address = rpc::require_address(doc, params, 0, "address")?;
        let public_key = rpc::require_string(doc, params, 1, "public_key")?;
        let signature = rpc::require_string(doc, params, 2, "signature")?;
        // Native checks both decoded lengths before address correspondence or
        // curve/signature validity; preserve that observable error ordering.
        if !native_base64::decode(public_key).is_ok_and(|raw| raw.len() == 32)
            || !native_base64::decode(signature).is_ok_and(|raw| raw.len() == 64)
        {
            return Err(Fault::new(-32000, b"invalid key or signature length"));
        }
        let message = [b"register_pubkey:".as_slice(), address].concat();
        verify_address_signature(
            address,
            public_key,
            signature,
            &message,
            b"public key does not match address",
        )?;
        Ok(Self {
            address: address.to_vec(),
            public_key: public_key.to_vec(),
        })
    }
    pub fn response(&self) -> Vec<u8> {
        let mut raw = b"{\"ok\":true,\"address\":".to_vec();
        json_string(&mut raw, &self.address);
        raw.push(b'}');
        raw
    }
}

pub struct Pvac {
    pub address: Vec<u8>,
    pub incoming: Vec<u8>,
}
#[derive(Clone, Copy)]
pub enum Existing {
    Absent,
    Same,
    Different,
}
impl Pvac {
    pub fn parse(doc: &Document, params: &Value, expected_kat: &[u8]) -> Result<Self, Fault> {
        let address = rpc::require_address(doc, params, 0, "address")?.to_vec();
        let encoded = rpc::require_string(doc, params, 1, "pubkey_blob")?;
        let incoming = native_base64::decode(encoded).map_err(|error| {
            Fault::new(105, b"malformed transaction").string_data(
                native_exception::string_argument(
                    b"Invalid_argument",
                    error.to_string().as_bytes(),
                ),
            )
        })?;
        if incoming.len() > 5_000_000 {
            return Err(Fault::new(105, b"malformed transaction")
                .string_data(b"pvac pubkey too large (max 5MB)"));
        }
        if let Some(Value::String(got)) = rpc::param(doc, params, 4) {
            if got != expected_kat {
                return Err(Fault::new(
                    -32000,
                    b"AES implementation incompatible: KAT mismatch",
                ));
            }
        }
        Ok(Self { address, incoming })
    }
    pub fn response(&self, existing: Existing) -> Result<Vec<u8>, Fault> {
        match existing {
            Existing::Same => {
                let mut raw = b"{\"address\":".to_vec();
                json_string(&mut raw, &self.address);
                raw.extend_from_slice(b",\"status\":\"already_registered\",\"registration\":\"canonical_key_switch\"}");
                Ok(raw)
            }
            Existing::Different => Err(Fault::new(
                -32000,
                b"pvac pubkey already registered: use key_switch transaction to rotate",
            )),
            Existing::Absent => Err(Fault::new(
                -32000,
                b"pvac pubkey registration must be submitted as a canonical key_switch transaction",
            )),
        }
    }
}
