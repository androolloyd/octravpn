// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native archive identity proofs, including legacy signed transaction records.
use crate::{
    native_json::{Document, Value},
    transaction::{
        address_from_public_key, decode_base64, json_string, Error as TransactionError, OpType,
        Transaction,
    },
};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    Exact,
    Signed,
    SignedOperation,
}
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Json(#[from] crate::native_json::Error),
    #[error("{0}")]
    Invalid(String),
}
impl From<TransactionError> for Error {
    fn from(error: TransactionError) -> Self {
        Self::Invalid(error.0)
    }
}
#[derive(Clone, Debug)]
pub struct Archive {
    tx: Transaction,
    proof: Proof,
    raw: Vec<u8>,
    proof_bytes: Vec<u8>,
    carried_public_key: Option<Vec<u8>>,
}
fn hash_matches(hash: &[u8], bytes: &[u8]) -> bool {
    hex::encode(Sha256::digest(bytes)).as_bytes() == hash
}
fn shape(document: &Document, operation: bool) -> bool {
    const REQUIRED: &[&[u8]] = &[
        b"from",
        b"to_",
        b"amount",
        b"nonce",
        b"ou",
        b"timestamp",
        b"signature",
    ];
    let Value::Object(fields) = document.root() else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    for (key, _) in fields {
        if !seen.insert(key.as_slice())
            || !(REQUIRED.contains(&key.as_slice())
                || [b"public_key".as_slice(), b"message", b"op_type"].contains(&key.as_slice())
                || operation && key == b"encrypted_data")
        {
            return false;
        }
    }
    if !REQUIRED.iter().all(|key| seen.contains(key))
        || operation && !seen.contains(b"op_type".as_slice())
    {
        return false;
    }
    for key in [b"public_key".as_slice(), b"message"]
        .into_iter()
        .chain(operation.then_some(b"encrypted_data".as_slice()))
    {
        if !matches!(
            document.field(document.root(), key),
            None | Some(Value::Null | Value::String(_))
        ) {
            return false;
        }
    }
    operation
        || matches!(
            document.field(document.root(), b"op_type"),
            None | Some(Value::Null)
        )
        || matches!(document.field(document.root(),b"op_type"),Some(Value::String(value)) if value==b"standard")
}
pub fn signed_bytes(tx: &Transaction) -> Result<Vec<u8>, TransactionError> {
    let mut bytes = tx.common_json()?;
    bytes.push(b'}');
    Ok(bytes)
}
pub fn operation_bytes(tx: &Transaction) -> Result<Vec<u8>, TransactionError> {
    let mut bytes = tx.common_json()?;
    tx.append_op(&mut bytes);
    bytes.push(b'}');
    Ok(bytes)
}
impl Archive {
    pub fn decode(hash: &[u8], raw: &[u8]) -> Result<Self, Error> {
        let document = Document::parse(raw)?;
        let mut tx = Transaction::from_document(&document)?;
        let exact_hash = hex::encode(tx.hash()?);
        let (proof, proof_bytes) = if exact_hash.as_bytes() == hash {
            if tx.to_json_bytes()? != raw {
                return Err(Error::Invalid("transaction encoding mismatch".into()));
            }
            (Proof::Exact, raw.to_vec())
        } else {
            let signed = signed_bytes(&tx)?;
            if hash_matches(hash, &signed) {
                if !shape(&document, false) {
                    return Err(Error::Invalid("signed transaction shape is invalid".into()));
                }
                (Proof::Signed, signed)
            } else {
                let operation = operation_bytes(&tx)?;
                if !hash_matches(hash, &operation) {
                    return Err(Error::Invalid("transaction hash mismatch".into()));
                }
                if !shape(&document, true) {
                    return Err(Error::Invalid("signed operation shape is invalid".into()));
                }
                (Proof::SignedOperation, operation)
            }
        };
        let carried_public_key = tx.public_key.clone();
        if proof != Proof::Exact {
            tx.public_key = None;
            tx.message = None;
            tx.encrypted_data = None;
            if proof == Proof::Signed {
                tx.op_type = OpType::Standard;
            }
        }
        Ok(Self {
            tx,
            proof,
            raw: raw.to_vec(),
            proof_bytes,
            carried_public_key,
        })
    }
    pub const fn transaction(&self) -> &Transaction {
        &self.tx
    }
    pub const fn proof(&self) -> Proof {
        self.proof
    }
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
    /// The trusted account key takes precedence over an archived carried key.
    /// Exact archives are authenticated by their canonical history hash binding;
    /// legacy archives require the historical signature over their proof bytes.
    pub fn verify(&self, account_public_key: Option<&[u8]>) -> Result<(), Error> {
        if self.proof == Proof::Exact {
            return Ok(());
        }
        let key = account_public_key
            .or(self.carried_public_key.as_deref())
            .ok_or_else(|| Error::Invalid("signed transaction public key is unavailable".into()))?;
        if address_from_public_key(key) != self.tx.from {
            return Err(Error::Invalid(
                "signed transaction public key does not match sender".into(),
            ));
        }
        let encoding_error =
            || Error::Invalid("signed transaction signature encoding is invalid".into());
        let public = decode_base64(key).map_err(|_| encoding_error())?;
        let signature = decode_base64(&self.tx.signature).map_err(|_| encoding_error())?;
        if !crate::network::public_key_safe(&public) {
            return Err(Error::Invalid(
                "signed transaction public key is invalid".into(),
            ));
        }
        if !crate::network::verify_ed25519(&public, &self.proof_bytes, &signature) {
            return Err(Error::Invalid(
                "signed transaction signature is invalid".into(),
            ));
        }
        Ok(())
    }
    pub fn visible_json(&self) -> Result<Vec<u8>, TransactionError> {
        if self.proof == Proof::Exact {
            return Ok(self.raw.clone());
        }
        let mut bytes = self.tx.common_json()?;
        bytes.extend_from_slice(b",\"signature\":");
        json_string(&mut bytes, &self.tx.signature);
        if self.proof == Proof::SignedOperation {
            self.tx.append_op(&mut bytes);
        }
        bytes.push(b'}');
        Ok(bytes)
    }
}
