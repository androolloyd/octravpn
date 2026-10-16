// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native compiler attestations. A valid signature does not establish program
//! safety: certificate provenance, effects and type flow must also be checked.
use crate::{
    native_base64,
    native_json::{Document, Value},
    network,
    program_trust::Keys,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("program attestation allocation unavailable")]
    Allocation,
    #[error("invalid program attestation certificate")]
    Certificate,
    #[error("invalid program attestation key id")]
    KeyId,
    #[error("program compiler attestation missing")]
    Missing,
    #[error("program compiler attestation key is not trusted")]
    UnknownKey,
    #[error("program compiler attestation signature invalid")]
    Signature,
}
pub fn valid_key_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= 64 && id.iter().all(|b| (33..=126).contains(b))
}
pub(crate) fn field<'a>(doc: &'a Document, object: &Value, name: &[u8]) -> Option<&'a Value> {
    let Value::Object(fields) = object else {
        return None;
    };
    let mut matches = fields.iter().filter(|(key, _)| key == name);
    let (_, id) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    doc.get(*id)
}
pub(crate) fn text<'a>(doc: &'a Document, object: &Value, name: &[u8]) -> Option<&'a [u8]> {
    match field(doc, object, name)? {
        Value::String(v) => Some(v),
        _ => None,
    }
}
pub fn payload(key_id: &[u8], doc: &Document) -> Result<Vec<u8>, Error> {
    if !valid_key_id(key_id) {
        return Err(Error::KeyId);
    }
    let Value::Object(fields) = doc.root() else {
        return Err(Error::Certificate);
    };
    let root = Value::Object(
        fields
            .iter()
            .filter(|(key, _)| key != b"attestation")
            .cloned()
            .collect(),
    );
    let mut message = b"octra:program_attestation:v1\0".to_vec();
    message.extend(key_id);
    message.push(0);
    message.extend(doc.write(&root, true).map_err(|error| match error {
        crate::native_json::Error::Allocation => Error::Allocation,
        crate::native_json::Error::Syntax(_) => Error::Certificate,
    })?);
    Ok(message)
}
/// Sign a compiler certificate with an already parsed Ed25519 signing key.
/// All prior attestation fields are replaced; other field order is preserved.
pub fn attach(
    key_id: &[u8],
    private_key: &ed25519_dalek::SigningKey,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::transaction::json_string;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::Signer;
    if !valid_key_id(key_id) {
        return Err(Error::KeyId);
    }
    let doc = Document::parse(raw).map_err(|error| match error {
        crate::native_json::Error::Allocation => Error::Allocation,
        crate::native_json::Error::Syntax(_) => Error::Certificate,
    })?;
    let message = payload(key_id, &doc)?;
    let Value::Object(fields) = doc.root() else {
        return Err(Error::Certificate);
    };
    let signature = private_key.sign(&message);
    let mut out = vec![b'{'];
    for (key, id) in fields.iter().filter(|(key, _)| key != b"attestation") {
        if out.len() > 1 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        let value = doc.get(*id).ok_or(Error::Certificate)?;
        out.extend(doc.write(value, false).map_err(|error| match error {
            crate::native_json::Error::Allocation => Error::Allocation,
            crate::native_json::Error::Syntax(_) => Error::Certificate,
        })?);
    }
    if out.len() > 1 {
        out.push(b',');
    }
    out.extend_from_slice(
        b"\"attestation\":{\"schema\":\"octra_program_attestation_v1\",\"key_id\":",
    );
    json_string(&mut out, key_id);
    out.extend_from_slice(b",\"signature\":");
    json_string(&mut out, STANDARD.encode(signature.to_bytes()).as_bytes());
    out.extend_from_slice(b"}}");
    Ok(out)
}
pub fn verify(trusted: &Keys, doc: &Document) -> Result<(), Error> {
    let Value::Object(fields) = doc.root() else {
        return Err(Error::Certificate);
    };
    let count = fields
        .iter()
        .filter(|(key, _)| key == b"attestation")
        .count();
    if count == 0 {
        return Err(Error::Missing);
    }
    let proof = field(doc, doc.root(), b"attestation")
        .filter(|v| matches!(v, Value::Object(_)))
        .ok_or(Error::Signature)?;
    let schema = text(doc, proof, b"schema").ok_or(Error::Signature)?;
    let id = text(doc, proof, b"key_id").ok_or(Error::Signature)?;
    let signature = text(doc, proof, b"signature").ok_or(Error::Signature)?;
    if schema != b"octra_program_attestation_v1" || !valid_key_id(id) {
        return Err(Error::Signature);
    }
    let message = payload(id, doc)?;
    let key = trusted.public_key(id).ok_or(Error::UnknownKey)?;
    let signature = native_base64::decode(signature).map_err(|_| Error::Signature)?;
    if signature.len() != 64 || !network::verify_ed25519(key, &message, &signature) {
        return Err(Error::Signature);
    }
    Ok(())
}
