//! Shape admission for native encrypted transaction payloads. Cryptographic
//! verification remains part of execution under the epoch's activated rules.
use octra_hfhe::{
    cipher::Cipher, keys::PublicKey, proof::zero::ZeroProof, seeded_rng::CtrRng, Error,
};
use octra_node_protocol::{
    native_json::{Document, Value},
    program_wire::Package,
    transaction::{decode_base64, OpType, Transaction},
};
use sha2::{Digest, Sha256};
fn parsed<T>(result: Result<T, Error>) -> Result<Option<T>, Error> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_operational() => Err(e),
        Err(_) => Ok(None),
    }
}
fn prefixed(raw: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    raw.strip_prefix(prefix)
        .filter(|v| !v.is_empty())
        .and_then(|v| decode_base64(v).ok())
}
pub fn cipher(raw: &[u8]) -> Result<Option<Cipher>, Error> {
    match prefixed(raw, b"hfhe_v1|") {
        Some(value) => parsed(Cipher::from_bytes_with_policy(&value, true, true)),
        None => Ok(None),
    }
}
pub fn zero_proof(raw: &[u8]) -> Result<bool, Error> {
    if raw.is_empty() || raw.len() > 64 * 1024 {
        return Ok(false);
    }
    let Some(value) = prefixed(raw, b"zkzp_v2|").filter(|v| v.len() >= 50) else {
        return Ok(false);
    };
    Ok(parsed(ZeroProof::from_raw_bytes(&value))?.is_some())
}
fn b64_32(raw: &[u8]) -> bool {
    decode_base64(raw).is_ok_and(|v| v.len() == 32)
}
fn hex_len(raw: &[u8], len: usize) -> bool {
    raw.len() == len && raw.iter().all(u8::is_ascii_hexdigit)
}
fn range_proof(raw: &[u8]) -> bool {
    prefixed(raw, b"rp_v1|").is_some_and(|v| !v.is_empty())
}
fn string<'a>(doc: &'a Document, name: &[u8]) -> Option<&'a [u8]> {
    match doc.field(doc.root(), name) {
        Some(Value::String(v)) => Some(v),
        _ => None,
    }
}
fn integer(doc: &Document, name: &[u8]) -> Option<i64> {
    match doc.field(doc.root(), name) {
        Some(Value::Int(v)) => Some(v.get()),
        _ => None,
    }
}
fn parse(raw: &[u8]) -> Result<Option<Document>, Error> {
    match Document::parse(raw) {
        Ok(v) => Ok(Some(v)),
        Err(octra_node_protocol::native_json::Error::Allocation) => {
            Err(Error("HFHE allocation unavailable"))
        }
        Err(_) => Ok(None),
    }
}
pub fn expected_kat() -> String {
    let mut rng = CtrRng::new(&Sha256::digest(b"pvac.aes.kat.key").into(), 0);
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
    hex::encode(bytes)
}
fn encrypt_decrypt(doc: &Document) -> Result<bool, Error> {
    let (Some(ct), Some(commitment), Some(proof), Some(blinding)) = (
        string(doc, b"cipher"),
        string(doc, b"amount_commitment"),
        string(doc, b"zero_proof"),
        string(doc, b"blinding"),
    ) else {
        return Ok(false);
    };
    Ok(cipher(ct)?.is_some() && b64_32(commitment) && zero_proof(proof)? && b64_32(blinding))
}
fn stealth(doc: &Document) -> Result<bool, Error> {
    if integer(doc, b"version") != Some(5) {
        return Ok(false);
    }
    let (
        Some(delta),
        Some(commitment),
        Some(delta_proof),
        Some(balance_proof),
        Some(eph),
        Some(tag),
        Some(_amount),
        Some(claim),
        Some(amount_commitment),
    ) = (
        string(doc, b"delta_cipher"),
        string(doc, b"commitment"),
        string(doc, b"range_proof_delta"),
        string(doc, b"range_proof_balance"),
        string(doc, b"eph_pub"),
        string(doc, b"stealth_tag"),
        string(doc, b"enc_amount"),
        string(doc, b"claim_pub"),
        string(doc, b"amount_commitment"),
    )
    else {
        return Ok(false);
    };
    if !hex_len(claim, 64)
        || !hex_len(tag, 32)
        || eph.is_empty()
        || delta.is_empty()
        || delta.len() > 96 * 1024
    {
        return Ok(false);
    }
    if !cipher(delta)?.is_some_and(|c| c.is_wrapped_scalar())
        || !range_proof(delta_proof)
        || !range_proof(balance_proof)
        || !b64_32(commitment)
        || !b64_32(amount_commitment)
    {
        return Ok(false);
    }
    let proof = string(doc, b"send_zero_proof").unwrap_or_default();
    Ok(proof.is_empty() || zero_proof(proof)?)
}
fn claim(doc: &Document) -> Result<bool, Error> {
    if integer(doc, b"version") != Some(5) {
        return Ok(false);
    }
    let (Some(output), Some(ct), Some(commitment), Some(secret), Some(proof)) = (
        integer(doc, b"output_id"),
        string(doc, b"claim_cipher"),
        string(doc, b"commitment"),
        string(doc, b"claim_secret"),
        string(doc, b"zero_proof"),
    ) else {
        return Ok(false);
    };
    Ok(hex_len(secret, 64)
        && output >= 0
        && cipher(ct)?.is_some()
        && zero_proof(proof)?
        && b64_32(commitment))
}
fn key_switch(doc: &Document) -> Result<bool, Error> {
    let (Some(key), Some(kat)) = (string(doc, b"new_pubkey"), string(doc, b"aes_kat")) else {
        return Ok(false);
    };
    if kat != expected_kat().as_bytes() {
        return Ok(false);
    }
    let Ok(raw) = decode_base64(key) else {
        return Ok(false);
    };
    if raw.len() > 5_000_000
        || !(raw.len() >= 6 && raw.starts_with(b"PVAC") && (1..=5).contains(&raw[4]) && raw[5] == 1
            || raw.len() >= 5 && raw[0] == 0xec)
    {
        return Ok(false);
    }
    Ok(parsed(PublicKey::from_bytes(&raw))?.is_some())
}
pub fn encrypted_payload_ok(tx: &Transaction) -> Result<bool, Error> {
    match tx.op_type {
        OpType::ProgramDeploy => Ok(tx
            .encrypted_data
            .as_deref()
            .is_some_and(|v| Package::decode_base64(v).is_ok())),
        OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch => {
            let Some(raw) = tx.encrypted_data.as_deref() else {
                return Ok(false);
            };
            let Some(doc) = parse(raw)? else {
                return Ok(false);
            };
            match tx.op_type {
                OpType::Encrypt | OpType::Decrypt => encrypt_decrypt(&doc),
                OpType::Stealth => stealth(&doc),
                OpType::Claim => claim(&doc),
                OpType::KeySwitch => key_switch(&doc),
                _ => unreachable!(),
            }
        }
        _ => Ok(true),
    }
}
