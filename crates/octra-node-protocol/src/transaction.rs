// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native transaction identity and envelope validation. Raw OCaml strings are bytes;
//! admission, rule activation, OU scheduling and execution are separate boundaries.
use base64::Engine;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub String);

/// The signed 63-bit OCaml integer used for account and transaction nonces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce(i64);
impl Nonce {
    pub const MIN: Self = Self(-(1_i64 << 62));
    pub const MAX: Self = Self((1_i64 << 62) - 1);
    pub fn new(value: i64) -> Result<Self, Error> {
        if (Self::MIN.0..=Self::MAX.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(Error("nonce is outside the native int63 range".into()))
        }
    }
    pub const fn get(self) -> i64 {
        self.0
    }
    pub const fn successor(self) -> Self {
        if self.0 == Self::MAX.0 {
            Self::MIN
        } else {
            Self(self.0 + 1)
        }
    }
}
macro_rules! operations {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum OpType { $($variant),+ }
        impl OpType {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            #[allow(clippy::string_lit_as_bytes)]
            pub fn parse(value: &[u8]) -> Result<Self, Error> {
                $(if value == $name.as_bytes() { return Ok(Self::$variant); })+
                Err(Error(format!("unsupported op_type: {}", String::from_utf8_lossy(value))))
            }
        }
    }
}
operations! {
    Standard => "standard", Encrypt => "encrypt", Decrypt => "decrypt", Private => "private",
    ContractDeploy => "deploy", ProgramDeploy => "program_deploy", ContractCall => "call",
    ProgramExec => "program_exec", MultiExec => "multi_exec", ContractUpgrade => "upgrade",
    CircleDeploy => "deploy_circle", CircleProgramUpdate => "circle_program_update",
    CircleAssetPut => "circle_asset_put", CircleAssetPutEncrypted => "circle_asset_put_encrypted",
    CircleSealedSlotPut => "circle_sealed_slot_put", CircleSlotPolicyPut => "circle_slot_policy_put",
    CircleStateDescriptorPut => "circle_state_descriptor_put", CircleBalanceCellPut => "circle_balance_cell_put",
    CircleRegisterCellPut => "circle_register_cell_put", CircleTransportPolicyPut => "circle_transport_policy_put",
    CircleHfhePolicyPut => "circle_hfhe_policy_put", CircleKeyPolicyPut => "circle_key_policy_put",
    CircleKeyGrant => "circle_key_grant", CircleKeyExtend => "circle_key_extend",
    CircleKeyRevoke => "circle_key_revoke", CircleKeyErase => "circle_key_erase",
    CircleOutboxOpen => "circle_outbox_open", CircleRelayClaim => "circle_relay_claim",
    CircleRelayCancel => "circle_relay_cancel", CircleIngressCommit => "circle_ingress_commit",
    CircleCall => "circle_call", ValidatorSetUpdate => "validator_set_update", ValidatorReady => "validator_ready",
    ValidatorBond => "validator_bond", ValidatorExit => "validator_exit", ValidatorWithdraw => "validator_withdraw",
    ValidatorEvidence => "validator_evidence", Stealth => "stealth", Claim => "claim", Recrypt => "recrypt",
    KeySwitch => "key_switch", Op01Burn => "op01_burn", ComputeFund => "compute_fund",
    ComputeReturn => "compute_return", ComputeSettle => "compute_settle",
}

#[derive(Clone, Debug, PartialEq)]
pub struct Transaction {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: BigInt,
    pub nonce: Nonce,
    pub ou: BigInt,
    pub timestamp: f64,
    pub signature: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub message: Option<Vec<u8>>,
    pub op_type: OpType,
    pub encrypted_data: Option<Vec<u8>>,
}

/// Append a native Yojson byte string without UTF-8 replacement.
pub fn json_string(out: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8] = b"0123456789abcdef";
    out.push(b'"');
    for &byte in value {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            8 => out.extend_from_slice(b"\\b"),
            12 => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=31 | 127 => out.extend_from_slice(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ]),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}
pub(crate) fn json_optional(out: &mut Vec<u8>, value: Option<&[u8]>) {
    if let Some(value) = value {
        json_string(out, value);
    } else {
        out.extend_from_slice(b"null");
    }
}

// Yojson uses C's %.16g, retries %.17g only if the first representation loses bits,
// and appends .0 to integer-looking floats. Rust's shortest float format differs.
pub(crate) fn general_float(value: f64, precision: usize) -> String {
    let scientific = format!("{value:.digits$e}", digits = precision - 1);
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific float");
    let exponent: i32 = exponent.parse().expect("scientific exponent");
    let (sign, magnitude) = mantissa
        .strip_prefix('-')
        .map_or(("", mantissa), |rest| ("-", rest));
    if exponent < -4 || exponent >= precision as i32 {
        let magnitude = magnitude.trim_end_matches('0').trim_end_matches('.');
        return format!("{sign}{magnitude}e{exponent:+03}");
    }
    let digits: String = magnitude.chars().filter(|&ch| ch != '.').collect();
    let position = exponent + 1;
    let mut out = String::from(sign);
    if position <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-position) as usize));
        out.push_str(&digits);
    } else if position as usize >= digits.len() {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n('0', position as usize - digits.len()));
    } else {
        out.push_str(&digits[..position as usize]);
        out.push('.');
        out.push_str(&digits[position as usize..]);
    }
    if out.contains('.') {
        out = out.trim_end_matches('0').trim_end_matches('.').to_owned();
    }
    out
}
/// Exact native Yojson float text. Non-finite values cannot be serialized.
pub fn native_float(value: f64) -> Result<String, Error> {
    if value.is_nan() {
        return Err(Error("NaN value not allowed in standard JSON".into()));
    }
    if value.is_infinite() {
        return Err(Error(
            if value.is_sign_negative() {
                "-Infinity value not allowed in standard JSON"
            } else {
                "Infinity value not allowed in standard JSON"
            }
            .into(),
        ));
    }
    let mut out = general_float(value, 16);
    if out.parse::<f64>().ok() != Some(value) {
        out = general_float(value, 17);
    }
    if out.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        out.push_str(".0");
    }
    Ok(out)
}
impl Transaction {
    pub(crate) fn common_json(&self) -> Result<Vec<u8>, Error> {
        let mut out = b"{\"from\":".to_vec();
        json_string(&mut out, &self.from);
        out.extend_from_slice(b",\"to_\":");
        json_string(&mut out, &self.to);
        out.extend_from_slice(b",\"amount\":");
        json_string(&mut out, self.amount.to_string().as_bytes());
        out.extend_from_slice(b",\"nonce\":");
        out.extend_from_slice(self.nonce.get().to_string().as_bytes());
        out.extend_from_slice(b",\"ou\":");
        json_string(&mut out, self.ou.to_string().as_bytes());
        out.extend_from_slice(b",\"timestamp\":");
        out.extend_from_slice(native_float(self.timestamp)?.as_bytes());
        Ok(out)
    }
    pub(crate) fn append_op(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b",\"op_type\":");
        json_string(out, self.op_type.as_str().as_bytes());
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.common_json()?;
        self.append_op(&mut out);
        for (name, value) in [
            (b",\"encrypted_data\":".as_slice(), &self.encrypted_data),
            (b",\"message\":".as_slice(), &self.message),
        ] {
            if let Some(value) = value {
                out.extend_from_slice(name);
                json_string(&mut out, value);
            }
        }
        out.push(b'}');
        Ok(out)
    }
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.common_json()?;
        out.extend_from_slice(b",\"signature\":");
        json_string(&mut out, &self.signature);
        self.append_op(&mut out);
        for (name, value) in [
            (b",\"public_key\":".as_slice(), &self.public_key),
            (b",\"message\":".as_slice(), &self.message),
            (b",\"encrypted_data\":".as_slice(), &self.encrypted_data),
        ] {
            if let Some(value) = value {
                out.extend_from_slice(name);
                json_string(&mut out, value);
            }
        }
        out.push(b'}');
        Ok(out)
    }
    /// Canonical preimage of Transaction.hash, including null optional fields.
    pub fn identity_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.common_json()?;
        out.extend_from_slice(b",\"signature\":");
        json_string(&mut out, &self.signature);
        self.append_op(&mut out);
        for (name, value) in [
            (b",\"public_key\":".as_slice(), &self.public_key),
            (b",\"message\":".as_slice(), &self.message),
            (b",\"encrypted_data\":".as_slice(), &self.encrypted_data),
        ] {
            out.extend_from_slice(name);
            json_optional(&mut out, value.as_deref());
        }
        out.push(b'}');
        Ok(out)
    }
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        Ok(Sha256::digest(self.identity_bytes()?).into())
    }
    pub fn compare_consensus(&self, other: &Self) -> Result<Ordering, Error> {
        let result = self
            .from
            .cmp(&other.from)
            .then_with(|| self.nonce.cmp(&other.nonce));
        if result == Ordering::Equal {
            Ok(self.hash()?.cmp(&other.hash()?))
        } else {
            Ok(result)
        }
    }
    pub fn verify(&self, public_key: &[u8]) -> bool {
        let (Ok(public), Ok(signature)) =
            (decode_base64(public_key), decode_base64(&self.signature))
        else {
            return false;
        };
        self.signing_bytes()
            .is_ok_and(|message| crate::network::verify_ed25519(&public, &message, &signature))
    }
}

pub fn decode_base64(value: &[u8]) -> Result<Vec<u8>, crate::native_base64::Error> {
    crate::native_base64::decode(value)
}
pub fn address_from_public_key(encoded: &[u8]) -> Vec<u8> {
    let Ok(raw) = decode_base64(encoded) else {
        return Vec::new();
    };
    let body = bs58::encode(Sha256::digest(&raw)).into_string();
    format!(
        "oct{}{body}",
        "1".repeat(44_usize.saturating_sub(body.len()))
    )
    .into_bytes()
}
pub fn is_valid_address(address: &[u8]) -> bool {
    address.len() == 47
        && address.starts_with(b"oct")
        && address[3..].iter().all(|byte| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(byte)
        })
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct EnvelopeError {
    pub tag: &'static str,
    pub reason: String,
}
fn envelope_error(tag: &'static str, reason: impl Into<String>) -> EnvelopeError {
    EnvelopeError {
        tag,
        reason: reason.into(),
    }
}
fn decode_envelope(value: &[u8], size: usize, field: &str) -> Result<Vec<u8>, EnvelopeError> {
    if value.len() > size.div_ceil(3) * 4 {
        return Err(envelope_error(
            "tx_too_large",
            format!("{field} encoding is too long"),
        ));
    }
    decode_base64(value)
        .ok()
        .filter(|raw| raw.len() == size)
        .ok_or_else(|| envelope_error("invalid_signature", format!("{field} encoding is invalid")))
}
/// Normalize only the envelope. This deliberately does not authenticate the signature.
pub fn normalize_envelope(
    tx: &Transaction,
    sender_key: Option<&[u8]>,
) -> Result<Transaction, EnvelopeError> {
    use base64::engine::general_purpose::STANDARD;
    if tx.public_key.as_ref().is_some_and(|key| key.len() > 44) {
        return Err(envelope_error(
            "tx_too_large",
            "public key encoding is too long",
        ));
    }
    let sender_key = sender_key
        .ok_or_else(|| envelope_error("invalid_signature", "sender public key is missing"))?;
    let key = decode_envelope(sender_key, 32, "public key")?;
    let public = STANDARD.encode(&key).into_bytes();
    if tx.from != address_from_public_key(&public) {
        return Err(envelope_error(
            "invalid_address",
            "sender public key does not match address",
        ));
    }
    if tx.op_type == OpType::ValidatorBond {
        let carried = tx
            .public_key
            .as_ref()
            .ok_or_else(|| envelope_error("invalid_signature", "bond public key is missing"))?;
        if decode_envelope(carried, 32, "bond public key")? != key {
            return Err(envelope_error(
                "invalid_signature",
                "bond public key differs from sender key",
            ));
        }
    }
    let signature = decode_envelope(&tx.signature, 64, "signature")?;
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    if signature[32..].iter().rev().cmp(ORDER.iter().rev()) != Ordering::Less {
        return Err(envelope_error(
            "invalid_signature",
            "signature scalar is out of range",
        ));
    }
    let mut normalized = tx.clone();
    normalized.public_key = Some(public);
    normalized.signature = STANDARD.encode(signature).into_bytes();
    Ok(normalized)
}
pub fn check_envelope(tx: &Transaction) -> Result<(), Error> {
    let normalized =
        normalize_envelope(tx, tx.public_key.as_deref()).map_err(|e| Error(e.reason))?;
    if tx.signature != normalized.signature {
        return Err(Error("signature encoding is not normalized".into()));
    }
    if tx.public_key != normalized.public_key {
        return Err(Error("public key encoding is not normalized".into()));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleMode {
    Prior,
    Active,
}
pub fn check_envelopes(mode: RuleMode, transactions: &[Transaction]) -> Result<(), Error> {
    if mode == RuleMode::Prior {
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for tx in transactions {
        check_envelope(tx)?;
        if !seen.insert((&tx.from, tx.nonce)) {
            return Err(Error("duplicate sender nonce".into()));
        }
    }
    Ok(())
}
pub fn check_compute(
    mode: RuleMode,
    settle: RuleMode,
    transactions: &[Transaction],
) -> Result<(), Error> {
    if mode == RuleMode::Prior
        && transactions.iter().any(|tx| {
            matches!(
                tx.op_type,
                OpType::ComputeFund | OpType::ComputeReturn | OpType::ComputeSettle
            )
        })
    {
        return Err(Error("compute transfers not active".into()));
    }
    if settle == RuleMode::Prior
        && transactions
            .iter()
            .any(|tx| tx.op_type == OpType::ComputeSettle)
    {
        return Err(Error("compute settlement not active".into()));
    }
    Ok(())
}

impl Transaction {
    pub fn from_document(document: &crate::native_json::Document) -> Result<Self, Error> {
        Self::from_value(document, document.root())
    }
    #[allow(clippy::cast_precision_loss)] // OCaml float_of_int uses the same IEEE-754 rounding.
    pub(crate) fn from_value(
        document: &crate::native_json::Document,
        value: &crate::native_json::Value,
    ) -> Result<Self, Error> {
        use crate::native_json::Value;
        use num_traits::Signed;
        if !matches!(value, Value::Object(_)) {
            return Err(Error("Expected JSON object".into()));
        }
        let malformed = || Error("Malformed JSON: missing or invalid fields".into());
        let field = |name: &[u8]| document.field(value, name);
        let string = |name: &[u8]| match field(name) {
            Some(Value::String(value)) => Some(value.clone()),
            _ => None,
        };
        let amount = |name: &[u8]| {
            match field(name) {
                Some(Value::String(value)) => parse_native_integer(value),
                Some(Value::Int(value)) => Some(value.get().into()),
                _ => None,
            }
            .filter(|value| !value.is_negative())
        };
        Ok(Self {
            from: string(b"from").ok_or_else(malformed)?,
            to: string(b"to_").ok_or_else(malformed)?,
            amount: amount(b"amount").ok_or_else(malformed)?,
            nonce: match field(b"nonce") {
                Some(Value::Int(value)) => *value,
                _ => return Err(malformed()),
            },
            ou: amount(b"ou").ok_or_else(malformed)?,
            timestamp: match field(b"timestamp") {
                Some(Value::Float(value)) => *value,
                Some(Value::Int(value)) => value.get() as f64,
                _ => return Err(malformed()),
            },
            signature: string(b"signature").ok_or_else(malformed)?,
            public_key: string(b"public_key"),
            message: string(b"message"),
            encrypted_data: string(b"encrypted_data"),
            op_type: match field(b"op_type") {
                Some(Value::String(value)) => OpType::parse(value).map_err(|_| malformed())?,
                _ => OpType::Standard,
            },
        })
    }
}

pub use crate::native_integer::{
    parse_int64 as parse_native_int64, parse_integer as parse_native_integer,
};
pub fn parse_native_int(raw: &[u8]) -> Option<Nonce> {
    crate::native_integer::parse_int63(raw).map(Nonce)
}
