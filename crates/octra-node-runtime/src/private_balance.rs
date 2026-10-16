// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Verified encrypt/decrypt ledger transitions. Epoch admission (caps, bound
//! keys, KAT and receipts) belongs to the caller; no unchecked plan is exposed.
use crate::private_crypto::{self as crypto, AmountProof, ResultPolicy};
use num_bigint::BigInt;
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    native_json::{Document, Value},
    state::Ledger,
    transaction::{OpType, RuleMode, Transaction},
};

pub(crate) use crate::private_error::{check, failure};
pub use crate::private_error::{Error, Failure};
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub fields: RuleMode,
    pub strict: bool,
    pub math: ScalarRule,
    pub result: ResultPolicy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Encrypt,
    Decrypt,
}
impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt_balance_failed",
            Self::Decrypt => "decrypt_cipher_failed",
        }
    }
    fn of(tx: &Transaction) -> Result<Self, Error> {
        match tx.op_type {
            OpType::Encrypt => Ok(Self::Encrypt),
            OpType::Decrypt => Ok(Self::Decrypt),
            _ => Err(Error::Unavailable("private balance route mismatch".into())),
        }
    }
}
struct Payload {
    cipher: Vec<u8>,
    commitment: Vec<u8>,
    proof: Vec<u8>,
    blinding: Vec<u8>,
    range: Option<Vec<u8>>,
}
fn field(
    doc: &Document,
    name: &str,
    unique: bool,
    optional: bool,
) -> Result<Option<Vec<u8>>, String> {
    let Value::Object(fields) = doc.root() else {
        return Err("encrypted_data must be a JSON object".into());
    };
    if unique
        && fields
            .iter()
            .filter(|(key, _)| key == name.as_bytes())
            .count()
            > 1
    {
        return Err(format!("duplicate {name}"));
    }
    match doc.field(doc.root(), name.as_bytes()) {
        None | Some(Value::Null) if optional => Ok(None),
        None | Some(Value::Null) => Err(format!("missing {name}")),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(format!("{name} must be a string")),
    }
}
fn payload(tx: &Transaction, operation: Operation, mode: RuleMode) -> Result<Payload, Error> {
    let op = operation.name();
    let malformed = format!("{op}: malformed encrypted_data");
    let Some(raw) = &tx.encrypted_data else {
        return Err(failure(
            "malformed_transaction",
            format!("{op}: missing encrypted_data"),
            Some(malformed.into_bytes()),
        ));
    };
    let doc = Document::parse(raw).map_err(|e| match e {
        octra_node_protocol::native_json::Error::Allocation => Error::Unavailable(e.to_string()),
        octra_node_protocol::native_json::Error::Syntax(_) => failure(
            "malformed_transaction",
            &malformed,
            Some(malformed.as_bytes().to_vec()),
        ),
    })?;
    let parse = || {
        let required = |name| {
            field(&doc, name, mode == RuleMode::Active, false).map(|v| v.expect("required field"))
        };
        Ok::<_, String>(Payload {
            cipher: required("cipher")?,
            commitment: required("amount_commitment")?,
            proof: required("zero_proof")?,
            blinding: required("blinding")?,
            range: if operation == Operation::Decrypt {
                field(&doc, "range_proof_balance", mode == RuleMode::Active, true)?
            } else {
                None
            },
        })
    };
    parse().map_err(|e| {
        failure(
            "malformed_transaction",
            format!("{op}: cannot parse encrypted_data: {e}"),
            Some(malformed.into_bytes()),
        )
    })
}
fn current<'a>(ledger: &'a Ledger, tx: &Transaction, op: Operation) -> Result<&'a [u8], Error> {
    ledger
        .accounts()
        .get(&tx.from)
        .map(|a| a.encrypted_balance.as_deref().unwrap_or(b"0"))
        .ok_or_else(|| failure(op.tag(), "account not found", None))
}
/// Proof-verified balance plan, or a historical plan matched to a certified
/// transition by the epoch host. Private fields prevent forged applications.
pub struct Verified {
    operation: Operation,
    transaction: [u8; 32],
    current: Vec<u8>,
    next: Vec<u8>,
}
impl Verified {
    pub fn current_cipher(&self) -> &[u8] {
        &self.current
    }
    pub fn next_cipher(&self) -> &[u8] {
        &self.next
    }
    pub fn transition_hash(&self) -> String {
        let tag = match self.operation {
            Operation::Encrypt => b"octra:private_transition:encrypt".as_slice(),
            Operation::Decrypt => b"octra:private_transition:decrypt".as_slice(),
        };
        crypto::transition_hash(tag, &[&self.current, &self.next])
    }
    /// Recheck state before charging. Every rejected application restores nonce,
    /// spent-nonce set, public supply, dirty addresses and account ciphertext.
    pub fn apply(&self, ledger: &mut Ledger, tx: &Transaction) -> Result<(), Error> {
        if tx.hash().map_err(|e| Error::Unavailable(e.to_string()))? != self.transaction {
            return Err(Error::Unavailable(
                "private balance plan transaction mismatch".into(),
            ));
        }
        if current(ledger, tx, self.operation)? != self.current {
            return Err(failure(
                self.operation.tag(),
                "encrypted balance changed during proof verification",
                None,
            ));
        }
        ledger.begin_journal();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let cost = if self.operation == Operation::Encrypt {
                &tx.amount + &tx.ou
            } else {
                tx.ou.clone()
            };
            ledger
                .debit(&tx.from, &cost, tx.nonce, None)
                .map_err(|e| failure("insufficient_balance", e.0, None))?;
            if self.operation == Operation::Decrypt {
                ledger
                    .credit(&tx.from, &tx.amount, None)
                    .map_err(|e| failure("supply_violation", e.0, None))?;
            }
            ledger.update_encrypted_balance(&tx.from, self.next.clone());
            Ok(())
        }));
        match result {
            Ok(Ok(())) => ledger
                .commit_journal()
                .map_err(|e| Error::Unavailable(e.to_string())),
            Ok(Err(e)) => {
                ledger.abort_journal();
                Err(e)
            }
            Err(e) => {
                ledger.abort_journal();
                std::panic::resume_unwind(e)
            }
        }
    }
}
pub fn verify(
    ledger: &Ledger,
    tx: &Transaction,
    pubkey: Option<&[u8]>,
    profile: Profile,
) -> Result<Verified, Error> {
    verify_with_key(ledger, tx, profile, || Ok(pubkey))
}
/// Load a bound key only after native payload checks. This always verifies
/// proofs; a caller-supplied receipt cannot select the certified replay path.
pub fn verify_with_key<B: AsRef<[u8]>>(
    ledger: &Ledger,
    tx: &Transaction,
    profile: Profile,
    pubkey: impl FnOnce() -> Result<Option<B>, Error>,
) -> Result<Verified, Error> {
    resolve(ledger, tx, profile, Evidence::Proof, pubkey)
}
/// Historical certificates authorize only their exact prepared transition.
/// This route stays inside the epoch host; public verification always checks proofs.
#[derive(Clone, Copy)]
pub(crate) enum Evidence<'a> {
    Proof,
    Certified(&'a [u8]),
}
pub(crate) fn resolve<B: AsRef<[u8]>>(
    ledger: &Ledger,
    tx: &Transaction,
    profile: Profile,
    evidence: Evidence<'_>,
    pubkey: impl FnOnce() -> Result<Option<B>, Error>,
) -> Result<Verified, Error> {
    if profile.strict && matches!(evidence, Evidence::Certified(_)) {
        return Err(Error::Unavailable(
            "active private rules require proof verification".into(),
        ));
    }
    let operation = Operation::of(tx)?;
    let op = operation.name();
    if operation == Operation::Decrypt {
        if tx.amount > BigInt::from(1_000_000_000_000_u64) {
            return Err(failure(
                "amount_too_large",
                "decrypt amount exceeds 1000000 OCT limit",
                None,
            ));
        }
        if tx.amount <= BigInt::from(0) {
            return Err(failure(
                "invalid_amount",
                "decrypt amount must be positive",
                None,
            ));
        }
    }
    let payload = payload(tx, operation, profile.fields)?;
    let blob = pubkey()?.ok_or_else(|| {
        failure(
            "bad_zero_proof",
            format!("{op}: no pvac pubkey registered"),
            Some(format!("{op}: bound zero proof failed: no pvac pubkey registered").into_bytes()),
        )
    })?;
    let current = current(ledger, tx, operation)?;
    let prefix = format!("{op}: ");
    check(
        crypto::check_private_input(current, profile.strict),
        operation.tag(),
        b"",
        Some(prefix.as_bytes()),
    )?;
    let verify = matches!(evidence, Evidence::Proof);
    if verify && operation == Operation::Decrypt && payload.range.is_none() {
        return Err(failure(
            "bad_range_proof_balance",
            "decrypt: range_proof_balance required: proves remaining encrypted balance >= 0",
            None,
        ));
    }
    let proof_prefix = format!("{op}: bound zero proof failed: ");
    let public = check(
        if verify {
            crypto::proof_pubkey(blob.as_ref())
        } else {
            crypto::load_pubkey(blob.as_ref())
        },
        "bad_zero_proof",
        prefix.as_bytes(),
        Some(proof_prefix.as_bytes()),
    )?;
    if verify {
        check(
            crypto::verify_amount(
                &public,
                &tx.amount,
                &AmountProof {
                    cipher: &payload.cipher,
                    proof: &payload.proof,
                    commitment: &payload.commitment,
                    blinding: &payload.blinding,
                },
                profile.strict,
                profile.math,
            ),
            "bad_zero_proof",
            prefix.as_bytes(),
            Some(proof_prefix.as_bytes()),
        )?;
    }
    let delta_prefix = if operation == Operation::Decrypt {
        b"cannot decode delta cipher: ".as_slice()
    } else {
        b""
    };
    let delta = check(
        crypto::decode_cipher(&payload.cipher, false, profile.strict),
        operation.tag(),
        delta_prefix,
        None,
    )?;
    let next_prefix = if operation == Operation::Decrypt {
        b"encrypted balance subtract failed: ".as_slice()
    } else {
        b""
    };
    let next = check(
        crypto::balance(
            &public,
            current,
            &delta,
            operation == Operation::Decrypt,
            profile.strict,
            profile.result,
        ),
        operation.tag(),
        next_prefix,
        None,
    )?;
    if let Some(range) = payload.range.filter(|_| verify) {
        let accepted = check(
            crypto::verify_range(&public, &next, &range, profile.strict, profile.math),
            "bad_range_proof_balance",
            b"decrypt range: ",
            Some(b"decrypt range: "),
        )?;
        if !accepted {
            return Err(failure("bad_range_proof_balance","decrypt: range_proof_balance verification failed: remaining balance may be negative",None));
        }
    }
    let plan = Verified {
        operation,
        transaction: tx.hash().map_err(|e| Error::Unavailable(e.to_string()))?,
        current: current.to_vec(),
        next,
    };
    if let Evidence::Certified(hash) = evidence {
        if hash != plan.transition_hash().as_bytes() {
            return Err(failure(
                "preverify_transition_mismatch",
                "private transition does not match the certified receipt",
                None,
            ));
        }
    }
    Ok(plan)
}
