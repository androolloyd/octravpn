// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native V5 stealth sends and claims. Only verified or certificate-bound plans
//! can debit an encrypted balance, create an output, or consume a claim.
use crate::private_crypto::isolated::PublicKey;
use crate::{
    private_balance::{AccountView, Evidence, Profile},
    private_crypto::isolated as crypto,
    private_error::{check, failure, Error},
    private_outputs::{self, Output},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    native_json::{Document, Value},
    state::Ledger,
    transaction::{OpType, RuleMode, Transaction},
};
use sha2::{Digest, Sha256};

const KEY_BOUND: &[u8] = b"pvac_key_bound_output_v1";
type Result<T> = std::result::Result<T, Error>;
fn operational(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
fn claim_rejection(mut error: Error) -> Error {
    if let Error::Rejected(failure) = &mut error {
        failure.preverify_reason = Some(failure.tag.as_bytes().to_vec());
    }
    error
}
fn document(tx: &Transaction, mode: RuleMode, claim: bool) -> Result<Document> {
    let version = if claim {
        "only version 5 (private) claim operations are accepted"
    } else {
        "only version 5 stealth transfers are accepted"
    };
    let Some(raw) = &tx.encrypted_data else {
        return Err(failure(
            "missing_encrypted_data",
            if claim {
                "encrypted_data required for claim"
            } else {
                "encrypted_data required for stealth transfer"
            },
            None,
        ));
    };
    let doc = Document::parse(raw).map_err(|error| match error {
        octra_node_protocol::native_json::Error::Allocation => operational(error),
        octra_node_protocol::native_json::Error::Syntax(_) => {
            failure("version_rejected", version, None)
        }
    })?;
    let valid = matches!(doc.field(doc.root(), b"version"), Some(Value::Int(v)) if v.get() == 5);
    let unique = mode != RuleMode::Active
        || match doc.root() {
            Value::Object(fields) => {
                fields.iter().filter(|(key, _)| key == b"version").count() <= 1
            }
            _ => false,
        };
    if !valid || !unique {
        return Err(failure("version_rejected", version, None));
    }
    Ok(doc)
}
fn field(doc: &Document, name: &[u8], claim: bool) -> Result<Vec<u8>> {
    match doc.field(doc.root(), name) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(missing(name, claim)),
    }
}
fn missing(name: &[u8], claim: bool) -> Error {
    let (tag, prefix) = if claim {
        (
            "invalid_claim_data",
            "cannot parse V5 claim payload: StealthClaimV5: missing ",
        )
    } else {
        (
            "invalid_stealth_data",
            "cannot parse V5 payload: PrivateTransferV4: missing ",
        )
    };
    failure(tag, [prefix.as_bytes(), name].concat(), None)
}
struct Send {
    delta: Vec<u8>,
    commitment: Vec<u8>,
    range_delta: Vec<u8>,
    range_balance: Vec<u8>,
    eph_pub: Vec<u8>,
    tag: Vec<u8>,
    enc_amount: Vec<u8>,
    claim_pub: Vec<u8>,
    amount_commitment: Vec<u8>,
    zero_proof: Vec<u8>,
}
impl Send {
    fn parse(tx: &Transaction, mode: RuleMode) -> Result<Self> {
        let doc = document(tx, mode, false)?;
        let payload = Self {
            delta: field(&doc, b"delta_cipher", false)?,
            commitment: field(&doc, b"commitment", false)?,
            range_delta: field(&doc, b"range_proof_delta", false)?,
            range_balance: field(&doc, b"range_proof_balance", false)?,
            eph_pub: field(&doc, b"eph_pub", false)?,
            tag: field(&doc, b"stealth_tag", false)?,
            enc_amount: field(&doc, b"enc_amount", false)?,
            claim_pub: field(&doc, b"claim_pub", false)?,
            amount_commitment: field(&doc, b"amount_commitment", false)?,
            zero_proof: match doc.field(doc.root(), b"send_zero_proof") {
                Some(Value::String(value)) => value.clone(),
                _ => vec![],
            },
        };
        if payload.claim_pub.len() != 64 {
            return Err(failure(
                "invalid_claim_pub",
                "claim_pub must be 64 hex characters",
                None,
            ));
        }
        Ok(payload)
    }
}
struct Claim {
    id: i64,
    cipher: Vec<u8>,
    commitment: Vec<u8>,
    secret: Vec<u8>,
    proof: Vec<u8>,
}
impl Claim {
    fn parse(tx: &Transaction, mode: RuleMode) -> Result<Self> {
        let doc = document(tx, mode, true)?;
        Ok(Self {
            id: match doc.field(doc.root(), b"output_id") {
                Some(Value::Int(v)) => v.get(),
                _ => return Err(missing(b"output_id", true)),
            },
            cipher: field(&doc, b"claim_cipher", true)?,
            commitment: field(&doc, b"commitment", true)?,
            secret: field(&doc, b"claim_secret", true)?,
            proof: field(&doc, b"zero_proof", true)?,
        })
    }
}
fn current<'a>(ledger: &'a impl AccountView, tx: &Transaction) -> Result<&'a [u8]> {
    ledger
        .account(&tx.from)
        .map(|account| account.encrypted_balance.as_deref().unwrap_or(b"0"))
        .ok_or_else(|| failure("encrypted_balance_update_failed", "account not found", None))
}
pub(crate) fn wrapped(encoded: &[u8], cap: bool) -> Result<bool> {
    match crypto::decode_cipher(encoded, false, cap) {
        Ok(cipher) => Ok(cipher.is_wrapped_scalar()),
        Err(crypto::Error::Rejected(_)) => Ok(false),
        Err(crypto::Error::Unavailable(error)) => Err(operational(error)),
    }
}
fn private_input(encoded: &[u8], cap: bool, operation: &[u8]) -> Result<()> {
    check(
        crypto::check_private_input(encoded, cap),
        "encrypted_balance_update_failed",
        b"",
        Some(&[operation, b": "].concat()),
    )
}
fn load_public(blob: Option<&[u8]>, claim: bool) -> Result<PublicKey> {
    let blob = blob.ok_or_else(|| {
        failure(
            "no_pvac_pubkey",
            if claim {
                "claimant has no registered PVAC pubkey"
            } else {
                "sender has no registered PVAC pubkey"
            },
            None,
        )
    })?;
    check(crypto::load_pubkey(blob), "bad_pvac_pubkey", b"", None)
}
fn claim_gate(tx: &Transaction, claim: &Claim, output: &Output) -> Result<()> {
    if output.claimed != 0 {
        return Err(failure(
            "already_claimed",
            format!("stealth output {} already claimed", claim.id),
            None,
        ));
    }
    let owned = || {
        if output.claim_pub.len() != 64 || claim.secret.len() != 64 {
            return false;
        }
        let (Ok(secret), Ok(_)) = (hex::decode(&claim.secret), hex::decode(&output.claim_pub))
        else {
            return false;
        };
        let mut hash = Sha256::new();
        hash.update(&secret);
        hash.update(&tx.from);
        hash.update(b"OCTRA_CLAIM_BIND_V1");
        hex::encode(hash.finalize())
            .as_bytes()
            .eq_ignore_ascii_case(&output.claim_pub)
    };
    if !owned() {
        return Err(failure(
            "invalid_claim_secret",
            "claim ownership verification failed: you are not the intended recipient",
            None,
        ));
    }
    if output.amount_commitment.is_empty() {
        return Err(failure(
            "no_amount_commitment",
            "stealth output has no stored amount_commitment (not a V5 output)",
            None,
        ));
    }
    if output.amount_hash != KEY_BOUND {
        return Err(failure("legacy_stealth_output", "stealth output predates key-bound PVAC send verification; legacy output migration is required", None));
    }
    Ok(())
}
enum Operation {
    Send(Send),
    Claim {
        id: i64,
        cipher: Vec<u8>,
        output: Box<Output>,
    },
}
pub struct Verified {
    authorized: bool,
    transaction: [u8; 32],
    current: Vec<u8>,
    next: Vec<u8>,
    operation: Operation,
}
impl Verified {
    pub(crate) fn retained_bytes(&self) -> usize {
        let operation = match &self.operation {
            Operation::Send(send) => [
                &send.delta,
                &send.commitment,
                &send.range_delta,
                &send.range_balance,
                &send.eph_pub,
                &send.tag,
                &send.enc_amount,
                &send.claim_pub,
                &send.amount_commitment,
                &send.zero_proof,
            ]
            .into_iter()
            .map(Vec::capacity)
            .fold(0, usize::saturating_add),
            Operation::Claim { cipher, output, .. } => cipher
                .capacity()
                .saturating_add(std::mem::size_of::<Output>())
                .saturating_add(
                    [
                        &output.stealth_tag,
                        &output.eph_pub,
                        &output.enc_amount,
                        &output.amount,
                        &output.tx_hash,
                        &output.sender_addr,
                        &output.claim_pub,
                        &output.delta_cipher_stored,
                        &output.amount_hash,
                        &output.amount_commitment,
                    ]
                    .into_iter()
                    .map(Vec::capacity)
                    .fold(0, usize::saturating_add),
                ),
        };
        std::mem::size_of::<Self>()
            .saturating_add(self.current.capacity())
            .saturating_add(self.next.capacity())
            .saturating_add(operation)
    }
    pub fn current_cipher(&self) -> &[u8] {
        &self.current
    }
    pub fn transition_hash(&self) -> String {
        match &self.operation {
            Operation::Send(send) => crypto::transition_hash(
                b"octra:private_transition:stealth",
                &[
                    &self.current,
                    &self.next,
                    &send.delta,
                    &send.tag,
                    &send.eph_pub,
                    &send.enc_amount,
                    &send.claim_pub,
                    &send.amount_commitment,
                ],
            ),
            Operation::Claim { id, cipher, .. } => crypto::transition_hash(
                b"octra:private_transition:claim",
                &[id.to_string().as_bytes(), cipher, &self.current, &self.next],
            ),
        }
    }
    /// Ledger and object writes share a savepoint. Any unavailable commit aborts
    /// the complete attempt; a failed claim can never leave its fee or balance.
    pub fn apply(
        &self,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        tx: &Transaction,
        epoch: i64,
    ) -> Result<()> {
        if !self.authorized {
            return Err(operational("unverified private transfer preparation"));
        }
        if tx.hash().map_err(operational)? != self.transaction
            || current(ledger, tx)? != self.current
        {
            return Err(operational("private transfer plan source changed"));
        }
        if let Operation::Claim { id, output, .. } = &self.operation {
            if private_outputs::get(state, *id)
                .map_err(operational)?
                .as_ref()
                != Some(output.as_ref())
            {
                return Err(operational("private claim output source changed"));
            }
        }
        let saved = state.save().map_err(operational)?;
        ledger.begin_journal();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger
                .debit(&tx.from, &tx.ou, tx.nonce, None)
                .map_err(|e| failure("insufficient_balance", e.0, None))?;
            ledger.update_encrypted_balance(&tx.from, self.next.clone());
            let hash = hex::encode(self.transaction);
            match &self.operation {
                Operation::Send(send) => {
                    private_outputs::insert(
                        state,
                        Output {
                            id: 0,
                            stealth_tag: send.tag.clone(),
                            eph_pub: send.eph_pub.clone(),
                            enc_amount: send.enc_amount.clone(),
                            amount: b"0".to_vec(),
                            epoch_id: epoch,
                            tx_hash: hash.into_bytes(),
                            sender_addr: tx.from.clone(),
                            claimed: 0,
                            claim_pub: send.claim_pub.clone(),
                            delta_cipher_stored: send.delta.clone(),
                            amount_hash: KEY_BOUND.to_vec(),
                            amount_commitment: send.amount_commitment.clone(),
                        },
                    )
                    .map_err(operational)?;
                }
                Operation::Claim { id, .. } => {
                    private_outputs::mark_claimed(state, *id, hash.as_bytes())
                        .map_err(operational)?
                        .map_err(operational)?;
                }
            }
            Ok(())
        }));
        match result {
            Ok(Ok(())) => ledger.commit_journal().map_err(operational),
            Ok(Err(error)) => {
                ledger.abort_journal();
                state.restore(saved).map_err(operational)?;
                Err(error)
            }
            Err(error) => {
                ledger.abort_journal();
                let _ = state.restore(saved);
                std::panic::resume_unwind(error)
            }
        }
    }
}
pub fn verify<B: AsRef<[u8]>>(
    ledger: &impl AccountView,
    state: &StateBatch,
    tx: &Transaction,
    profile: Profile,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<Verified> {
    resolve(ledger, state, tx, profile, Evidence::Proof, key)
}
pub(crate) fn resolve<B: AsRef<[u8]>>(
    ledger: &impl AccountView,
    state: &StateBatch,
    tx: &Transaction,
    profile: Profile,
    evidence: Evidence<'_>,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<Verified> {
    resolve_inner(ledger, state, tx, profile, evidence, key, false, None)
}
fn resolve_inner<B: AsRef<[u8]>>(
    ledger: &impl AccountView,
    state: &StateBatch,
    tx: &Transaction,
    profile: Profile,
    evidence: Evidence<'_>,
    key: impl FnOnce() -> Result<Option<B>>,
    prepared: bool,
    cached: Option<&crate::single_private::CacheBinding>,
) -> Result<Verified> {
    if profile.strict && matches!(evidence, Evidence::Certified(_)) {
        return Err(operational(
            "active private rules require proof verification",
        ));
    }
    let verify = matches!(evidence, Evidence::Proof) && !prepared;
    let (operation, source, next) = match tx.op_type {
        OpType::Stealth => {
            let send = Send::parse(tx, profile.fields)?;
            let blob = key()?;
            if blob.is_none() {
                return Err(failure(
                    "no_pvac_pubkey",
                    "sender has no registered PVAC pubkey",
                    None,
                ));
            }
            let source = current(ledger, tx)?;
            if !wrapped(&send.delta, profile.strict)? {
                return Err(failure(
                    "bad_delta_cipher",
                    "stealth delta cipher must be a wrapped scalar",
                    None,
                ));
            }
            private_input(source, profile.strict, b"stealth")?;
            let public = load_public(blob.as_ref().map(AsRef::as_ref), false)?;
            let delta = check(
                crypto::decode_cipher(&send.delta, false, profile.strict),
                "bad_delta_cipher",
                b"cannot decode delta cipher: ",
                None,
            )?;
            let next = check(
                crypto::balance(
                    &public,
                    source,
                    &delta,
                    true,
                    profile.strict,
                    profile.result,
                ),
                "encrypted_balance_update_failed",
                b"sender encrypted balance update: ",
                None,
            )?;
            if (verify || prepared)
                && !check(
                    crypto::verify_commitment(
                        &public,
                        &send.delta,
                        &send.commitment,
                        profile.strict,
                    ),
                    "bad_commitment",
                    b"",
                    None,
                )?
            {
                return Err(failure(
                    "bad_commitment",
                    "delta cipher commitment verification failed",
                    None,
                ));
            }
            if verify {
                // Native evaluates both ranges before choosing the first false
                // result; an unavailable second proof still aborts the attempt.
                let range = |cipher: &[u8], proof: &[u8], prefix: &[u8]| {
                    if !public.supports_alias_rejection() {
                        return Ok(false);
                    }
                    check(
                        crypto::verify_range(&public, cipher, proof, profile.strict, profile.math),
                        "bad_range_proof",
                        prefix,
                        Some(prefix),
                    )
                };
                let (delta_ok, balance_ok) = match cached.and_then(|binding| {
                    binding.results(
                        tx,
                        profile,
                        source,
                        blob.as_ref().map(AsRef::as_ref).unwrap_or_default(),
                    )
                }) {
                    Some(results) => results,
                    None => (
                        range(&send.delta, &send.range_delta, b"stealth delta range: ")?,
                        range(&next, &send.range_balance, b"stealth balance range: ")?,
                    ),
                };
                if !delta_ok {
                    return Err(failure(
                        "bad_range_proof_delta",
                        "delta range proof failed: delta must be non-negative",
                        None,
                    ));
                }
                if !balance_ok {
                    return Err(failure(
                        "bad_range_proof_balance",
                        "balance range proof failed: sender may have insufficient balance",
                        None,
                    ));
                }
                let prefix = b"send_zero_proof does not bind delta_cipher to amount_commitment: ";
                if send.zero_proof.is_empty() {
                    return Err(failure(
                        "bad_send_binding",
                        [prefix.as_slice(), b"send_zero_proof required but missing"].concat(),
                        None,
                    ));
                }
                check(
                    crypto::verify_claim(
                        &public,
                        &send.delta,
                        &send.zero_proof,
                        &send.amount_commitment,
                        profile.strict,
                        profile.math,
                    ),
                    "bad_send_binding",
                    prefix,
                    None,
                )?;
            }
            (Operation::Send(send), source.to_vec(), next)
        }
        OpType::Claim => {
            let (claim, output, blob, verified_public) = (|| {
                if tx.from != tx.to {
                    return Err(failure(
                        "claim_not_self",
                        "claim operation must target sender (from == to)",
                        None,
                    ));
                }
                let claim = Claim::parse(tx, profile.fields)?;
                let output = private_outputs::get(state, claim.id)
                    .map_err(operational)?
                    .ok_or_else(|| {
                        failure(
                            "output_not_found",
                            format!("stealth output {} not found", claim.id),
                            None,
                        )
                    })?;
                claim_gate(tx, &claim, &output)?;
                if !wrapped(&claim.cipher, profile.strict)? {
                    return Err(failure(
                        "bad_claim_cipher",
                        "claim cipher must be a wrapped scalar",
                        None,
                    ));
                }
                let blob = key()?;
                let verified_public = if verify {
                    let public = load_public(blob.as_ref().map(AsRef::as_ref), true)?;
                    if !check(
                        crypto::verify_commitment(
                            &public,
                            &claim.cipher,
                            &claim.commitment,
                            profile.strict,
                        ),
                        "bad_commitment",
                        b"",
                        None,
                    )? {
                        return Err(failure(
                            "bad_commitment",
                            "claim cipher commitment verification failed",
                            None,
                        ));
                    }
                    check(
                        crypto::verify_claim(
                            &public,
                            &claim.cipher,
                            &claim.proof,
                            &output.amount_commitment,
                            profile.strict,
                            profile.math,
                        ),
                        "bad_zero_proof",
                        b"bound zero proof verification failed: ",
                        None,
                    )?;
                    Some(public)
                } else {
                    None
                };
                Ok((claim, output, blob, verified_public))
            })()
            .map_err(claim_rejection)?;
            let source = current(ledger, tx)?;
            private_input(source, profile.strict, b"claim")?;
            let public = match verified_public {
                Some(public) => public,
                None => load_public(blob.as_ref().map(AsRef::as_ref), true)?,
            };
            let delta = check(
                crypto::decode_cipher(&claim.cipher, false, profile.strict),
                "bad_claim_cipher",
                b"cannot decode claim cipher: ",
                None,
            )?;
            let next = check(
                crypto::balance(
                    &public,
                    source,
                    &delta,
                    false,
                    profile.strict,
                    profile.result,
                ),
                "encrypted_balance_update_failed",
                b"claimant encrypted balance update: ",
                None,
            )?;
            (
                Operation::Claim {
                    id: claim.id,
                    cipher: claim.cipher,
                    output: Box::new(output),
                },
                source.to_vec(),
                next,
            )
        }
        _ => return Err(operational("private transfer route mismatch")),
    };
    let plan = Verified {
        authorized: !prepared,
        transaction: tx.hash().map_err(operational)?,
        current: source,
        next,
        operation,
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

/// Parsed, key-bound stealth balance preparation. Its inner plan cannot apply
/// until range/commitment/binding proofs are actually verified.
pub(crate) struct PreparedStealth {
    inner: Verified,
}
impl PreparedStealth {
    pub(crate) fn current_cipher(&self) -> &[u8] {
        self.inner.current_cipher()
    }
}
pub(crate) fn prepare_stealth<B: AsRef<[u8]>>(
    ledger: &Ledger,
    state: &StateBatch,
    tx: &Transaction,
    profile: Profile,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<PreparedStealth> {
    if tx.op_type != OpType::Stealth {
        return Err(operational("stealth preparation route mismatch"));
    }
    Ok(PreparedStealth {
        inner: resolve_inner(ledger, state, tx, profile, Evidence::Proof, key, true, None)?,
    })
}
/// Range-only speculative work, as Tx_view.preverify_stealth_ranges. This does
/// not authorize execution: commitment and send binding are checked at apply.
struct SingleRanges {
    source: Vec<u8>,
    public: PublicKey,
    send: Send,
    next: Vec<u8>,
    profile: Profile,
}
impl SingleRanges {
    fn prepare(ledger: &Ledger, tx: &Transaction, profile: Profile, blob: &[u8]) -> Result<Self> {
        let send = Send::parse(tx, profile.fields)?;
        if !wrapped(&send.delta, false)? {
            return Err(failure(
                "invalid_stealth_data",
                "stealth delta cipher shape invalid",
                None,
            ));
        }
        let source = current(ledger, tx)?;
        let public = load_public(Some(blob), false)?;
        let delta = check(
            crypto::decode_cipher(&send.delta, false, profile.strict),
            "bad_delta_cipher",
            b"",
            None,
        )?;
        let next = check(
            crypto::balance(
                &public,
                source,
                &delta,
                true,
                profile.strict,
                profile.result,
            ),
            "encrypted_balance_update_failed",
            b"",
            None,
        )?;

        Ok(Self {
            source: source.to_vec(),
            public,
            send,
            next,
            profile,
        })
    }
    fn check(&self, balance: bool) -> Result<bool> {
        if self.public.supports_alias_rejection() {
            let (cipher, proof) = if balance {
                (&self.next, &self.send.range_balance)
            } else {
                (&self.send.delta, &self.send.range_delta)
            };
            check(
                crypto::verify_range(
                    &self.public,
                    cipher,
                    proof,
                    self.profile.strict,
                    self.profile.math,
                ),
                "bad_range_proof",
                b"",
                None,
            )
        } else {
            Ok(false)
        }
    }
}
pub(crate) fn single_ranges(
    ledger: &Ledger,
    tx: &Transaction,
    profile: Profile,
    blob: &[u8],
) -> Result<(Vec<u8>, bool, bool)> {
    let ranges = SingleRanges::prepare(ledger, tx, profile, blob)?;
    let delta = ranges.check(false)?;
    let balance = ranges.check(true)?;
    Ok((ranges.source, delta, balance))
}
/// A trusted helper's one native proof phase. No externally supplied verdict.
pub(crate) fn single_range(
    ledger: &Ledger,
    tx: &Transaction,
    profile: Profile,
    blob: &[u8],
    balance: bool,
) -> Result<bool> {
    SingleRanges::prepare(ledger, tx, profile, blob)?.check(balance)
}

pub(crate) fn verify_single<B: AsRef<[u8]>>(
    ledger: &Ledger,
    state: &StateBatch,
    tx: &Transaction,
    profile: Profile,
    cached: Option<&crate::single_private::CacheBinding>,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<Verified> {
    resolve_inner(
        ledger,
        state,
        tx,
        profile,
        Evidence::Proof,
        key,
        false,
        cached,
    )
}

/// Native private_source distinguishes malformed claims, missing IDs and the
/// complete parsed output. Artifact reuse hashes every native output field.
pub(crate) fn artifact_claim_source(
    tx: &Transaction,
    fields: RuleMode,
    state: &StateBatch,
) -> Result<Option<(i64, Option<Output>)>> {
    let claim = match Claim::parse(tx, fields) {
        Ok(claim) => claim,
        Err(Error::Rejected(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    private_outputs::get(state, claim.id)
        .map(|output| Some((claim.id, output)))
        .map_err(operational)
}
