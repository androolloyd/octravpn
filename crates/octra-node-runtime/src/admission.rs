//! Native RPC transaction admission. Each phase preserves the native refusal
//! order; cryptographic resource failures remain operational errors.
use num_traits::Signed;
use octra_node_protocol::{
    control_payload::BondedReady,
    duty,
    native_json::{Document, Value},
    state::Ledger,
    transaction::{
        address_from_public_key, is_valid_address, EnvelopeError, Nonce, OpType, RuleMode,
        Transaction,
    },
    transaction_payload::{self, Limits},
    transaction_policy::{self, Profile},
};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Rejected(#[from] EnvelopeError),
    #[error("transaction admission unavailable: {0}")]
    Unavailable(String),
}
fn refusal(tag: &'static str, reason: impl Into<String>) -> EnvelopeError {
    EnvelopeError {
        tag,
        reason: reason.into(),
    }
}
#[derive(Clone, Debug)]
pub struct Precheck<'a> {
    pub now: f64,
    pub max_timestamp_drift: f64,
    pub observer: bool,
    pub bft: bool,
    pub profile: &'a Profile,
    pub duty: Option<(i64, RuleMode)>,
    pub limits: Limits,
}
#[derive(Clone, Copy, Debug)]
pub struct Postcheck {
    pub preverify_has_capacity: bool,
    pub preverify_pending: Nonce,
    pub preverify_pending_max: Nonce,
    pub bft: bool,
    pub confirmed_nonce: Nonce,
    pub bft_window: Nonce,
}
pub fn address_route(tx: &Transaction) -> Result<(), EnvelopeError> {
    let valid = match tx.op_type {
        OpType::Stealth => tx.to == b"stealth",
        OpType::MultiExec => tx.to == b"multi_exec",
        _ => is_valid_address(&tx.to),
    };
    if !is_valid_address(&tx.from) || !valid {
        Err(refusal(
            "invalid_address",
            "malformed sender or recipient address",
        ))
    } else {
        Ok(())
    }
}
pub fn self_route(tx: &Transaction) -> Result<(), EnvelopeError> {
    let same = tx.from == tx.to;
    let error = match (tx.op_type, same) {
        (OpType::Standard, true) => Some(("self_transfer", "sender and recipient are the same")),
        (OpType::Private, true) => Some((
            "self_transfer",
            "private transfer must target different address",
        )),
        (OpType::Encrypt, false) => Some((
            "self_only_operation",
            "encrypt operation must target sender",
        )),
        (OpType::Decrypt, false) => Some((
            "self_only_operation",
            "decrypt operation must target sender",
        )),
        (OpType::Claim, false) => {
            Some(("self_only_operation", "claim operation must target sender"))
        }
        (OpType::Recrypt, false) => Some((
            "self_only_operation",
            "recrypt operation must target sender",
        )),
        (OpType::KeySwitch, false) => Some((
            "self_only_operation",
            "key_switch operation must target sender",
        )),
        (OpType::Op01Burn, false) => Some((
            "self_only_operation",
            "op01_burn must target sender (self-tx)",
        )),
        _ => None,
    };
    error.map_or(Ok(()), |(tag, reason)| Err(refusal(tag, reason)))
}
pub fn signature(tx: &Transaction, account_public_key: Option<&[u8]>) -> Result<(), EnvelopeError> {
    let public_key = account_public_key
        .or(tx.public_key.as_deref())
        .ok_or_else(|| refusal("invalid_signature", "no public key available"))?;
    if address_from_public_key(public_key) != tx.from {
        Err(refusal(
            "invalid_address",
            "address does not match public key",
        ))
    } else if !tx.verify(public_key) {
        Err(refusal(
            "invalid_signature",
            "signature verification failed",
        ))
    } else {
        Ok(())
    }
}
pub fn sender(tx: &Transaction, exists: bool) -> Result<(), EnvelopeError> {
    if !tx.ou.is_positive() {
        Err(refusal(
            "malformed_transaction",
            "OU must be greater than zero",
        ))
    } else if !exists {
        Err(refusal("sender_not_found", "sender account does not exist"))
    } else {
        Ok(())
    }
}
pub fn payload_size(tx: &Transaction, limits: Limits) -> Result<(), EnvelopeError> {
    if transaction_policy::is_asset_body(tx.op_type)
        && tx
            .encrypted_data
            .as_ref()
            .is_some_and(|v| v.len() > 44_739_244)
    {
        return Err(refusal(
            "malformed_transaction",
            "circle asset body exceeds max encoded size",
        ));
    }
    transaction_payload::admit(limits, tx).map_err(|e| refusal("malformed_transaction", e.0))
}
pub fn call_params_ok(tx: &Transaction) -> bool {
    if !matches!(
        tx.op_type,
        OpType::ContractCall
            | OpType::ProgramExec
            | OpType::MultiExec
            | OpType::ContractDeploy
            | OpType::ProgramDeploy
            | OpType::CircleCall
    ) {
        return true;
    }
    let Some(doc) = tx.message.as_deref().and_then(|v| Document::parse(v).ok()) else {
        return true;
    };
    match doc.root() {
        Value::List(values) => values.iter().all(|id| match doc.get(*id) {
            Some(Value::String(v)) => !v.windows(2).any(|p| {
                p[0] == b'<' && (p[1].is_ascii_alphabetic() || matches!(p[1], b'/' | b'!'))
            }),
            _ => true,
        }),
        _ => true,
    }
}
pub fn payload(tx: &Transaction, limits: Limits) -> Result<(), Error> {
    payload_size(tx, limits)?;
    if !crate::crypto_payload::encrypted_payload_ok(tx)
        .map_err(|e| Error::Unavailable(e.to_string()))?
    {
        return Err(refusal(
            "malformed_transaction",
            "malformed or oversized encrypted_data",
        )
        .into());
    }
    if !call_params_ok(tx) {
        return Err(refusal(
            "malformed_transaction",
            "contract call params contain invalid characters",
        )
        .into());
    }
    Ok(())
}
pub fn duty_retry(tx: &Transaction, context: &Precheck<'_>) -> bool {
    duty_retry_at(tx, context.now, context.duty, context.bft)
}
pub(crate) fn duty_retry_at(
    tx: &Transaction,
    now: f64,
    duty: Option<(i64, RuleMode)>,
    bft: bool,
) -> bool {
    let Some((head, RuleMode::Active)) = duty else {
        return false;
    };
    bft && now.is_finite()
        && tx.timestamp.is_finite()
        && tx.timestamp <= now
        && tx.op_type == OpType::ValidatorReady
        && !duty::expired(tx, Some(head), RuleMode::Active)
        && BondedReady::parse(tx.message.as_deref()).is_ok_and(|ready| ready.head_epoch <= head)
}
#[allow(clippy::cast_possible_truncation)] // Native Printf converts the configured floating limit with int_of_float.
pub fn pre_route(tx: &Transaction, context: &Precheck<'_>) -> Result<(), EnvelopeError> {
    let drift = (tx.timestamp - context.now).abs();
    if !(tx.timestamp.is_finite() && context.now.is_finite())
        || drift > context.max_timestamp_drift && !duty_retry(tx, context)
    {
        let value = if drift.is_nan() {
            "nan".into()
        } else {
            format!("{drift:.0}")
        };
        return Err(refusal(
            "malformed_transaction",
            format!(
                "timestamp drift {value}s exceeds {}s limit",
                context.max_timestamp_drift as i64
            ),
        ));
    }
    if context.observer {
        return Err(refusal("read_only_observer", "observer node is read-only"));
    }
    if context.bft && !context.profile.consensus_admits(tx.op_type) {
        return Err(refusal(
            "unsupported_operation",
            format!(
                "BFT operation disabled by the active release profile; op_type = {}",
                tx.op_type.as_str()
            ),
        ));
    }
    Ok(())
}
pub fn pre_signature(
    tx: &Transaction,
    exists: bool,
    context: &Precheck<'_>,
) -> Result<(), EnvelopeError> {
    pre_route(tx, context)?;
    address_route(tx)?;
    payload_size(tx, context.limits)?;
    self_route(tx)?;
    transaction_policy::semantic_check(tx).map_err(|e| refusal("malformed_transaction", e))?;
    sender(tx, exists)
}
pub fn post_signature(tx: &Transaction, context: Postcheck) -> Result<(), EnvelopeError> {
    let missing = tx.encrypted_data.as_ref().is_none_or(Vec::is_empty);
    if tx.op_type == OpType::Stealth && missing {
        return Err(refusal(
            "malformed_transaction",
            "stealth tx requires encrypted_data with FHE delta + range proofs",
        ));
    }
    if matches!(
        tx.op_type,
        OpType::Encrypt | OpType::Decrypt | OpType::Recrypt | OpType::KeySwitch
    ) && missing
    {
        return Err(refusal(
            "malformed_transaction",
            "FHE op requires encrypted_data with cipher + proofs",
        ));
    }
    if tx.op_type == OpType::Stealth && !context.preverify_has_capacity {
        return Err(refusal(
            "pre_verify_busy",
            format!(
                "stealth pre-verify busy ({}/{}), retry shortly",
                context.preverify_pending.get(),
                context.preverify_pending_max.get()
            ),
        ));
    }
    let sum = context
        .confirmed_nonce
        .get()
        .wrapping_add(context.bft_window.get());
    let threshold = (sum << 1) >> 1;
    if context.bft && tx.nonce.get() > threshold {
        return Err(refusal(
            "nonce_too_far",
            format!(
                "nonce too far ahead for BFT admission window (confirmed={} window={})",
                context.confirmed_nonce.get(),
                context.bft_window.get()
            ),
        ));
    }
    Ok(())
}
pub fn duty_nonce(
    tx: &Transaction,
    head: Option<i64>,
    confirmed: Nonce,
) -> Result<(), &'static str> {
    let Some(head) = head.filter(|_| tx.op_type == OpType::ValidatorReady) else {
        return Ok(());
    };
    match BondedReady::parse(tx.message.as_deref()) {
        Ok(ready) if ready.head_epoch > head => {
            if i128::from(ready.head_epoch) - i128::from(head) <= 16 {
                Ok(())
            } else {
                Err("validator ready head exceeds relay window")
            }
        }
        _ if tx.nonce.get() > confirmed.get() + 1 => {
            Err("validator ready requires next confirmed nonce")
        }
        _ => Ok(()),
    }
}
/// Submitted transaction with the current account key, native payload shape and
/// RPC admission checks applied. Epoch rule-fold and stateful admission still run
/// at execution time because the head and ledger may have changed.
pub struct Admitted(Transaction);
impl Admitted {
    pub fn transaction(&self) -> &Transaction {
        &self.0
    }
    pub fn into_transaction(self) -> Transaction {
        self.0
    }
}
pub fn submit(
    tx: Transaction,
    ledger: &Ledger,
    pre: &Precheck<'_>,
    post: Postcheck,
) -> Result<Admitted, Error> {
    let account = ledger.account(&tx.from);
    pre_signature(&tx, account.is_some(), pre)?;
    signature(&tx, account.and_then(|a| a.public_key.as_deref()))?;
    payload(&tx, Limits::default())?;
    post_signature(&tx, post)?;
    Ok(Admitted(tx))
}
