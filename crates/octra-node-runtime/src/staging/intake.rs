//! Native normalized queue intake shared by RPC and peer submissions. The host
//! owns the canonical ledger, active rules, preverification workers and effects.
use super::{preview, DropRecord, Limits, Pool};
use crate::admission;
use num_bigint::BigInt;
use octra_node_protocol::{
    duty, resource_lanes,
    state::Ledger,
    transaction::{self, EnvelopeError, OpType, RuleMode, Transaction},
    transaction_payload,
    transaction_policy::{self, Profile},
};

pub struct Rules {
    pub bft: bool,
    pub profile: Profile,
    pub compute: RuleMode,
    pub settle: RuleMode,
    pub proof: RuleMode,
    pub duty: Option<(i64, RuleMode)>,
    pub queue_head: Option<i64>,
    pub stealth_minimum: BigInt,
}
/// These effects run while the host holds the queue and canonical-head lock.
/// A preverification refusal removes the new entry but retains prior evictions,
/// exactly as the native facade does. Worker failures must be returned as errors.
pub trait Host {
    fn preverify(&mut self, tx: &Transaction, pool: &Pool) -> Result<(), String>;
    fn save_drops(&mut self, drops: &[DropRecord]);
    fn invalidate(&mut self, hash: &[u8]);
    fn changed(&mut self, pool: &Pool);
    fn accepted(&mut self, tx: &Transaction, pool: &Pool);
}
fn prepare(tx: &Transaction, ledger: &Ledger) -> Result<Transaction, EnvelopeError> {
    transaction::normalize_envelope(
        tx,
        ledger
            .account(&tx.from)
            .and_then(|a| a.public_key.as_deref())
            .or(tx.public_key.as_deref()),
    )
}
/// Port of `Node_rest_facade.add_tx_to_staging`. As upstream, the caller must
/// authenticate the signature and payload first; RPC callers should use `submit`.
pub fn stage(
    pool: &mut Pool,
    tx: &Transaction,
    ledger: &Ledger,
    rules: &Rules,
    host: &mut dyn Host,
    clock: &dyn Fn() -> f64,
) -> Result<Vec<u8>, String> {
    transaction::check_compute(rules.compute, rules.settle, std::slice::from_ref(tx))
        .map_err(|e| e.to_string())?;
    let tx = prepare(tx, ledger).map_err(|e| e.reason)?;
    let head = rules.duty.map(|(h, _)| h);
    let mode = rules.duty.map_or(RuleMode::Prior, |(_, m)| m);
    if duty::expired(&tx, head, mode) {
        return Err("validator ready head has expired".into());
    }
    if rules.bft && !rules.profile.consensus_admits(tx.op_type) {
        return Err(format!(
            "BFT operation disabled by the active release profile; op_type = {}",
            tx.op_type.as_str()
        ));
    }
    if rules.bft {
        resource_lanes::queue_check(&tx, rules.proof, &rules.stealth_minimum)
            .map_err(|e| e.to_string())?;
    }
    transaction_policy::staging_admission(
        &tx,
        &rules.stealth_minimum,
        &pool.min_relay_fee(&tx, &rules.stealth_minimum),
    )?;
    let hash = hex::encode(tx.hash().map_err(|e| e.to_string())?).into_bytes();
    pool.preview(preview::Message::Check(rules.queue_head, hash.clone()))?;
    let drops = pool.expire_duty(Some(&tx.from), head, mode, clock);
    if !drops.is_empty() {
        host.save_drops(&drops);
        for drop in &drops {
            host.invalidate(&drop.hash);
        }
        host.changed(pool);
    }
    if tx.op_type == OpType::ValidatorReady && pool.find(&hash).is_some() {
        return Ok(hash);
    }
    let lookup = |a: &[u8]| ledger.account(a).map(|a| (a.balance.clone(), a.nonce));
    admission::duty_nonce(&tx, head, lookup(&tx.from).unwrap_or_default().1)?;
    pool.refresh_balance(&tx.from, lookup(&tx.from).unwrap_or_default().0);
    let drops = pool.add(
        tx.clone(),
        &Limits {
            stealth_minimum: rules.stealth_minimum.clone(),
            ..Limits::default()
        },
        rules.queue_head,
        &lookup,
        clock,
    )?;
    host.save_drops(&drops);
    let verification =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.preverify(&tx, pool)))
            .unwrap_or_else(|_| {
                Err("pre_verify_unavailable reason = preverification worker panicked".into())
            });
    if let Err(reason) = verification {
        pool.remove(&hash);
        host.invalidate(&hash);
        return Err(reason);
    }
    host.accepted(&tx, pool);
    Ok(hash)
}
pub fn staging_error(message: String) -> EnvelopeError {
    let m = message.to_ascii_lowercase();
    let (tag, replacement) = if m == "duplicate transaction" {
        ("duplicate_transaction", Some("tx already in staging"))
    } else if m == "preview refused in this epoch" {
        (
            "preview_refused",
            Some("retry after epoch commit or replace transaction at same nonce"),
        )
    } else if m.starts_with("duplicate nonce") {
        ("duplicate_transaction", None)
    } else if m == "nonce too low (already used)" {
        ("invalid_nonce", Some("nonce already used"))
    } else if m == "nonce too far ahead"
        || m == "validator ready requires next confirmed nonce"
        || m == "validator ready head exceeds relay window"
    {
        ("nonce_too_far", None)
    } else if m.starts_with("insufficient balance ") {
        ("insufficient_balance", None)
    } else if m.len() > 20 && m.starts_with("amount must be posit") {
        (
            "malformed_transaction",
            Some("amount must be greater than zero"),
        )
    } else if m.len() > 20 && m.starts_with("amount must be zero ") {
        ("malformed_transaction", None)
    } else if m.len() > 8 && m.starts_with("fee too ") {
        ("fee_too_low", None)
    } else if m.len() > 12 && m.starts_with("staging full") {
        ("staging_full", None)
    } else if m.starts_with("pre_verify_busy") {
        ("pre_verify_busy", None)
    } else if m.starts_with("pre_verify_unavailable") {
        ("pre_verify_unavailable", None)
    } else if m.len() > 11 && m.starts_with("transaction") {
        ("tx_too_large", None)
    } else {
        ("internal_error", None)
    };
    EnvelopeError {
        tag,
        reason: replacement.map_or(message, str::to_owned),
    }
}
pub struct Rpc {
    pub now: f64,
    pub max_drift: f64,
    pub observer: bool,
    pub preverify_capacity: bool,
    pub preverify_pending: transaction::Nonce,
    pub preverify_maximum: transaction::Nonce,
    pub nonce_window: transaction::Nonce,
}
/// Authenticate and stage while the same host lock protects the ledger and pool.
pub fn submit(
    pool: &mut Pool,
    tx: &Transaction,
    ledger: &Ledger,
    rules: &Rules,
    rpc: &Rpc,
    host: &mut dyn Host,
    clock: &dyn Fn() -> f64,
) -> Result<Vec<u8>, admission::Error> {
    transaction::check_compute(rules.compute, rules.settle, std::slice::from_ref(tx)).map_err(
        |e| EnvelopeError {
            tag: "malformed_transaction",
            reason: e.to_string(),
        },
    )?;
    let pre = admission::Precheck {
        now: rpc.now,
        max_timestamp_drift: rpc.max_drift,
        observer: rpc.observer,
        bft: rules.bft,
        profile: &rules.profile,
        duty: rules.duty,
        limits: transaction_payload::Limits::default(),
    };
    let account = ledger.account(&tx.from);
    admission::pre_signature(tx, account.is_some(), &pre)?;
    let tx = prepare(tx, ledger)?;
    admission::signature(&tx, account.and_then(|a| a.public_key.as_deref()))?;
    admission::payload(&tx, transaction_payload::Limits::default())?;
    admission::post_signature(
        &tx,
        admission::Postcheck {
            preverify_has_capacity: rpc.preverify_capacity,
            preverify_pending: rpc.preverify_pending,
            preverify_pending_max: rpc.preverify_maximum,
            bft: rules.bft,
            confirmed_nonce: account.expect("sender admission").nonce,
            bft_window: rpc.nonce_window,
        },
    )?;
    stage(pool, &tx, ledger, rules, host, clock)
        .map_err(|e| admission::Error::Rejected(staging_error(e)))
}
