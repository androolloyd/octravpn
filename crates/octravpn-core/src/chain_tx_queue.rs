//! Single-owner nonce queue for Octra transaction submission.
//!
//! The queue serializes operator-signed submissions behind one actor so
//! callers cannot race by independently fetching the same account nonce.
//!
//! `octra_submit` only STAGES a transaction (lite_node rpc_view.ml:706-712);
//! it is applied — or rejected — at the next epoch tick, every 10s
//! (epoch_time.ml:10-11). The actor therefore follows every staged submit
//! with a status poll against `octra_transaction`, which reports real
//! terminal statuses — pending / confirmed / rejected / dropped
//! (history_read_rpc.ml:131-175) — and refines a confirm with the execution
//! receipt (`contract_receipt`, contract_rpc.ml:765-780).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::{
    address::Address,
    rpc::{next_nonce, BalanceResult, RpcClient, SubmitResult},
    CoreError, CoreResult, KeyPair,
};

const QUEUE_CAPACITY: usize = 1024;
const MAX_NONCE_RETRIES: usize = 1;
const MAX_TRANSIENT_RETRIES: usize = 3;
/// R5: total wall-time budget for the submit/retry phase. This single actor
/// serializes every operator-signed tx, so a slow/hanging RPC (the 10s HTTP
/// client timeout) across retries could otherwise stall every settle/arm/claim
/// queued behind it. Stop retrying once this budget is spent.
const MAX_ITEM_WALL: Duration = Duration::from_secs(20);
/// Confirmation polls after a successful stage. Terminal statuses only appear
/// at epoch apply and the epoch interval is a hardcoded 10s
/// (epoch_time.ml:10-11), so 15 polls on the 2s production cadence span
/// ~30s ≈ three epochs — enough to ride out one late tick without pinning
/// the actor forever.
const MAX_CONFIRM_POLLS: usize = 15;
/// Wall-clock backstop for the confirm phase: each poll is itself an RPC
/// that can burn its own timeout, so the poll count alone does not bound
/// elapsed time.
const MAX_CONFIRM_WALL: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct ChainTxQueueHandle {
    tx: mpsc::Sender<SubmitRequest>,
}

impl ChainTxQueueHandle {
    /// Submit an unsigned contract-call envelope through the nonce owner.
    ///
    /// The caller may pass a placeholder `nonce`; the queue overwrites it
    /// immediately before signing. On `Ok`, the tx was staged and — unless
    /// the chain was too slow to answer within the confirm budget — has
    /// confirmed at an epoch with a non-reverted receipt. `rejected`,
    /// `dropped`, and reverted-execution outcomes surface as `Err` with the
    /// node-reported reason.
    pub async fn submit(&self, unsigned_call: serde_json::Value) -> CoreResult<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(SubmitRequest {
                unsigned_call,
                reply_tx,
            })
            .await
            .map_err(|_| CoreError::Rpc("chain tx queue task is closed".to_string()))?;
        reply_rx
            .await
            .map_err(|_| CoreError::Rpc("chain tx queue task dropped reply".to_string()))?
    }
}

/// Spawn the single-owner nonce actor.
///
/// The actor owns the next nonce cache. `None` means it must reconcile
/// from chain before the next submission.
///
/// `chain_id` must be empty: the real Octra tx envelope has no chain_id
/// field (see `sign_with_nonce`). The parameter survives so existing call
/// sites keep compiling; a non-empty value fails every submission with an
/// explicit configuration error instead of an inscrutable on-chain 101.
pub fn spawn(rpc: RpcClient, wallet: Arc<KeyPair>, chain_id: String) -> ChainTxQueueHandle {
    spawn_with_rpc(rpc, wallet, chain_id)
}

struct SubmitRequest {
    unsigned_call: Value,
    reply_tx: oneshot::Sender<CoreResult<String>>,
}

struct ChainTxQueue<R> {
    rpc: R,
    wallet: Arc<KeyPair>,
    wallet_addr: Address,
    chain_id: String,
    next: Option<u64>,
    rx: mpsc::Receiver<SubmitRequest>,
}

#[async_trait]
trait QueueRpc: Send + Sync + 'static {
    async fn balance(&self, addr: &Address) -> CoreResult<BalanceResult>;
    async fn submit(&self, signed_tx: &Value) -> CoreResult<SubmitResult>;
    /// `octra_transaction` status lookup: `{status: pending|confirmed|
    /// rejected|dropped, ...}` (history_read_rpc.ml:131-175).
    async fn transaction(&self, hash: &str) -> CoreResult<Value>;
    /// `contract_receipt` execution receipt for a confirmed tx:
    /// `{success, events, effort, error, ...}` (contract_rpc.ml:765-780).
    async fn contract_receipt(&self, hash: &str) -> CoreResult<Value>;
}

#[async_trait]
impl QueueRpc for RpcClient {
    // Path form (rather than `self.balance(..)`) so these resolve to the
    // inherent RpcClient methods and not recursively back into this impl.
    async fn balance(&self, addr: &Address) -> CoreResult<BalanceResult> {
        Self::balance(self, addr).await
    }

    async fn submit(&self, signed_tx: &Value) -> CoreResult<SubmitResult> {
        Self::submit(self, signed_tx).await
    }

    async fn transaction(&self, hash: &str) -> CoreResult<Value> {
        Self::transaction(self, hash).await
    }

    async fn contract_receipt(&self, hash: &str) -> CoreResult<Value> {
        self.raw_call("contract_receipt", json!([hash])).await
    }
}

fn spawn_with_rpc<R>(rpc: R, wallet: Arc<KeyPair>, chain_id: String) -> ChainTxQueueHandle
where
    R: QueueRpc,
{
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    let wallet_addr = Address::from_pubkey(&wallet.public.0);
    let mut queue = ChainTxQueue {
        rpc,
        wallet,
        wallet_addr,
        chain_id,
        next: None,
        rx,
    };
    tokio::spawn(async move {
        queue.run().await;
    });
    ChainTxQueueHandle { tx }
}

impl<R> ChainTxQueue<R>
where
    R: QueueRpc,
{
    async fn run(&mut self) {
        while let Some(req) = self.rx.recv().await {
            let result = self.process(req.unsigned_call).await;
            let _ = req.reply_tx.send(result);
        }
    }

    async fn process(&mut self, unsigned_call: Value) -> CoreResult<String> {
        let started = Instant::now();
        let mut nonce_retries = 0usize;
        let mut transient_retries = 0usize;

        loop {
            if self.next.is_none() {
                self.next = Some(self.reconcile_next_nonce().await?);
            }
            let nonce = self
                .next
                .ok_or_else(|| CoreError::Rpc("chain tx queue missing reconciled nonce".into()))?;
            let signed =
                sign_with_nonce(&self.wallet, &self.chain_id, unsigned_call.clone(), nonce)?;

            match self.rpc.submit(&signed).await {
                Ok(result) => {
                    // Staged: octra_submit accepting means the tx now sits in
                    // staging holding our nonce (rpc_view.ml:706-712), so later
                    // items must use nonce+1 whether or not this one ultimately
                    // confirms. The confirm phase walks that back (reconcile)
                    // if the epoch apply rejects/drops it.
                    self.next = nonce.checked_add(1);
                    return self.confirm_staged(result.hash).await;
                }
                Err(err) => {
                    let msg = core_error_message(&err);
                    // R5: once the per-item wall-time budget is spent, stop
                    // retrying and return -- do not hold the single queue actor
                    // open behind one slow submission (head-of-line blocking).
                    // Clear the cached nonce first: we timed out mid-flight and
                    // cannot know whether the tx landed, so the NEXT item must
                    // reconcile from chain rather than reuse a possibly-stale nonce.
                    if started.elapsed() >= MAX_ITEM_WALL {
                        self.next = None;
                        return Err(err);
                    }
                    if is_nonce_error(&msg) {
                        self.next = None;
                        if nonce_retries < MAX_NONCE_RETRIES {
                            nonce_retries += 1;
                            transient_retries = 0;
                            continue;
                        }
                        return Err(err);
                    }

                    if is_transient_error(&msg) && transient_retries < MAX_TRANSIENT_RETRIES {
                        transient_retries += 1;
                        sleep_transient_backoff(transient_retries).await;
                        continue;
                    }

                    return Err(err);
                }
            }
        }
    }

    /// Poll a staged tx through to a terminal `octra_transaction` status.
    ///
    /// This runs inside the serial actor on purpose: a `rejected`/`dropped`
    /// outcome means the ledger never consumed our nonce, so the cached
    /// `next` must be discarded BEFORE the next queued item signs —
    /// pipelining confirmation would let a whole run of wrong-nonce txs
    /// stage behind one rejection. The cost is throughput (roughly one tx
    /// per epoch through this queue), which the v4 loop's low-rate
    /// submitters (arm/claim/refund/sweep) absorb.
    async fn confirm_staged(&mut self, hash: String) -> CoreResult<String> {
        let started = Instant::now();
        for _ in 0..MAX_CONFIRM_POLLS {
            // Wait before every poll: octra_submit only stages
            // (rpc_view.ml:706-712) and nothing terminal can happen before
            // the next 10s epoch apply (epoch_time.ml:10-11) — polling
            // instantly would always read back "pending".
            sleep_confirm_poll().await;
            if started.elapsed() >= MAX_CONFIRM_WALL {
                break;
            }
            // Lookup failures are poll-transient: -32012 stable-read
            // retries, the brief staging->chaindata indexing gap at epoch
            // apply (healed lazily, history_read_rpc.ml:100-126), or plain
            // network luck. Keep polling inside the budget.
            let Ok(status) = self.rpc.transaction(&hash).await else {
                continue;
            };
            match status.get("status").and_then(Value::as_str) {
                Some("confirmed") => return self.check_confirmed_receipt(hash).await,
                Some("rejected") => {
                    // Rejected at epoch apply: the ledger never consumed this
                    // nonce, so the +1 taken at staging is wrong for the next
                    // item — reconcile from chain first, then surface the
                    // node-reported reason (shape: tx_view.ml:107-122).
                    self.next = None;
                    let err_type = status
                        .pointer("/error/type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let reason = status
                        .pointer("/error/reason")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    return Err(CoreError::Rpc(format!(
                        "tx {hash} rejected at epoch apply ({err_type}): {reason}"
                    )));
                }
                Some("dropped") => {
                    // Dropped from staging without ever applying — nonce not
                    // consumed (shape: tx_view.ml:124-136).
                    self.next = None;
                    let reason = status
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    let detail = status.get("detail").and_then(Value::as_str).unwrap_or("");
                    return Err(CoreError::Rpc(format!(
                        "tx {hash} dropped before apply: {reason} ({detail})"
                    )));
                }
                // "pending" (or an unrecognized status from a newer node):
                // the epoch has not applied it yet; keep waiting.
                _ => {}
            }
        }
        // Still pending after ~3 epochs. The tx is staged and holds our
        // nonce; nothing says it failed. Return the hash under the plain
        // staging semantics rather than erroring — an error here would
        // invite callers to resubmit an op that may yet confirm.
        Ok(hash)
    }

    /// Refine a confirmed tx with its execution receipt.
    ///
    /// "confirmed" only means the tx applied at an epoch; a contract call
    /// can still have reverted inside the VM. The receipt is authoritative
    /// for that: `{success, effort, events, error}` (contract_rpc.ml:765-780;
    /// written by store_chaindata.ml:217-229). The nonce IS consumed either
    /// way, so the cached `next` stays advanced.
    async fn check_confirmed_receipt(&self, hash: String) -> CoreResult<String> {
        match self.rpc.contract_receipt(&hash).await {
            Ok(receipt) if receipt.get("success").and_then(Value::as_bool) == Some(false) => {
                let error = receipt
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified");
                Err(CoreError::Rpc(format!(
                    "tx {hash} confirmed but reverted: {error}"
                )))
            }
            // A missing receipt is not a failure: non-call ops have none
            // (code 112 "not found"), and a read hiccup must not fail a tx
            // the chain has already confirmed.
            _ => Ok(hash),
        }
    }

    async fn reconcile_next_nonce(&self) -> CoreResult<u64> {
        let balance = self.rpc.balance(&self.wallet_addr).await?;
        Ok(next_nonce(&balance))
    }
}

fn sign_with_nonce(
    wallet: &KeyPair,
    chain_id: &str,
    mut call: Value,
    nonce: u64,
) -> CoreResult<Value> {
    // The real Octra signing preimage has NO chain_id field: the node
    // serializes exactly from/to_/amount/nonce/ou/timestamp/op_type
    // (+ optional encrypted_data/message) and verifies the ed25519 over
    // those bytes (lite_node transaction.ml:309-326, `serialize_for_signing`;
    // reference impl webcli/lib/tx_builder.hpp:78-106). Our tx signer treats
    // a chain_id key as opt-in "v2" binding and weaves it into the signed
    // bytes — bytes the node can never recompute — so inserting it would
    // fail every submission with code 101 "invalid signature". A non-empty
    // chain_id is therefore a configuration error; fail loudly instead of
    // silently dropping it, because an operator who set it would believe
    // they have cross-chain replay binding the chain does not provide.
    if !chain_id.is_empty() {
        return Err(CoreError::Rpc(format!(
            "chain tx queue misconfigured: chain_id {chain_id:?} is set, but the Octra \
             tx envelope has no chain_id field (transaction.ml serialize_for_signing); \
             signing with it would fail on-chain signature verification (code 101) — \
             unset chain_id"
        )));
    }
    let obj = call
        .as_object_mut()
        .ok_or_else(|| CoreError::Rpc("chain tx queue call must be a JSON object".to_string()))?;
    obj.insert("nonce".to_string(), json!(nonce));
    // Sign with OUR canonical port, not octra-foundry's `tx::sign_call`.
    // The foundry renders the timestamp with Rust's `Display for f64`,
    // which prints an integral value as `1755400000`; yojson — and so the
    // node's own `serialize_for_signing` — prints `1755400000.0`. That one
    // byte is a code 101, and it has stayed latent only because
    // `as_secs_f64()` lands on an exact second with vanishing probability.
    crate::tx_signer::sign_call_canonical(wallet, &call)
        .map_err(|e| CoreError::Crypto(format!("chain tx queue canonical sign: {e}")))
}

fn core_error_message(err: &CoreError) -> String {
    match err {
        CoreError::Rpc(msg) => msg.clone(),
        _ => err.to_string(),
    }
}

/// Return true for nonce rejects that require the queue to discard its
/// cached `next` value and reconcile from chain.
///
/// The node's staging validator has exactly two nonce errors: code 102
/// "invalid nonce" and code 103 "nonce too far ahead" (lite_node
/// lib/core/rpc.ml:29-30). Earlier revisions also matched Ethereum-style
/// strings ("nonce too low", "already used") that no Octra node emits;
/// those guesses were dropped once the node source became readable.
#[must_use]
pub fn is_nonce_error(msg: &str) -> bool {
    let msg = msg.to_ascii_lowercase();
    msg.contains("invalid nonce")
        || msg.contains("nonce too far ahead")
        || msg.contains("error 102")
        || msg.contains("code 102")
        || msg.contains("code: 102")
        || msg.contains("\"code\":102")
        || msg.contains("\"code\": 102")
        || msg.contains(" 102:")
        || msg.contains("error 103")
        || msg.contains("code 103")
        || msg.contains("\"code\":103")
}

fn is_transient_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    msg.starts_with("send ")
        || msg.contains("HTTP 5")
        // -32012 committed-state-changed: the node itself says "retry"
        // (node_rpc_server.ml:440-444, stable-read guard).
        || msg.contains("-32012")
        || lower.contains("timeout")
        || lower.contains("timed out")
}

async fn sleep_transient_backoff(retry: usize) {
    #[cfg(test)]
    let _ = retry;
    #[cfg(test)]
    let delay = Duration::ZERO;
    #[cfg(not(test))]
    let delay = {
        let millis = match retry {
            0 | 1 => 50,
            2 => 100,
            _ => 250,
        };
        Duration::from_millis(millis)
    };

    if delay.is_zero() {
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(delay).await;
    }
}

async fn sleep_confirm_poll() {
    #[cfg(test)]
    let delay = Duration::ZERO;
    // 2s cadence: fast enough to notice an epoch apply promptly, slow
    // enough that MAX_CONFIRM_POLLS spans ~3 epochs (see the constant).
    #[cfg(not(test))]
    let delay = Duration::from_secs(2);

    if delay.is_zero() {
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum SubmitStep {
        Ok,
        NonceErr,
        TransientErr,
        CommittedChangedErr,
        TerminalErr,
    }

    #[derive(Clone, Copy, Debug)]
    enum StatusStep {
        Pending,
        Confirmed,
        Rejected(&'static str),
        Dropped(&'static str),
        LookupErr,
    }

    #[derive(Clone, Copy, Debug)]
    enum ReceiptStep {
        NotFound,
        Success,
        Reverted(&'static str),
    }

    #[derive(Debug)]
    struct MockState {
        balances: VecDeque<(u64, u64)>,
        submit_steps: VecDeque<SubmitStep>,
        /// Scripted `octra_transaction` outcomes; an exhausted queue
        /// defaults to Confirmed so pre-confirmation tests keep their
        /// original shape.
        status_steps: VecDeque<StatusStep>,
        /// Scripted `contract_receipt` outcomes; an exhausted queue
        /// defaults to NotFound (treated as plain success).
        receipt_steps: VecDeque<ReceiptStep>,
        submitted_nonces: Vec<u64>,
        accepted_nonces: Vec<u64>,
        balance_calls: usize,
        submit_calls: u64,
        status_calls: usize,
        receipt_calls: usize,
        chain_last_used: u64,
    }

    #[derive(Clone, Debug)]
    struct MockRpc {
        state: Arc<Mutex<MockState>>,
    }

    impl MockRpc {
        fn new(
            chain_last_used: u64,
            balances: impl Into<VecDeque<(u64, u64)>>,
            submit_steps: impl Into<VecDeque<SubmitStep>>,
        ) -> (Self, Arc<Mutex<MockState>>) {
            let state = Arc::new(Mutex::new(MockState {
                balances: balances.into(),
                submit_steps: submit_steps.into(),
                status_steps: VecDeque::new(),
                receipt_steps: VecDeque::new(),
                submitted_nonces: Vec::new(),
                accepted_nonces: Vec::new(),
                balance_calls: 0,
                submit_calls: 0,
                status_calls: 0,
                receipt_calls: 0,
                chain_last_used,
            }));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl QueueRpc for MockRpc {
        async fn balance(&self, _addr: &Address) -> CoreResult<BalanceResult> {
            let mut state = self.state.lock().expect("mock state");
            state.balance_calls += 1;
            let fallback = (state.chain_last_used, state.chain_last_used);
            let (nonce, pending_nonce) = state.balances.pop_front().unwrap_or(fallback);
            Ok(balance(nonce, pending_nonce))
        }

        async fn submit(&self, signed_tx: &Value) -> CoreResult<SubmitResult> {
            let mut state = self.state.lock().expect("mock state");
            state.submit_calls += 1;
            let nonce = signed_tx
                .get("nonce")
                .and_then(Value::as_u64)
                .expect("signed tx carries nonce");
            state.submitted_nonces.push(nonce);
            // The wire envelope has no chain_id field, ever
            // (transaction.ml:309-326) -- enforce that at the mock chain
            // boundary for every test.
            assert!(
                signed_tx.get("chain_id").is_none(),
                "envelope must never carry chain_id"
            );
            match state.submit_steps.pop_front().unwrap_or(SubmitStep::Ok) {
                SubmitStep::Ok => {
                    state.accepted_nonces.push(nonce);
                    state.chain_last_used = state.chain_last_used.max(nonce);
                    Ok(SubmitResult {
                        hash: format!("{:064x}", state.submit_calls),
                        status: Some("accepted".to_string()),
                    })
                }
                SubmitStep::NonceErr => Err(CoreError::Rpc(
                    "rpc octra_submit error 102: invalid nonce".to_string(),
                )),
                SubmitStep::TransientErr => {
                    Err(CoreError::Rpc("rpc octra_submit HTTP 500".to_string()))
                }
                SubmitStep::CommittedChangedErr => Err(CoreError::Rpc(
                    "rpc octra_submit error -32012: committed state changed during read; retry"
                        .to_string(),
                )),
                SubmitStep::TerminalErr => Err(CoreError::Rpc(
                    "rpc octra_submit error -32000: rejected".to_string(),
                )),
            }
        }

        async fn transaction(&self, hash: &str) -> CoreResult<Value> {
            let mut state = self.state.lock().expect("mock state");
            state.status_calls += 1;
            match state
                .status_steps
                .pop_front()
                .unwrap_or(StatusStep::Confirmed)
            {
                StatusStep::Pending => Ok(json!({
                    "status": "pending", "tx_hash": hash, "epoch": null,
                })),
                StatusStep::Confirmed => Ok(json!({
                    "status": "confirmed", "tx_hash": hash, "epoch": 7,
                })),
                StatusStep::Rejected(reason) => Ok(json!({
                    "status": "rejected", "tx_hash": hash, "epoch": 7,
                    "error": {"type": "validation", "reason": reason},
                    "source": "rejected_txs",
                })),
                StatusStep::Dropped(reason) => Ok(json!({
                    "status": "dropped", "tx_hash": hash,
                    "reason": reason, "detail": "staging restart",
                })),
                StatusStep::LookupErr => Err(CoreError::Rpc(
                    "rpc octra_transaction error 112: not found".to_string(),
                )),
            }
        }

        async fn contract_receipt(&self, _hash: &str) -> CoreResult<Value> {
            let mut state = self.state.lock().expect("mock state");
            state.receipt_calls += 1;
            match state
                .receipt_steps
                .pop_front()
                .unwrap_or(ReceiptStep::NotFound)
            {
                ReceiptStep::NotFound => Err(CoreError::Rpc(
                    "rpc contract_receipt error 112: not found".to_string(),
                )),
                ReceiptStep::Success => Ok(json!({
                    "contract": "oct11111111111111111111111111111111111111111111",
                    "method": "noop", "success": true, "effort": 10,
                    "events": [], "error": null, "epoch": 7,
                })),
                ReceiptStep::Reverted(error) => Ok(json!({
                    "contract": "oct11111111111111111111111111111111111111111111",
                    "method": "noop", "success": false, "effort": 10,
                    "events": [], "error": error, "epoch": 7,
                })),
            }
        }
    }

    fn balance(nonce: u64, pending_nonce: u64) -> BalanceResult {
        BalanceResult {
            formatted: String::new(),
            raw: String::new(),
            nonce,
            pending_nonce,
            public_key: None,
        }
    }

    fn wallet() -> Arc<KeyPair> {
        Arc::new(KeyPair::from_secret_bytes(&[7u8; 32]))
    }

    fn sample_call(wallet: &KeyPair) -> Value {
        let from = Address::from_pubkey(&wallet.public.0).display().to_string();
        json!({
            "kind": "contract_call",
            "from": from,
            "to": "oct11111111111111111111111111111111111111111111",
            "method": "noop",
            "params": [],
            "value": 0u64,
            "fee": 1000u64,
            "nonce": 0u64,
            "timestamp": 0.0,
        })
    }

    #[tokio::test]
    async fn concurrent_submits_get_contiguous_unique_nonces() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from(vec![SubmitStep::Ok; 100]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());
        let call = sample_call(&wallet);

        let mut tasks = Vec::new();
        for _ in 0..100 {
            let handle = handle.clone();
            let call = call.clone();
            tasks.push(tokio::spawn(async move { handle.submit(call).await }));
        }
        for task in tasks {
            task.await.expect("submit task").expect("submit ok");
        }

        let state = state.lock().expect("mock state");
        let expected: Vec<u64> = (69..169).collect();
        assert_eq!(state.submitted_nonces, expected);
        assert_eq!(state.accepted_nonces, expected);
        assert_eq!(state.balance_calls, 1);
    }

    #[tokio::test]
    async fn non_empty_chain_id_is_a_configuration_error() {
        // The Octra envelope has no chain_id field (transaction.ml:309-326):
        // a configured id must fail fast at the queue, never reach the wire
        // as v2-signed bytes the node would 101.
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(68, VecDeque::from([(68, 68)]), VecDeque::new());
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());

        let err = handle
            .submit(sample_call(&wallet))
            .await
            .expect_err("configured chain_id must fail the submission");
        let msg = err.to_string();
        assert!(msg.contains("chain_id"), "unhelpful error: {msg}");
        assert!(
            msg.contains("101"),
            "should point at the on-chain symptom: {msg}"
        );

        let state = state.lock().expect("mock state");
        assert_eq!(state.submit_calls, 0, "nothing may reach the wire");
    }

    #[tokio::test]
    async fn nonce_error_forces_refetch_and_retries_corrected_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68), (80, 80)]),
            VecDeque::from([SubmitStep::NonceErr, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        let hash = handle.submit(sample_call(&wallet)).await.expect("submit");

        assert_eq!(hash, format!("{:064x}", 2));
        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 81]);
        assert_eq!(state.accepted_nonces, [81]);
        assert_eq!(state.balance_calls, 2);
    }

    #[tokio::test]
    async fn transient_error_reuses_same_nonce_before_advancing() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::TransientErr, SubmitStep::Ok, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        handle
            .submit(sample_call(&wallet))
            .await
            .expect("first submit");
        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");

        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 69, 70]);
        assert_eq!(state.accepted_nonces, [69, 70]);
        assert_eq!(state.balance_calls, 1);
    }

    #[tokio::test]
    async fn committed_state_changed_is_retried_on_same_nonce() {
        // -32012 is the node's stable-read "retry" answer
        // (node_rpc_server.ml:440-444): same nonce, no reconcile.
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::CommittedChangedErr, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        handle.submit(sample_call(&wallet)).await.expect("submit");

        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 69]);
        assert_eq!(state.accepted_nonces, [69]);
        assert_eq!(state.balance_calls, 1);
    }

    #[tokio::test]
    async fn cold_start_uses_next_nonce_from_balance_last_used_semantics() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        handle.submit(sample_call(&wallet)).await.expect("submit");

        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69]);
        assert_eq!(state.accepted_nonces, [69]);
    }

    #[tokio::test]
    async fn forced_reconcile_snaps_to_higher_chain_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            10,
            VecDeque::from([(10, 10), (30, 30)]),
            VecDeque::from([SubmitStep::Ok, SubmitStep::NonceErr, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        handle
            .submit(sample_call(&wallet))
            .await
            .expect("first submit");
        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");

        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [11, 12, 31]);
        assert_eq!(state.accepted_nonces, [11, 31]);
        assert_eq!(state.balance_calls, 2);
    }

    #[tokio::test]
    async fn terminal_error_does_not_advance_cached_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::TerminalErr, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        let err = handle
            .submit(sample_call(&wallet))
            .await
            .expect_err("terminal error");
        assert!(err.to_string().contains("rejected"));
        handle
            .submit(sample_call(&wallet))
            .await
            .expect("retry submit");

        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 69]);
        assert_eq!(state.accepted_nonces, [69]);
        assert_eq!(state.balance_calls, 1);
    }

    #[tokio::test]
    async fn pending_polls_until_confirmed() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::Ok]),
        );
        state.lock().expect("mock state").status_steps = VecDeque::from([
            StatusStep::Pending,
            StatusStep::LookupErr,
            StatusStep::Pending,
            StatusStep::Confirmed,
        ]);
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        handle.submit(sample_call(&wallet)).await.expect("submit");

        let state = state.lock().expect("mock state");
        assert_eq!(
            state.status_calls, 4,
            "poll rides out pending + lookup blips"
        );
        assert_eq!(state.receipt_calls, 1, "confirmed tx gets a receipt check");
    }

    #[tokio::test]
    async fn rejected_at_apply_surfaces_reason_and_reconciles_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            // Chain never consumed nonce 69: reconcile re-reads (68, 68).
            VecDeque::from([(68, 68), (68, 68)]),
            VecDeque::from([SubmitStep::Ok, SubmitStep::Ok]),
        );
        state.lock().expect("mock state").status_steps =
            VecDeque::from([StatusStep::Rejected("insufficient balance")]);
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        let err = handle
            .submit(sample_call(&wallet))
            .await
            .expect_err("rejected tx is terminal");
        let msg = err.to_string();
        assert!(msg.contains("rejected"), "{msg}");
        assert!(
            msg.contains("insufficient balance"),
            "reason must surface: {msg}"
        );

        // Next item must reconcile and reuse the unconsumed nonce.
        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");
        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 69]);
        assert_eq!(state.balance_calls, 2);
    }

    #[tokio::test]
    async fn dropped_surfaces_reason_and_reconciles_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68), (68, 68)]),
            VecDeque::from([SubmitStep::Ok, SubmitStep::Ok]),
        );
        state.lock().expect("mock state").status_steps =
            VecDeque::from([StatusStep::Dropped("staging evicted")]);
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        let err = handle
            .submit(sample_call(&wallet))
            .await
            .expect_err("dropped tx is terminal");
        let msg = err.to_string();
        assert!(msg.contains("dropped"), "{msg}");
        assert!(
            msg.contains("staging evicted"),
            "reason must surface: {msg}"
        );

        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");
        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 69]);
        assert_eq!(state.balance_calls, 2);
    }

    #[tokio::test]
    async fn reverted_receipt_errs_but_keeps_nonce_advanced() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::Ok, SubmitStep::Ok]),
        );
        state.lock().expect("mock state").receipt_steps = VecDeque::from([
            ReceiptStep::Reverted("relay: session not open"),
            ReceiptStep::Success,
        ]);
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        let err = handle
            .submit(sample_call(&wallet))
            .await
            .expect_err("reverted execution surfaces");
        let msg = err.to_string();
        assert!(msg.contains("reverted"), "{msg}");
        assert!(
            msg.contains("session not open"),
            "receipt error must surface: {msg}"
        );

        // A reverted call still consumed the nonce on-chain: no reconcile,
        // next item advances.
        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");
        let state = state.lock().expect("mock state");
        assert_eq!(state.submitted_nonces, [69, 70]);
        assert_eq!(state.balance_calls, 1);
    }

    #[tokio::test]
    async fn still_pending_after_budget_returns_staged_hash() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::Ok, SubmitStep::Ok]),
        );
        // Exactly one budget's worth of "pending": the first submit must
        // stop at MAX_CONFIRM_POLLS, leaving the second submit to confirm
        // on its first (default) poll.
        state.lock().expect("mock state").status_steps =
            VecDeque::from(vec![StatusStep::Pending; MAX_CONFIRM_POLLS]);
        let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());

        // The tx never leaves staging inside the budget: degrade to the
        // plain staging semantics (hash back, nonce stays advanced) rather
        // than a resubmit-inviting error.
        let hash = handle.submit(sample_call(&wallet)).await.expect("staged");
        assert_eq!(hash, format!("{:064x}", 1));

        handle
            .submit(sample_call(&wallet))
            .await
            .expect("second submit");
        let state = state.lock().expect("mock state");
        assert_eq!(
            state.status_calls,
            MAX_CONFIRM_POLLS + 1,
            "budget bounds the poll loop"
        );
        assert_eq!(state.submitted_nonces, [69, 70]);
        assert_eq!(state.balance_calls, 1);
    }

    #[test]
    fn detects_nonce_error_variants() {
        assert!(is_nonce_error("octra_submit error 102: invalid nonce"));
        assert!(is_nonce_error(
            "octra_submit error 103: nonce too far ahead"
        ));
        assert!(is_nonce_error(r#"{"code":102,"message":"bad"}"#));
        assert!(!is_nonce_error("rpc octra_submit HTTP 500"));
        // Ethereum-isms the Octra node never emits (lib/core/rpc.ml:29-30)
        // must no longer trigger a reconcile.
        assert!(!is_nonce_error("nonce too low"));
        assert!(!is_nonce_error("already used"));
    }

    #[test]
    fn committed_state_changed_is_transient() {
        assert!(is_transient_error(
            "rpc octra_submit error -32012: committed state changed during read; retry"
        ));
        assert!(!is_transient_error(
            "rpc octra_submit error -32000: rejected"
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_ok_nonces_increment_once_per_success(
            start_last_used in 0u64..10_000,
            actions in prop::collection::vec(0u8..3, 1..40),
        ) {
            let action_count = actions.len();
            let mut steps = VecDeque::new();
            for action in actions {
                match action {
                    0 => steps.push_back(SubmitStep::Ok),
                    1 => {
                        steps.push_back(SubmitStep::NonceErr);
                        steps.push_back(SubmitStep::Ok);
                    }
                    _ => {
                        steps.push_back(SubmitStep::TransientErr);
                        steps.push_back(SubmitStep::Ok);
                    }
                }
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            let accepted = rt.block_on(async move {
                let wallet = wallet();
                let (rpc, state) = MockRpc::new(
                    start_last_used,
                    VecDeque::from([(start_last_used, start_last_used)]),
                    steps,
                );
                let handle = spawn_with_rpc(rpc, wallet.clone(), String::new());
                let call = sample_call(&wallet);
                for _ in 0..action_count {
                    handle.submit(call.clone()).await.expect("submit ok");
                }
                let accepted = state.lock().expect("mock state").accepted_nonces.clone();
                accepted
            });

            let expected: Vec<u64> = ((start_last_used + 1)..=(start_last_used + action_count as u64)).collect();
            prop_assert_eq!(accepted, expected);
        }
    }
}
