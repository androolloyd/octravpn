//! Single-owner nonce queue for Octra transaction submission.
//!
//! The queue serializes operator-signed submissions behind one actor so
//! callers cannot race by independently fetching the same account nonce.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::{
    address::Address,
    rpc::{next_nonce, BalanceResult, RpcClient, SubmitResult},
    tx, CoreError, CoreResult, KeyPair,
};

const QUEUE_CAPACITY: usize = 1024;
const MAX_NONCE_RETRIES: usize = 1;
const MAX_TRANSIENT_RETRIES: usize = 3;

#[derive(Clone)]
pub struct ChainTxQueueHandle {
    tx: mpsc::Sender<SubmitRequest>,
}

impl ChainTxQueueHandle {
    /// Submit an unsigned contract-call envelope through the nonce owner.
    ///
    /// The caller may pass a placeholder `nonce`; the queue overwrites it
    /// immediately before signing.
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
}

#[async_trait]
impl QueueRpc for RpcClient {
    async fn balance(&self, addr: &Address) -> CoreResult<BalanceResult> {
        RpcClient::balance(self, addr).await
    }

    async fn submit(&self, signed_tx: &Value) -> CoreResult<SubmitResult> {
        RpcClient::submit(self, signed_tx).await
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
                    self.next = nonce.checked_add(1);
                    return Ok(result.hash);
                }
                Err(err) => {
                    let msg = core_error_message(&err);
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
    let obj = call
        .as_object_mut()
        .ok_or_else(|| CoreError::Rpc("chain tx queue call must be a JSON object".to_string()))?;
    obj.insert("nonce".to_string(), json!(nonce));
    if !chain_id.is_empty() {
        obj.entry("chain_id".to_string())
            .or_insert_with(|| json!(chain_id));
    }
    tx::sign_call(wallet, call)
        .map_err(|e| CoreError::Crypto(format!("chain tx queue sign_call: {e}")))
}

fn core_error_message(err: &CoreError) -> String {
    match err {
        CoreError::Rpc(msg) => msg.clone(),
        _ => err.to_string(),
    }
}

/// Return true for nonce rejects that require the queue to discard its
/// cached `next` value and reconcile from chain.
#[must_use]
pub fn is_nonce_error(msg: &str) -> bool {
    let msg = msg.to_ascii_lowercase();
    msg.contains("invalid nonce")
        || msg.contains("nonce too low")
        || msg.contains("already used")
        || msg.contains("error 102")
        || msg.contains("code 102")
        || msg.contains("code: 102")
        || msg.contains("\"code\":102")
        || msg.contains("\"code\": 102")
        || msg.contains(" 102:")
}

fn is_transient_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    msg.starts_with("send ")
        || msg.contains("HTTP 5")
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
        TerminalErr,
    }

    #[derive(Debug)]
    struct MockState {
        balances: VecDeque<(u64, u64)>,
        submit_steps: VecDeque<SubmitStep>,
        submitted_nonces: Vec<u64>,
        accepted_nonces: Vec<u64>,
        submitted_chain_ids: Vec<Option<String>>,
        balance_calls: usize,
        submit_calls: u64,
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
                submitted_nonces: Vec::new(),
                accepted_nonces: Vec::new(),
                submitted_chain_ids: Vec::new(),
                balance_calls: 0,
                submit_calls: 0,
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
            state.submitted_chain_ids.push(
                signed_tx
                    .get("chain_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
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
                SubmitStep::TerminalErr => Err(CoreError::Rpc(
                    "rpc octra_submit error -32000: rejected".to_string(),
                )),
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
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());
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
        assert!(state
            .submitted_chain_ids
            .iter()
            .all(|id| id.as_deref() == Some("octra-devnet")));
    }

    #[tokio::test]
    async fn nonce_error_forces_refetch_and_retries_corrected_nonce() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68), (80, 80)]),
            VecDeque::from([SubmitStep::NonceErr, SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());

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
        assert!(state.submitted_chain_ids.iter().all(Option::is_none));
    }

    #[tokio::test]
    async fn cold_start_uses_next_nonce_from_balance_last_used_semantics() {
        let wallet = wallet();
        let (rpc, state) = MockRpc::new(
            68,
            VecDeque::from([(68, 68)]),
            VecDeque::from([SubmitStep::Ok]),
        );
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());

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
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());

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
        let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());

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

    #[test]
    fn detects_nonce_error_variants() {
        assert!(is_nonce_error("octra_submit error 102: invalid nonce"));
        assert!(is_nonce_error("nonce too low"));
        assert!(is_nonce_error("already used"));
        assert!(is_nonce_error(r#"{"code":102,"message":"bad"}"#));
        assert!(!is_nonce_error("rpc octra_submit HTTP 500"));
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
                let handle = spawn_with_rpc(rpc, wallet.clone(), "octra-devnet".to_string());
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
