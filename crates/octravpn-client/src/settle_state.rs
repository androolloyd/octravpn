//! Durable client-side v4 relay settlement state.
//!
//! The money-path invariant is intentionally simple: no `arm_relay`
//! broadcast unless the per-session durable floor is exactly
//! `Countersigned(2)`. That floor is written only after the operator
//! accepted the countersigned receipt handback.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use octravpn_core::{
    address::Address,
    receipt::SignedReceipt,
    receipt_journal::{FsyncPolicy, ReceiptJournal},
    receipt_vault::ReceiptVault,
    session::SessionId,
};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::settler;

/// `program/main-v4.aml` ON-CHAIN session statuses (what `get_session_status`
/// returns). Distinct namespace from the durable ladder codes below (they
/// overlap numerically but are used in different contexts). A session leaves
/// `SESSION_OPEN` only forward: to `RELAY_ARMED` or straight to a terminal.
pub(crate) const SESSION_OPEN: u64 = 0;
pub(crate) const SESSION_RELAY_ARMED: u64 = 3;
pub(crate) const SESSION_RELAY_CLAIMED: u64 = 4;
pub(crate) const SESSION_RELAY_REFUNDED: u64 = 5;

/// Durable client settlement ladder (the `settle_state.bin` floor per session).
/// Forward-only; terminals (`Refunded`/`Settled`) are appended strictly ABOVE
/// the `RefundSubmitted` write-ahead rung so a drain always bumps. Because the
/// AML makes relay_claim (`epoch < D`) and relay_refund (`epoch >= D`) disjoint,
/// exactly one terminal is ever written per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SettlementState {
    Proposed = 1,
    Countersigned = 2,
    ArmSubmitted = 3,
    ArmConfirmed = 4,
    /// Write-ahead: `relay_refund` broadcast, not yet confirmed. Non-terminal.
    RefundSubmitted = 5,
    /// Terminal: chain confirmed `SESSION_RELAY_REFUNDED` (deposit returned).
    Refunded = 6,
    /// Terminal: chain confirmed `SESSION_RELAY_CLAIMED` (operator won; the
    /// client must NOT refund).
    Settled = 7,
}

impl SettlementState {
    fn code(self) -> u64 {
        self as u64
    }

    fn from_code(code: u64) -> Result<Option<Self>> {
        Ok(match code {
            0 => None,
            1 => Some(Self::Proposed),
            2 => Some(Self::Countersigned),
            3 => Some(Self::ArmSubmitted),
            4 => Some(Self::ArmConfirmed),
            5 => Some(Self::RefundSubmitted),
            6 => Some(Self::Refunded),
            7 => Some(Self::Settled),
            other => bail!("unknown settle_state floor code {other}"),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SettleStatePaths {
    pub(crate) wallet_dir: PathBuf,
    pub(crate) settle_state: PathBuf,
    pub(crate) arm_net: PathBuf,
    pub(crate) client_receipts: PathBuf,
}

impl SettleStatePaths {
    pub(crate) fn for_wallet(state_dir: impl AsRef<Path>, wallet_addr: &Address) -> Self {
        let wallet_dir = state_dir.as_ref().join(wallet_addr.display());
        Self {
            settle_state: wallet_dir.join("settle_state.bin"),
            arm_net: wallet_dir.join("arm_net.bin"),
            client_receipts: wallet_dir.join("client_receipts.bin"),
            wallet_dir,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SettleStateStore {
    paths: SettleStatePaths,
    state: ReceiptJournal,
    arm_net: ReceiptJournal,
    receipts: ReceiptVault,
}

#[derive(Clone, Debug)]
pub(crate) struct ArmEnvironment {
    pub(crate) program_addr: Address,
    pub(crate) wallet_addr: Address,
    pub(crate) relay_expiry_epochs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ArmSubmission {
    pub(crate) session_id: u64,
    pub(crate) tx_hash: String,
    pub(crate) settlement_hash: String,
    pub(crate) net: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReplaySummary {
    pub(crate) proposed_left_alone: usize,
    pub(crate) countersigned_armed: usize,
    pub(crate) submitted_confirmed: usize,
    pub(crate) submitted_resubmitted: usize,
    pub(crate) already_confirmed: usize,
}

#[async_trait]
pub(crate) trait ArmChain: Send + Sync {
    async fn arm_fee(&self) -> Result<u64>;
    async fn submit_arm_call(&self, call: Value) -> Result<String>;
    async fn get_session_status(&self, session_id: u64) -> Result<u64>;
}

/// The chain surface the refund watcher needs. Extracted as a trait (like
/// `ArmChain`) so the two-pass drain/submit logic is testable with a mock chain.
#[async_trait]
pub(crate) trait RefundChain: Send + Sync {
    async fn refund_fee(&self) -> Result<u64>;
    /// STRICT: a bad body is an Err (skip/retry), never a phantom 0.
    async fn get_session_status_strict(&self, session_id: u64) -> Result<u64>;
    async fn get_relay_deadline(&self, session_id: u64) -> Result<u64>;
    /// Current epoch (float-truncated LOWER bound; only ever delays a refund).
    async fn current_epoch(&self) -> Result<u64>;
    async fn submit_refund_call(&self, call: Value) -> Result<String>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RefundSummary {
    pub(crate) refund_submitted: usize,
    pub(crate) drained_refunded: usize,
    pub(crate) drained_settled: usize,
}

impl SettleStateStore {
    pub(crate) fn open(state_dir: impl AsRef<Path>, wallet_addr: &Address) -> Result<Self> {
        let paths = SettleStatePaths::for_wallet(state_dir, wallet_addr);
        let state = ReceiptJournal::open(paths.settle_state.clone())
            .with_context(|| format!("open {}", paths.settle_state.display()))?;
        state.set_fsync_policy(FsyncPolicy::EveryWrite);
        let arm_net = ReceiptJournal::open(paths.arm_net.clone())
            .with_context(|| format!("open {}", paths.arm_net.display()))?;
        arm_net.set_fsync_policy(FsyncPolicy::EveryWrite);
        let receipts = ReceiptVault::open(paths.client_receipts.clone())
            .with_context(|| format!("open {}", paths.client_receipts.display()))?;
        Ok(Self {
            paths,
            state,
            arm_net,
            receipts,
        })
    }

    pub(crate) fn paths(&self) -> &SettleStatePaths {
        &self.paths
    }

    pub(crate) fn state(&self, session_id: &SessionId) -> Result<Option<SettlementState>> {
        SettlementState::from_code(self.state.floor(session_id))
    }

    pub(crate) fn state_entries(&self) -> Result<Vec<(SessionId, SettlementState)>> {
        self.state
            .entries()
            .into_iter()
            .map(|(id, code)| {
                let state = SettlementState::from_code(code)?
                    .ok_or_else(|| anyhow!("settle_state entries contained zero floor"))?;
                Ok((id, state))
            })
            .collect()
    }

    pub(crate) fn record_proposed(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::Proposed)
    }

    pub(crate) fn record_countersigned(
        &self,
        session_id: &SessionId,
        receipt: &SignedReceipt,
        net: u64,
    ) -> Result<()> {
        if matches!(
            self.state(session_id)?,
            Some(
                SettlementState::Countersigned
                    | SettlementState::ArmSubmitted
                    | SettlementState::ArmConfirmed
            )
        ) {
            let (existing, existing_net) = self.arm_material(session_id)?;
            if existing == *receipt && existing_net == net {
                return Ok(());
            }
            bail!(
                "countersigned relay material already frozen for session {}",
                session_id.to_hex()
            );
        }

        self.receipts
            .put(session_id, receipt)
            .context("store client countersigned receipt")?;
        self.record_arm_net(session_id, net)?;
        self.bump_state(session_id, SettlementState::Countersigned)
    }

    pub(crate) async fn arm_if_countersigned<C: ArmChain>(
        &self,
        chain: &C,
        env: &ArmEnvironment,
        session_id: &SessionId,
    ) -> Result<Option<ArmSubmission>> {
        let state = self.state(session_id)?;
        if state != Some(SettlementState::Countersigned) {
            return Ok(None);
        }
        // A relay session that owes net==0 (sub-MiB usage or zero price) has
        // nothing to settle on chain: arm_relay requires net>0 and would revert
        // terminally, leaving the ladder stuck at ArmSubmitted and re-broadcasting
        // a doomed tx on every boot. Skip arming; the countersigned receipt stays
        // stashed for any off-chain dispute. (Defensive -- the auto path skips
        // recording net==0 and the CLI rejects it, so nothing should record one.)
        if self.arm_material(session_id)?.1 == 0 {
            tracing::debug!(
                session = %session_id.to_hex(),
                "relay net is 0; nothing to settle on chain, skipping arm_relay"
            );
            return Ok(None);
        }
        // AUDIT #4 (I6 write-ahead): record ArmSubmitted BEFORE broadcasting, so a
        // crash after the tx reaches the chain (but before we could record it) does
        // NOT leave us stuck at Countersigned and re-broadcast a duplicate arm. If
        // the broadcast itself fails, replay sees ArmSubmitted + not-yet-armed and
        // re-submits (idempotent), promoting to ArmConfirmed once the chain is armed.
        self.record_arm_submitted(session_id)?;
        let submitted = self.submit_arm_from_journal(chain, env, session_id).await?;
        Ok(Some(submitted))
    }

    pub(crate) fn record_arm_submitted(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::ArmSubmitted)
    }

    pub(crate) fn record_arm_confirmed(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::ArmConfirmed)
    }

    /// Write-ahead (I6): record a `relay_refund` broadcast BEFORE it hits the
    /// wire, so a crash mid-broadcast does not re-refund on the next boot.
    pub(crate) fn record_refund_submitted(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::RefundSubmitted)
    }

    /// Terminal: chain confirmed the deposit was refunded to the funder.
    pub(crate) fn record_refunded(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::Refunded)
    }

    /// Terminal: chain confirmed the operator claimed (RELAY_CLAIMED); the client
    /// must stop trying to refund this session.
    pub(crate) fn record_settled(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::Settled)
    }

    pub(crate) async fn replay_pending<C: ArmChain>(
        &self,
        chain: &C,
        env: &ArmEnvironment,
    ) -> Result<ReplaySummary> {
        let mut summary = ReplaySummary::default();
        for (session_id, state) in self.state_entries()? {
            match state {
                SettlementState::Proposed => {
                    summary.proposed_left_alone += 1;
                }
                SettlementState::Countersigned => {
                    if self
                        .arm_if_countersigned(chain, env, &session_id)
                        .await?
                        .is_some()
                    {
                        summary.countersigned_armed += 1;
                    }
                }
                SettlementState::ArmSubmitted => {
                    let sid = session_id
                        .as_u64()
                        .ok_or_else(|| anyhow!("v4 relay settlement requires u64 session ids"))?;
                    let status = chain
                        .get_session_status(sid)
                        .await
                        .with_context(|| format!("get_session_status({sid})"))?;
                    if status == SESSION_OPEN {
                        // Arm not yet on chain -> re-broadcast (idempotent). ONLY
                        // for SESSION_OPEN: any other status means the session has
                        // moved past OPEN -- RELAY_ARMED (arm landed, awaiting
                        // claim) or a terminal outcome (SETTLED/REFUNDED/
                        // RELAY_CLAIMED/RELAY_REFUNDED) -- where a re-broadcast
                        // arm_relay reverts "session not open" and burns a fee on
                        // every boot. RELAY_CLAIMED is the mainline terminal
                        // outcome now that claims succeed, so freeze the floor
                        // instead of resubmitting forever.
                        self.submit_arm_from_journal(chain, env, &session_id)
                            .await?;
                        self.record_arm_submitted(&session_id)?;
                        summary.submitted_resubmitted += 1;
                    } else {
                        self.record_arm_confirmed(&session_id)?;
                        summary.submitted_confirmed += 1;
                    }
                }
                SettlementState::ArmConfirmed => {
                    summary.already_confirmed += 1;
                }
                // The refund watcher (a separate pass) owns these rungs; the arm
                // replay leaves them strictly alone. Explicit arms, never a
                // `_ =>` catch-all: a future ladder state must force a compile
                // error here rather than silently re-arming a terminal session.
                SettlementState::RefundSubmitted
                | SettlementState::Refunded
                | SettlementState::Settled => {}
            }
        }
        Ok(summary)
    }

    /// Funder-side mirror of the node claimer: refund an armed session whose
    /// operator NO-SHOWED (never claimed) so the deposit returns to the funder.
    /// Two ordered passes over the durable ladder, candidates in
    /// `{ArmConfirmed, RefundSubmitted}`:
    ///   1. DRAIN — promote to a terminal (`Refunded`/`Settled`) purely from an
    ///      EXACT positive strict on-chain status match; a bad read leaves it.
    ///   2. SUBMIT — reveal a `relay_refund` only when the session is still
    ///      RELAY_ARMED and `epoch >= deadline + margin` (the I3 refund window,
    ///      strictly after the claim window), write-ahead first.
    /// One-shot (boot scan + CLI), so no in-flight-grace loop is needed; a
    /// still-unconfirmed refund is naturally re-attempted only on the next run.
    pub(crate) async fn refund_pending<C: RefundChain>(
        &self,
        chain: &C,
        env: &ArmEnvironment,
        refund_margin: u64,
    ) -> Result<RefundSummary> {
        let mut summary = RefundSummary::default();

        // ---- PASS 1: DRAIN (terminal only from an exact positive strict match) ----
        for (session_id, state) in self.state_entries()? {
            if !matches!(
                state,
                SettlementState::ArmConfirmed | SettlementState::RefundSubmitted
            ) {
                continue;
            }
            let Some(sid) = session_id.as_u64() else {
                continue;
            };
            match chain.get_session_status_strict(sid).await {
                Ok(SESSION_RELAY_REFUNDED) => {
                    self.record_refunded(&session_id)?;
                    summary.drained_refunded += 1;
                }
                Ok(SESSION_RELAY_CLAIMED) => {
                    // Operator won the race; stop trying to refund this session.
                    self.record_settled(&session_id)?;
                    summary.drained_settled += 1;
                }
                Ok(_) => {}
                Err(e) => {
                    debug!(session = sid, error = %e, "refund confirm-drain read failed; retry next scan");
                }
            }
        }

        // ---- PASS 2: SUBMIT (fresh strict re-read + margin gate pre-broadcast) ----
        for (session_id, state) in self.state_entries()? {
            if !matches!(
                state,
                SettlementState::ArmConfirmed | SettlementState::RefundSubmitted
            ) {
                continue;
            }
            let Some(sid) = session_id.as_u64() else {
                continue;
            };
            let status = match chain.get_session_status_strict(sid).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(session = sid, error = %e, "refund status read failed; skip this scan");
                    continue;
                }
            };
            // Only a still-RELAY_ARMED session is refundable; a claimed/refunded
            // one is handled by the drain pass, not re-submitted here.
            if status != SESSION_RELAY_ARMED {
                continue;
            }
            let deadline = match chain.get_relay_deadline(sid).await {
                Ok(d) => d,
                Err(e) => {
                    debug!(session = sid, error = %e, "relay deadline read failed; skip");
                    continue;
                }
            };
            let epoch = match chain.current_epoch().await {
                Ok(e) => e,
                Err(e) => {
                    debug!(session = sid, error = %e, "current epoch read failed; skip");
                    continue;
                }
            };
            // I3 refund window [D + k_r, inf): strictly after the operator's claim
            // window (-inf, D - k_c]. epoch is a LOWER bound, so a conservative
            // read only delays -- it can never fire early into the claim window.
            if epoch < deadline.saturating_add(refund_margin) {
                continue;
            }
            // WRITE-AHEAD (I6): record the intent BEFORE the broadcast so a crash
            // mid-submit does not re-refund on the next boot.
            self.record_refund_submitted(&session_id)?;
            let fee = match chain.refund_fee().await {
                Ok(f) => f,
                Err(e) => {
                    debug!(session = sid, error = %e, "refund fee read failed; skip (retry next scan)");
                    continue;
                }
            };
            let call =
                settler::build_relay_refund_params(&env.program_addr, &env.wallet_addr, sid, fee);
            // Best-effort: the durable RefundSubmitted floor means the next scan
            // re-submits (still RELAY_ARMED) or drains (if it actually landed), so
            // a transient submit failure must NOT abort the scan (or, via boot,
            // the whole client) -- refunding your own deposit has no downside.
            match chain.submit_refund_call(call).await {
                Ok(tx_hash) => {
                    info!(hash = %tx_hash, session = sid, "relay_refund submitted (operator no-show)");
                    summary.refund_submitted += 1;
                }
                Err(e) => {
                    warn!(session = sid, error = %e, "relay_refund submit failed; will retry next scan");
                }
            }
        }
        Ok(summary)
    }

    pub(crate) fn arm_material(&self, session_id: &SessionId) -> Result<(SignedReceipt, u64)> {
        let receipt = self
            .receipts
            .get(session_id)
            .ok_or_else(|| anyhow!("missing client receipt for session {}", session_id.to_hex()))?;
        let net = self
            .arm_net(session_id)?
            .ok_or_else(|| anyhow!("missing arm net for session {}", session_id.to_hex()))?;
        Ok((receipt, net))
    }

    async fn submit_arm_from_journal<C: ArmChain>(
        &self,
        chain: &C,
        env: &ArmEnvironment,
        session_id: &SessionId,
    ) -> Result<ArmSubmission> {
        let sid = session_id
            .as_u64()
            .ok_or_else(|| anyhow!("v4 relay settlement requires u64 session ids"))?;
        let (receipt, net) = self.arm_material(session_id)?;
        let settlement_hash = receipt.settlement_hash();
        let fee = chain.arm_fee().await?;
        let call = settler::build_arm_params(
            &env.program_addr,
            &env.wallet_addr,
            sid,
            &settlement_hash,
            net,
            env.relay_expiry_epochs,
            fee,
        );
        let tx_hash = chain
            .submit_arm_call(call)
            .await
            .with_context(|| format!("submit arm_relay({sid})"))?;
        info!(
            hash = %tx_hash,
            session = sid,
            settlement_hash = %settlement_hash,
            net,
            relay_expiry_epochs = env.relay_expiry_epochs,
            "arm_relay submitted"
        );
        Ok(ArmSubmission {
            session_id: sid,
            tx_hash,
            settlement_hash,
            net,
        })
    }

    fn bump_state(&self, session_id: &SessionId, next: SettlementState) -> Result<()> {
        let cur = self.state.floor(session_id);
        if cur >= next.code() {
            return Ok(());
        }
        SettlementState::from_code(cur)?;
        self.state.bump(session_id, next.code()).with_context(|| {
            format!(
                "record settle state {:?} for session {}",
                next,
                session_id.to_hex()
            )
        })
    }

    fn record_arm_net(&self, session_id: &SessionId, net: u64) -> Result<()> {
        let encoded = net
            .checked_add(1)
            .ok_or_else(|| anyhow!("arm net is too large to encode: {net}"))?;
        let cur = self.arm_net.floor(session_id);
        if cur != 0 {
            let existing = cur - 1;
            if existing == net {
                return Ok(());
            }
            bail!(
                "arm net conflict for session {}: existing={} new={}",
                session_id.to_hex(),
                existing,
                net
            );
        }
        self.arm_net
            .bump(session_id, encoded)
            .with_context(|| format!("record arm net for session {}", session_id.to_hex()))
    }

    fn arm_net(&self, session_id: &SessionId) -> Result<Option<u64>> {
        let raw = self.arm_net.floor(session_id);
        Ok(if raw == 0 { None } else { Some(raw - 1) })
    }
}

pub(crate) async fn replay_pending_for_client(client: &crate::runner::Client) -> Result<()> {
    if !client.relay_config().enabled {
        return Ok(());
    }
    let store = client.open_settle_state()?;
    let env = client.arm_environment();
    let summary = store.replay_pending(client, &env).await?;
    if summary != ReplaySummary::default() {
        info!(
            proposed_left_alone = summary.proposed_left_alone,
            countersigned_armed = summary.countersigned_armed,
            submitted_confirmed = summary.submitted_confirmed,
            submitted_resubmitted = summary.submitted_resubmitted,
            already_confirmed = summary.already_confirmed,
            state_dir = %store.paths().wallet_dir.display(),
            "settlement replay scan complete"
        );
    }

    // Step 8: refund watcher. Catches an operator no-show that only became
    // refundable while the client was offline for days. Always runs when relay
    // is enabled -- refunding your own deposit has no downside beyond one fee.
    // NON-FATAL: this is best-effort background work at boot; a transient failure
    // must never abort client startup (the write-ahead makes it self-heal on the
    // next launch). The explicit `settle refund` CLI still surfaces errors.
    let refund_margin = client.relay_config().resolved_refund_margin_epochs();
    match store.refund_pending(client, &env, refund_margin).await {
        Ok(refund) if refund != RefundSummary::default() => info!(
            refund_submitted = refund.refund_submitted,
            drained_refunded = refund.drained_refunded,
            drained_settled = refund.drained_settled,
            state_dir = %store.paths().wallet_dir.display(),
            "relay refund scan complete"
        ),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "boot relay-refund scan failed; retrying next launch"),
    }
    Ok(())
}

#[async_trait]
impl ArmChain for crate::runner::Client {
    async fn arm_fee(&self) -> Result<u64> {
        Ok(self
            .rpc()
            .recommended_fee(Some("contract_call"))
            .await
            .ok()
            .map(|f| f.recommended)
            .filter(|f| *f > 0)
            .unwrap_or(crate::chain_v3::CALL_FEE_FALLBACK))
    }

    async fn submit_arm_call(&self, call: Value) -> Result<String> {
        settler::submit_arm(self, call).await
    }

    async fn get_session_status(&self, session_id: u64) -> Result<u64> {
        let ctx =
            crate::chain_v3::ChainCtxV3::new(self.rpc(), self.program_addr(), self.wallet_kp());
        ctx.get_session_status(session_id).await
    }
}

#[async_trait]
impl RefundChain for crate::runner::Client {
    async fn refund_fee(&self) -> Result<u64> {
        Ok(self
            .rpc()
            .recommended_fee(Some("contract_call"))
            .await
            .ok()
            .map(|f| f.recommended)
            .filter(|f| *f > 0)
            .unwrap_or(crate::chain_v3::CALL_FEE_FALLBACK))
    }

    async fn get_session_status_strict(&self, session_id: u64) -> Result<u64> {
        let ctx =
            crate::chain_v3::ChainCtxV3::new(self.rpc(), self.program_addr(), self.wallet_kp());
        ctx.get_session_status_strict(session_id).await
    }

    async fn get_relay_deadline(&self, session_id: u64) -> Result<u64> {
        let ctx =
            crate::chain_v3::ChainCtxV3::new(self.rpc(), self.program_addr(), self.wallet_kp());
        ctx.get_relay_deadline(session_id).await
    }

    async fn current_epoch(&self) -> Result<u64> {
        let ctx =
            crate::chain_v3::ChainCtxV3::new(self.rpc(), self.program_addr(), self.wallet_kp());
        ctx.current_epoch().await
    }

    async fn submit_refund_call(&self, call: Value) -> Result<String> {
        settler::submit_refund(self, call).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs::OpenOptions, io::Write};

    use octravpn_core::{
        receipt::{Receipt, ReceiptContext, CHAIN_ID_TEST},
        session::Blind,
        sig::KeyPair,
    };
    use parking_lot::Mutex;
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct MockChain {
        fee_calls: Mutex<usize>,
        submit_calls: Mutex<Vec<Value>>,
        statuses: Mutex<VecDeque<u64>>,
    }

    #[async_trait]
    impl ArmChain for MockChain {
        async fn arm_fee(&self) -> Result<u64> {
            *self.fee_calls.lock() += 1;
            Ok(500)
        }

        async fn submit_arm_call(&self, call: Value) -> Result<String> {
            self.submit_calls.lock().push(call);
            Ok("arm-tx".to_string())
        }

        async fn get_session_status(&self, _session_id: u64) -> Result<u64> {
            Ok(self.statuses.lock().pop_front().unwrap_or(0))
        }
    }

    fn addr(byte: u8) -> Address {
        Address::from_pubkey(&[byte; 32])
    }

    fn env() -> ArmEnvironment {
        ArmEnvironment {
            program_addr: addr(0x33),
            wallet_addr: addr(0x44),
            relay_expiry_epochs: 200,
        }
    }

    fn store(dir: &Path) -> SettleStateStore {
        SettleStateStore::open(dir, &addr(0x44)).unwrap()
    }

    fn id(n: u64) -> SessionId {
        SessionId::from_u64(n)
    }

    fn signed(session_id: SessionId, seq: u64, bytes_used: u64) -> SignedReceipt {
        let client = KeyPair::from_secret_bytes(&[0x11; 32]);
        let node = KeyPair::from_secret_bytes(&[0x22; 32]);
        let ctx = ReceiptContext::v1_1(addr(0x33), CHAIN_ID_TEST);
        SignedReceipt::build(
            Receipt::new(ctx, session_id, seq, bytes_used, Blind::new([0x55; 32])),
            &client,
            &node,
        )
    }

    #[test]
    fn forward_only_ladder_equal_and_backward_are_noops() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(7);

        s.record_proposed(&sid).unwrap();
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Proposed));
        s.record_proposed(&sid).unwrap();
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Proposed));

        s.record_arm_submitted(&sid).unwrap();
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::ArmSubmitted));
        s.record_proposed(&sid).unwrap();
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::ArmSubmitted));
    }

    #[test]
    fn countersigned_material_freezes_at_countersigned_floor() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(70);
        let receipt = signed(sid.clone(), 1, 123);
        s.record_proposed(&sid).unwrap();
        s.record_countersigned(&sid, &receipt, 99).unwrap();
        s.record_countersigned(&sid, &receipt, 99).unwrap();

        let err = s
            .record_countersigned(&sid, &signed(sid.clone(), 2, 123), 99)
            .unwrap_err();

        assert!(err.to_string().contains("already frozen"));
        assert_eq!(s.arm_material(&sid).unwrap().0, receipt);
    }

    #[tokio::test]
    async fn arm_if_countersigned_skips_before_ack_floor() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(8);
        let chain = MockChain::default();
        s.record_proposed(&sid).unwrap();

        let out = s.arm_if_countersigned(&chain, &env(), &sid).await.unwrap();

        assert!(out.is_none());
        assert_eq!(*chain.fee_calls.lock(), 0);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Proposed));
    }

    #[tokio::test]
    async fn arm_if_countersigned_submits_after_ack_floor() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(9);
        let receipt = signed(sid.clone(), 1, 2_000);
        let chain = MockChain::default();
        s.record_proposed(&sid).unwrap();
        s.record_countersigned(&sid, &receipt, 1234).unwrap();

        let out = s.arm_if_countersigned(&chain, &env(), &sid).await.unwrap();

        assert_eq!(out.unwrap().settlement_hash, receipt.settlement_hash());
        assert_eq!(*chain.fee_calls.lock(), 1);
        let calls = chain.submit_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["method"], "arm_relay");
        assert_eq!(
            calls[0]["params"],
            json!([9, receipt.settlement_hash(), 1234, 200])
        );
        assert_eq!(calls[0]["nonce"], 0);
        drop(calls);
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::ArmSubmitted));
    }

    #[tokio::test]
    async fn arm_if_countersigned_skips_when_net_is_zero() {
        // A sub-MiB (or zero-price) session records net==0. arm_relay requires
        // net>0 and would revert terminally -> the ladder must NOT advance to
        // ArmSubmitted (that is the boot-loop poison Fable flagged): no broadcast,
        // stays at Countersigned.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(99);
        let chain = MockChain::default();
        s.record_proposed(&sid).unwrap();
        s.record_countersigned(&sid, &signed(sid.clone(), 1, 500), 0)
            .unwrap();

        let out = s.arm_if_countersigned(&chain, &env(), &sid).await.unwrap();

        assert!(out.is_none());
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(*chain.fee_calls.lock(), 0);
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Countersigned));

        // And a replay must keep leaving it alone, not re-broadcast forever.
        let summary = s.replay_pending(&chain, &env()).await.unwrap();
        assert_eq!(summary.countersigned_armed, 0);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Countersigned));
    }

    #[tokio::test]
    async fn replay_pending_only_arms_countersigned_or_submitted() {
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::default();
        let proposed = id(1);
        let countersigned = id(2);
        let submitted = id(3);
        let confirmed = id(4);

        {
            let s = store(dir.path());
            s.record_proposed(&proposed).unwrap();
            s.record_proposed(&countersigned).unwrap();
            s.record_countersigned(&countersigned, &signed(countersigned.clone(), 1, 20), 200)
                .unwrap();
            s.record_proposed(&submitted).unwrap();
            s.record_countersigned(&submitted, &signed(submitted.clone(), 1, 30), 300)
                .unwrap();
            s.record_arm_submitted(&submitted).unwrap();
            s.record_proposed(&confirmed).unwrap();
            s.record_countersigned(&confirmed, &signed(confirmed.clone(), 1, 40), 400)
                .unwrap();
            s.record_arm_submitted(&confirmed).unwrap();
            s.record_arm_confirmed(&confirmed).unwrap();
        }

        let reopened = store(dir.path());
        let summary = reopened.replay_pending(&chain, &env()).await.unwrap();

        assert_eq!(summary.proposed_left_alone, 1);
        assert_eq!(summary.countersigned_armed, 1);
        assert_eq!(summary.submitted_resubmitted, 1);
        assert_eq!(summary.already_confirmed, 1);
        assert_eq!(chain.submit_calls.lock().len(), 2);
        assert_eq!(
            reopened.state(&proposed).unwrap(),
            Some(SettlementState::Proposed)
        );
        assert_eq!(
            reopened.state(&countersigned).unwrap(),
            Some(SettlementState::ArmSubmitted)
        );
        assert_eq!(
            reopened.state(&submitted).unwrap(),
            Some(SettlementState::ArmSubmitted)
        );
    }

    #[tokio::test]
    async fn replay_pending_stops_resubmitting_a_settled_session() {
        // Regression (Fable re-verify): once the operator claims (status
        // RELAY_CLAIMED=4) — the mainline terminal outcome now that claims
        // succeed — replay must NOT re-broadcast arm_relay. Pre-fix the
        // non-RELAY_ARMED branch resubmitted for every status except 3, so every
        // settled session re-armed (and reverted "session not open", burning a
        // fee) on every boot forever.
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::default();
        chain.statuses.lock().push_back(4); // SESSION_RELAY_CLAIMED
        let sid = id(21);
        {
            let s = store(dir.path());
            s.record_proposed(&sid).unwrap();
            s.record_countersigned(&sid, &signed(sid.clone(), 1, 30), 300)
                .unwrap();
            s.record_arm_submitted(&sid).unwrap();
        }

        let reopened = store(dir.path());
        let summary = reopened.replay_pending(&chain, &env()).await.unwrap();

        assert_eq!(summary.submitted_resubmitted, 0);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(
            reopened.state(&sid).unwrap(),
            Some(SettlementState::ArmConfirmed)
        );
    }

    #[tokio::test]
    async fn replay_pending_promotes_submitted_when_chain_is_armed() {
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::default();
        chain.statuses.lock().push_back(SESSION_RELAY_ARMED);
        let sid = id(11);
        {
            let s = store(dir.path());
            s.record_proposed(&sid).unwrap();
            s.record_countersigned(&sid, &signed(sid.clone(), 1, 30), 300)
                .unwrap();
            s.record_arm_submitted(&sid).unwrap();
        }

        let reopened = store(dir.path());
        let summary = reopened.replay_pending(&chain, &env()).await.unwrap();

        assert_eq!(summary.submitted_confirmed, 1);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(
            reopened.state(&sid).unwrap(),
            Some(SettlementState::ArmConfirmed)
        );
    }

    #[test]
    fn reconstruction_uses_only_receipt_vault_and_arm_net() {
        let dir = tempfile::tempdir().unwrap();
        let sid = id(12);
        let receipt = signed(sid.clone(), 5, 9_999);
        let live_hash = receipt.settlement_hash();
        let live_net = 777;
        let state_path;
        {
            let s = store(dir.path());
            state_path = s.paths().settle_state.clone();
            s.record_proposed(&sid).unwrap();
            s.record_countersigned(&sid, &receipt, live_net).unwrap();
        }
        std::fs::remove_file(state_path).unwrap();

        let reopened = store(dir.path());
        let (recovered, net) = reopened.arm_material(&sid).unwrap();
        let call = settler::build_arm_params(
            &env().program_addr,
            &env().wallet_addr,
            12,
            &recovered.settlement_hash(),
            net,
            env().relay_expiry_epochs,
            500,
        );

        assert_eq!(recovered.settlement_hash(), live_hash);
        assert_eq!(net, live_net);
        assert_eq!(call["params"], json!([12, live_hash, live_net, 200]));
    }

    #[test]
    fn torn_write_on_settle_state_is_dropped_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let sid = id(13);
        let state_path;
        {
            let s = store(dir.path());
            state_path = s.paths().settle_state.clone();
            s.record_proposed(&sid).unwrap();
            s.record_countersigned(&sid, &signed(sid.clone(), 1, 10), 1)
                .unwrap();
        }
        let mut f = OpenOptions::new().append(true).open(&state_path).unwrap();
        f.write_all(&[0xAB; 17]).unwrap();
        f.sync_data().unwrap();

        let reopened = store(dir.path());

        assert_eq!(
            reopened.state(&sid).unwrap(),
            Some(SettlementState::Countersigned)
        );
    }

    // ---- Step 8: refund watcher --------------------------------------------

    struct MockRefundChain {
        status: Mutex<u64>,
        strict_err: Mutex<bool>,
        submit_err: Mutex<bool>,
        deadline: u64,
        epoch: u64,
        submit_calls: Mutex<Vec<Value>>,
    }

    impl MockRefundChain {
        fn new(status: u64, deadline: u64, epoch: u64) -> Self {
            Self {
                status: Mutex::new(status),
                strict_err: Mutex::new(false),
                submit_err: Mutex::new(false),
                deadline,
                epoch,
                submit_calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RefundChain for MockRefundChain {
        async fn refund_fee(&self) -> Result<u64> {
            Ok(500)
        }
        async fn get_session_status_strict(&self, _sid: u64) -> Result<u64> {
            if *self.strict_err.lock() {
                return Err(anyhow!("mock strict status read error"));
            }
            Ok(*self.status.lock())
        }
        async fn get_relay_deadline(&self, _sid: u64) -> Result<u64> {
            Ok(self.deadline)
        }
        async fn current_epoch(&self) -> Result<u64> {
            Ok(self.epoch)
        }
        async fn submit_refund_call(&self, call: Value) -> Result<String> {
            if *self.submit_err.lock() {
                return Err(anyhow!("mock submit error"));
            }
            self.submit_calls.lock().push(call);
            Ok("refund-tx".to_string())
        }
    }

    /// Drive a session to the `ArmConfirmed` floor (the refund watcher's entry
    /// candidate).
    fn arm_confirmed(s: &SettleStateStore, sid: &SessionId) {
        s.record_proposed(sid).unwrap();
        s.record_countersigned(sid, &signed(sid.clone(), 1, 100), 200)
            .unwrap();
        s.record_arm_submitted(sid).unwrap();
        s.record_arm_confirmed(sid).unwrap();
    }

    #[tokio::test]
    async fn refund_pending_submits_when_armed_and_past_deadline() {
        // Operator no-show: still RELAY_ARMED, epoch = D + k_r -> refund submitted,
        // floor write-ahead to RefundSubmitted.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(50);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 103);

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out.refund_submitted, 1);
        assert_eq!(chain.submit_calls.lock().len(), 1);
        assert_eq!(chain.submit_calls.lock()[0]["method"], "relay_refund");
        assert_eq!(chain.submit_calls.lock()[0]["params"], json!([50]));
        assert_eq!(
            s.state(&sid).unwrap(),
            Some(SettlementState::RefundSubmitted)
        );
    }

    #[tokio::test]
    async fn refund_pending_skips_inside_the_quiet_zone() {
        // epoch = D + k_r - 1 -> inside the quiet zone -> no refund, floor stays.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(51);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 102);

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out.refund_submitted, 0);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::ArmConfirmed));
    }

    #[tokio::test]
    async fn refund_pending_records_settled_when_operator_claimed() {
        // Operator won the race (RELAY_CLAIMED): drain to Settled, never refund.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(52);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_CLAIMED, 100, 999);

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out.drained_settled, 1);
        assert_eq!(out.refund_submitted, 0);
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Settled));
    }

    #[tokio::test]
    async fn refund_pending_strict_read_error_leaves_entry() {
        // A hostile/failed status read must NOT phantom-drain or submit.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(53);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 999);
        *chain.strict_err.lock() = true;

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out, RefundSummary::default());
        assert!(chain.submit_calls.lock().is_empty());
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::ArmConfirmed));
    }

    #[tokio::test]
    async fn refund_pending_no_double_submit_then_drains_on_confirm() {
        // Full no-show sequence over one store, across two scans: submit once,
        // then (once chain shows REFUNDED) drain to terminal with no re-submit.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(54);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 200);

        let first = s.refund_pending(&chain, &env(), 3).await.unwrap();
        assert_eq!(first.refund_submitted, 1);
        assert_eq!(
            s.state(&sid).unwrap(),
            Some(SettlementState::RefundSubmitted)
        );

        // The refund confirmed on chain.
        *chain.status.lock() = SESSION_RELAY_REFUNDED;
        let second = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(second.drained_refunded, 1);
        assert_eq!(second.refund_submitted, 0);
        assert_eq!(
            chain.submit_calls.lock().len(),
            1,
            "exactly one refund tx total"
        );
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Refunded));
    }

    #[tokio::test]
    async fn refund_pending_ignores_non_armed_floors() {
        // Countersigned (net==0 stuck) and a fresh Proposed must never be a
        // refund candidate.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let cs = id(55);
        s.record_proposed(&cs).unwrap();
        s.record_countersigned(&cs, &signed(cs.clone(), 1, 100), 200)
            .unwrap();
        let prop = id(56);
        s.record_proposed(&prop).unwrap();
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 999);

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out, RefundSummary::default());
        assert!(chain.submit_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn refund_pending_submit_error_is_non_fatal_and_wrote_ahead() {
        // Review finding: a transient submit failure must NOT abort the scan (or,
        // via the boot path, client startup). refund_pending returns Ok; the
        // write-ahead RefundSubmitted floor persists so the next scan retries.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(58);
        arm_confirmed(&s, &sid);
        let chain = MockRefundChain::new(SESSION_RELAY_ARMED, 100, 200);
        *chain.submit_err.lock() = true;

        let out = s.refund_pending(&chain, &env(), 3).await.unwrap();

        assert_eq!(out.refund_submitted, 0);
        assert_eq!(
            s.state(&sid).unwrap(),
            Some(SettlementState::RefundSubmitted),
            "write-ahead persists for retry"
        );
    }

    #[test]
    fn ladder_from_code_round_trips_new_terminals() {
        assert_eq!(
            SettlementState::from_code(5).unwrap(),
            Some(SettlementState::RefundSubmitted)
        );
        assert_eq!(
            SettlementState::from_code(6).unwrap(),
            Some(SettlementState::Refunded)
        );
        assert_eq!(
            SettlementState::from_code(7).unwrap(),
            Some(SettlementState::Settled)
        );
        assert!(SettlementState::from_code(8).is_err());
        // Forward-only: RefundSubmitted -> Refunded bumps; backward is a no-op.
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let sid = id(57);
        arm_confirmed(&s, &sid);
        s.record_refund_submitted(&sid).unwrap();
        s.record_refunded(&sid).unwrap();
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Refunded));
        s.record_refund_submitted(&sid).unwrap(); // backward
        assert_eq!(s.state(&sid).unwrap(), Some(SettlementState::Refunded));
    }
}
