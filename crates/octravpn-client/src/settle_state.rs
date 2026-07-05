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
use tracing::info;

use crate::settler;

/// `program/main-v4.aml` status for the relay lane.
pub(crate) const SESSION_RELAY_ARMED: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SettlementState {
    Proposed = 1,
    Countersigned = 2,
    ArmSubmitted = 3,
    ArmConfirmed = 4,
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
        let submitted = self.submit_arm_from_journal(chain, env, session_id).await?;
        self.record_arm_submitted(session_id)?;
        Ok(Some(submitted))
    }

    pub(crate) fn record_arm_submitted(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::ArmSubmitted)
    }

    pub(crate) fn record_arm_confirmed(&self, session_id: &SessionId) -> Result<()> {
        self.bump_state(session_id, SettlementState::ArmConfirmed)
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
                    if status == SESSION_RELAY_ARMED {
                        self.record_arm_confirmed(&session_id)?;
                        summary.submitted_confirmed += 1;
                    } else {
                        self.submit_arm_from_journal(chain, env, &session_id)
                            .await?;
                        self.record_arm_submitted(&session_id)?;
                        summary.submitted_resubmitted += 1;
                    }
                }
                SettlementState::ArmConfirmed => {
                    summary.already_confirmed += 1;
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
}
