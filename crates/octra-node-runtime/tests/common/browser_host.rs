//! Local development-chain host for Chromium qualification. Wallet signing,
//! native admission, execution, QC publication and receipts are real; validator
//! keys and genesis balances are public test fixtures, without a network driver.
use super::{circle_host, finality_host};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer as _, SigningKey};
use octra_browser::{application::Context, AssetResolver, Error, Provenance};
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    CommittedEpochSource, Sequence,
};
use octra_node_protocol::{
    consensus::codec::Wire,
    state::Account,
    transaction::{self, Nonce, OpType, RuleMode, Transaction},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    account_store,
    browser_wallet::{self, Node},
    canonical::CanonicalStore,
    circle::WasmRules,
    circle_assets::CanonicalAssets,
    circle_transaction,
    finality::{ExecutedEpoch, Publisher},
    staging::{intake, DropRecord, Pool},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

pub(crate) struct DevelopmentSigner;
pub(crate) fn address() -> Vec<u8> {
    transaction::address_from_public_key(
        STANDARD
            .encode(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes())
            .as_bytes(),
    )
}
pub(crate) fn fund(state: &mut StateBatch) {
    let account = Account {
        balance: 10_000.into(),
        public_key: Some(
            STANDARD
                .encode(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes())
                .into_bytes(),
        ),
        ..Account::default()
    };
    account_store::set(state, &address(), &account, RuleMode::Active).unwrap();
    state
        .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
        .unwrap();
    state
        .set(&[b"meta", b"total_supply"], b"10000".to_vec())
        .unwrap();
}
#[async_trait]
impl browser_wallet::Signer for DevelopmentSigner {
    fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()
    }
    async fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        Ok(SigningKey::from_bytes(&[42; 32]).sign(bytes).to_bytes())
    }
}
fn error(e: impl std::fmt::Display) -> Error {
    Error::Unavailable(e.to_string())
}
pub(crate) fn profile() -> WasmRules {
    WasmRules {
        wasm_float: false,
        proof_exec: false,
        math: false,
    }
}
pub(crate) struct Host {
    pub(crate) store: Arc<CanonicalStore>,
    pub(crate) authority: finality_host::Authority,
    pub(crate) calls: Mutex<Vec<Value>>,
    pub(crate) writing: AsyncMutex<()>,
    pub(crate) pending: Mutex<Pool>,
}
// Native BFT intake does not schedule ordinary public Circle calls in the
// private/key-switch admission workers. This fixture executes their WASM below.
struct AdmissionWorkers;
impl intake::Host for AdmissionWorkers {
    fn preverify(&mut self, tx: &Transaction, _: &Pool) -> Result<(), String> {
        if tx.op_type == OpType::CircleCall {
            Ok(())
        } else {
            Err("pre_verify_unavailable fixture only executes public Circle calls".into())
        }
    }
    fn save_drops(&mut self, _: &[DropRecord]) {}
    fn invalidate(&mut self, _: &[u8]) {}
    fn changed(&mut self, _: &Pool) {}
    fn accepted(&mut self, _: &Transaction, _: &Pool) {}
}
impl Host {
    async fn current(&self, context: &Context) -> Result<(), Error> {
        let actual = CanonicalAssets::capture(&self.store).await?;
        if actual.provenance() != context.provenance {
            return Err(Error::SnapshotChanged);
        }
        Ok(())
    }
}
#[async_trait]
impl Node for Host {
    async fn account(
        &self,
        context: &Context,
        address: &[u8],
    ) -> Result<browser_wallet::Account, Error> {
        let _guard = self.writing.lock().await;
        self.current(context).await?;
        let (_, state) = self.store.snapshot().await.map_err(error)?;
        let account = account_store::load(&state, address)
            .map_err(error)?
            .ok_or_else(|| error("sender not found"))?;
        let pool = self.pending.lock().unwrap();
        let reserved = pool
            .stats()
            .remove(address)
            .map_or_else(|| 0.into(), |(_, total)| total);
        Ok(browser_wallet::Account {
            provenance: context.provenance.clone(),
            available: account.balance - reserved,
            next_nonce: pool.pending_nonce(address, account.nonce).successor(),
            timestamp: 1.,
        })
    }
    async fn submit(&self, context: &Context, tx: Transaction) -> Result<(), Error> {
        let _guard = self.writing.lock().await;
        self.current(context).await?;
        if tx.to != context.circle_id.as_bytes() {
            return Err(error("Circle target differs"));
        }
        let (base, mut state) = self.store.snapshot().await.map_err(error)?;
        let mut ledger = account_store::ledger(&state).map_err(error)?;
        let tx = {
            let mut pool = self.pending.lock().unwrap();
            let rules = intake::Rules {
                bft: true,
                profile: Profile::from_values(Some(b"devnet_full_v1"), None, None),
                compute: RuleMode::Active,
                settle: RuleMode::Active,
                proof: RuleMode::Active,
                duty: None,
                queue_head: Some(i64::try_from(base.cursor.epoch.0).map_err(error)?),
                stealth_minimum: 5000.into(),
            };
            let hash = intake::submit(
                &mut pool,
                &tx,
                &ledger,
                &rules,
                &intake::Rpc {
                    now: 1.,
                    max_drift: 60.,
                    observer: false,
                    preverify_capacity: true,
                    preverify_pending: Nonce::default(),
                    preverify_maximum: Nonce::new(6).unwrap(),
                    nonce_window: Nonce::new(32).unwrap(),
                },
                &mut AdmissionWorkers,
                &|| 1.,
            )
            .map_err(error)?;
            let selected = pool.ready_epoch(
                &10_000_000_000u64.into(),
                &|sender| ledger.account(sender).map(|a| a.nonce),
                &|tx| transaction::check_envelope(tx).is_ok(),
            );
            if selected.len() != 1 || selected[0].hash != hash {
                return Err(error("fixture call is not the sole ready transaction"));
            }
            selected[0].tx.clone()
        };
        transaction::check_envelopes(RuleMode::Active, std::slice::from_ref(&tx)).map_err(error)?;
        state.begin().map_err(error)?;
        let epoch = i64::try_from(base.cursor.epoch.0 + 1).map_err(error)?;
        let runtime = circle_host::runtime();
        let mut calls = circle_transaction::Calls::new(
            &runtime,
            circle_transaction::Rules {
                manifest: octra_node_runtime::circle::WasmProfile::Compute,
                update_policy: false,
                wasm: profile(),
                inspect: true,
                storage_proof: true,
                fhe_work: false,
                object_cost: false,
            },
            epoch,
            123.5,
            hex::encode(base.cursor.state_root.0).as_bytes(),
            circle_transaction::Verification::Direct,
        );
        use octra_node_runtime::{epoch_execution, epoch_footer, validator_epoch};
        let emission = epoch_footer::Policy {
            emission_guard: true,
            schedule: octra_node_protocol::emission::Schedule::Inactive,
            legacy_total: None,
        };
        let reward = finality_host::reward(self.authority.seed);
        let committed = state.snapshot();
        let previous = hex::encode(base.cursor.state_root.0);
        let batch = epoch_execution::execute(
            &epoch_execution::Request {
                validators: validator_epoch::Request {
                    chain: self.store.chain().chain_id.as_bytes(),
                    epoch,
                    policy: &octra_node_protocol::validator::policy::Policy::Inactive,
                    legacy_members: &[],
                    previous_root: previous.as_bytes(),
                    committed_head: Some(&committed),
                },
                envelope: octra_node_protocol::transaction_outcome::Rules {
                    envelope: RuleMode::Active,
                    compute: RuleMode::Prior,
                    settle: RuleMode::Prior,
                },
                sender_key_activation: Some(0),
                preverification: None,
                emission: &emission,
                reward: &reward,
                validator_keys: &[],
            },
            &|_: i64, _: &StateBatch| {
                Ok(validator_epoch::Fold {
                    account_mode: RuleMode::Active,
                    ..validator_epoch::Fold::prior()
                })
            },
            std::slice::from_ref(&tx),
            &mut ledger,
            &mut state,
            |tx, ledger, state| calls.process(tx, ledger, state),
        )
        .map_err(error)?;
        if batch.artifacts.confirmed.as_slice() != [(0, 0)] || !batch.artifacts.rejected.is_empty()
        {
            return Err(error("fixture transaction was not confirmed"));
        }
        let hash = hex::encode(tx.hash().map_err(error)?);
        let identity = tx.identity_bytes().map_err(error)?;
        let record = NativeTransaction {
            txid: base.txid_hi + 1,
            hash: hash.clone(),
            proof: ArchiveProof::Exact,
            identity: identity.clone(),
            transaction: identity,
            receipt: Some(calls.receipts()[&hash].clone()),
        };
        let executed = ExecutedEpoch {
            epoch_observation: None,
            metrics: octra_node_protocol::metrics::Epoch::default(),
            vm_receipts: std::collections::BTreeMap::default(),
            reward_source: finality_host::reward_source(self.authority.seed),
            state: state.snapshot(),
            transactions: vec![record],
            consensus_receipts: vec![],
            date: epoch,
            message: b"reviewed browser Circle call".to_vec(),
        };
        let certificate = finality_host::certificate(&base, &executed, &self.authority)
            .encode()
            .map_err(error)?;
        let publisher = Publisher::open(self.store.clone(), self.authority.clone())
            .await
            .map_err(error)?;
        publisher
            .prepare(&base, &certificate, executed)
            .await
            .map_err(error)?
            .commit()
            .await
            .map_err(error)?;
        publisher.audit().await.map_err(error)?;
        self.pending
            .lock()
            .unwrap()
            .remove_processed(&[hash.as_bytes().to_vec()]);
        self.calls.lock().unwrap().push(json!({"context":context,"call":{"method":std::str::from_utf8(tx.encrypted_data.as_ref().unwrap()).map_err(error)?,"params":serde_json::from_slice::<Value>(tx.message.as_ref().unwrap()).map_err(error)?,"amount":tx.amount.to_string(),"ou":tx.ou.to_string()},"hash":hash,"epoch":epoch}));
        Ok(())
    }
    async fn status(&self, context: &Context, address: &[u8], hash: &str) -> Result<Value, Error> {
        let Provenance::Canonical(identity) = &context.provenance else {
            return Err(Error::SnapshotChanged);
        };
        if identity.chain_id != self.store.chain().chain_id
            || identity.origin != self.store.chain().origin
        {
            return Err(Error::SnapshotChanged);
        }
        let source = self.store.source();
        for sequence in 1..=source.head().await.map_err(error)?.sequence.0 {
            let epoch = source
                .load(Sequence(sequence))
                .await
                .map_err(error)?
                .ok_or_else(|| error("history gap"))?;
            for record in &epoch.events {
                if record.hash != hash {
                    continue;
                }
                let doc = octra_node_protocol::native_json::Document::parse(&record.transaction)
                    .map_err(error)?;
                let tx = Transaction::from_document(&doc).map_err(error)?;
                if tx.from != address || tx.to != context.circle_id.as_bytes() {
                    return Err(Error::NotFound);
                }
                return Ok(
                    json!({"hash":hash,"status":"committed","epoch":epoch.cursor.epoch.0,"receipt":serde_json::from_slice::<Value>(record.receipt.as_ref().unwrap()).map_err(error)?}),
                );
            }
        }
        Err(Error::NotFound)
    }
}
