//! Native deposits, owned-note withdrawal and consolidation use the same
//! ledger as purchases. A submitted or locally valid proof is never finality.
use super::{
    records::{Attempt, Coin, Creation},
    Incoming, Payer, Progress, Proposal,
};
use anyhow::{ensure, Context, Result};
use octra_private_payments_experimental::pool::{
    self, call::Call, envelope, transaction::Prover, Membership, PoolIndex,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub(super) const MOVEMENT: u8 = 4;

#[derive(Clone, Copy)]
pub struct Window {
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub relayer: [u8; 47],
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Action {
    Deposit { amount: u64 },
    Withdraw { amount: u64, payout: String },
    Consolidate { notes: [[u8; 32]; 2] },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terms {
    action: Action,
    valid_from: u64,
    expires: u64,
    relayer: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Movement {
    terms: Terms,
    inputs: Vec<[u8; 32]>,
    output_slot: Option<u64>,
    progress: Progress,
    attempt: Option<Attempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<DepositSignature>,
}

/// Deposits have no spent input nullifier. One durable signature per funding
/// operation therefore binds retries without allowing another native debit.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DepositSignature {
    pub(super) public: [u8; 32],
    pub(super) sequence: u32,
}

pub struct Prepared {
    pub id: [u8; 32],
    inner: Proposal,
}
impl Prepared {
    pub fn parameters(&self) -> &serde_json::Value {
        self.inner.parameters()
    }
    pub fn statement(&self) -> Result<pool::Statement> {
        self.inner.statement()
    }
    pub fn call(&self) -> Result<Call> {
        self.inner.call()
    }
    pub fn outputs(&self) -> [[u8; 32]; 2] {
        self.inner.outputs()
    }
    pub fn output_slot(&self) -> Option<u64> {
        self.inner.change_slot()
    }
    pub fn first_output_index(&self) -> Result<u32> {
        self.inner.first_output_index()
    }
}
impl Payer {
    /// Consent imported after a movement was prepared cannot relabel a
    /// withdrawal, change its amount/window or adopt another native relayer.
    pub(super) async fn check_deposit_consent(
        &self,
        user_id: [u8; 32],
        amount: u64,
        window: Window,
    ) -> Result<()> {
        let id = self.movement_id(user_id)?;
        let mut tx = self.0.disk.begin().await?;
        let saved: Option<Movement> = self
            .0
            .disk
            .load(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?)
            .await?;
        tx.rollback().await?;
        if let Some(saved) = saved {
            ensure!(
                saved.terms
                    == Terms {
                        action: Action::Deposit { amount },
                        valid_from: window.valid_from_ms,
                        expires: window.expires_ms,
                        relayer: std::str::from_utf8(&window.relayer)?.to_owned(),
                    },
                "funding consent differs from existing movement"
            );
        }
        Ok(())
    }
    pub(super) async fn deposit_signature(
        &self,
        user_id: [u8; 32],
    ) -> Result<Option<DepositSignature>> {
        let record = self.load_movement(self.movement_id(user_id)?).await?;
        ensure!(
            matches!(record.terms.action, Action::Deposit { .. }),
            "funding operation differs"
        );
        Ok(record.signature)
    }
    pub(super) async fn record_deposit_signature(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        user_id: [u8; 32],
        signature: DepositSignature,
    ) -> Result<()> {
        let tag = self.0.disk.tag(MOVEMENT, &self.movement_id(user_id)?)?;
        let mut record: Movement = self
            .0
            .disk
            .load(tx, MOVEMENT, &tag)
            .await?
            .context("wallet deposit missing")?;
        let Action::Deposit { amount } = record.terms.action else {
            anyhow::bail!("wallet operation is not a deposit");
        };
        ensure!(
            amount > 0
                && record.inputs.is_empty()
                && record.output_slot.is_some()
                && record
                    .attempt
                    .as_ref()
                    .is_some_and(|a| a.call.deposit == amount && a.call.withdraw == 0)
                && record.progress == Progress::Ready
                && record.signature.is_none(),
            "wallet deposit already has a signed attempt"
        );
        record.signature = Some(signature);
        self.0.disk.replace(tx, MOVEMENT, &tag, &record).await
    }
    /// Fund one newly reserved owned note. The native relayer must carry the
    /// explicit amount as well as its fee. A signed deposit cannot be rebased or
    /// signed again; reconcile it, or explicitly consent using another ID.
    pub async fn prepare_deposit(
        &self,
        id: [u8; 32],
        amount_ou: u64,
        window: Window,
        index: &PoolIndex,
        prover: &Prover,
    ) -> Result<Prepared> {
        ensure!(
            amount_ou > 0
                && amount_ou <= self.1.config.custody_cap_ou
                && i64::try_from(amount_ou).is_ok(),
            "wallet deposit amount differs"
        );
        self.prepare_movement(
            id,
            Action::Deposit { amount: amount_ou },
            window,
            index,
            prover,
        )
        .await
    }
    pub(super) async fn movement_output(&self, user_id: [u8; 32]) -> Result<(u64, bool)> {
        let record = self.load_movement(self.movement_id(user_id)?).await?;
        Ok((
            record
                .attempt
                .context("wallet movement proof missing")?
                .count,
            record.output_slot.is_some(),
        ))
    }
    pub(super) async fn movement_attempt(
        &self,
        user_id: [u8; 32],
        index: &PoolIndex,
    ) -> Result<(Attempt, Vec<[u8; 32]>, [u8; 32])> {
        let id = self.movement_id(user_id)?;
        let record = self.load_movement(id).await?;
        ensure!(
            record.progress == Progress::Ready,
            "wallet movement is not ready for submission"
        );
        let (_, now) = self.current(index).await?;
        ensure!(
            (record.terms.valid_from..record.terms.expires).contains(&now),
            "wallet movement submission expired"
        );
        Ok((
            record.attempt.context("wallet movement proof missing")?,
            record.inputs,
            id,
        ))
    }
    fn movement_id(&self, id: [u8; 32]) -> Result<[u8; 32]> {
        ensure!(id != [0; 32], "wallet movement ID is zero");
        let mut hash = Sha256::new();
        hash.update(b"Octranet wallet movement v1\0");
        hash.update(self.1.origin);
        hash.update(self.1.address);
        hash.update(id);
        Ok(hash.finalize().into())
    }
    async fn load_movement(&self, id: [u8; 32]) -> Result<Movement> {
        let mut tx = self.0.disk.begin().await?;
        let record = self
            .0
            .disk
            .load(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?)
            .await?
            .context("wallet movement missing")?;
        tx.rollback().await?;
        Ok(record)
    }
    pub async fn movement_progress(&self, id: [u8; 32]) -> Result<Progress> {
        self.0.disk.check()?;
        Ok(self.load_movement(self.movement_id(id)?).await?.progress)
    }
    pub async fn prepare_withdrawal(
        &self,
        id: [u8; 32],
        amount_ou: u64,
        payout: [u8; 47],
        window: Window,
        index: &PoolIndex,
        prover: &Prover,
    ) -> Result<Prepared> {
        super::super::native(std::str::from_utf8(&payout)?)?;
        ensure!(
            payout != self.1.address && amount_ou > 0 && i64::try_from(amount_ou).is_ok(),
            "wallet withdrawal amount/payout differs"
        );
        self.prepare_movement(
            id,
            Action::Withdraw {
                amount: amount_ou,
                payout: std::str::from_utf8(&payout)?.to_owned(),
            },
            window,
            index,
            prover,
        )
        .await
    }
    /// Select two explicit owned notes and roll their full value into one
    /// freshly reserved own address. No fee is taken from their shielded value.
    pub async fn consolidate(
        &self,
        id: [u8; 32],
        notes: [[u8; 32]; 2],
        window: Window,
        index: &PoolIndex,
        prover: &Prover,
    ) -> Result<Prepared> {
        ensure!(notes[0] != notes[1], "wallet consolidation repeats a note");
        self.prepare_movement(id, Action::Consolidate { notes }, window, index, prover)
            .await
    }
    async fn prepare_movement(
        &self,
        user_id: [u8; 32],
        action: Action,
        window: Window,
        index: &PoolIndex,
        prover: &Prover,
    ) -> Result<Prepared> {
        let _gate = self.0.gate.lock().await;
        self.check_prover(prover)?;
        let id = self.movement_id(user_id)?;
        super::super::native(std::str::from_utf8(&window.relayer)?)?;
        let (lease, now) = self.current(index).await?;
        let terms = Terms {
            action,
            valid_from: window.valid_from_ms,
            expires: window.expires_ms,
            relayer: std::str::from_utf8(&window.relayer)?.to_owned(),
        };
        let mut call = Call {
            quote: [0; 32],
            valid_from_ms: terms.valid_from,
            expires_ms: terms.expires,
            payout: match &terms.action {
                Action::Withdraw { payout, .. } => super::super::native(payout)?,
                Action::Consolidate { .. } | Action::Deposit { .. } => window.relayer,
            },
            deposit_ou: match terms.action {
                Action::Deposit { amount } => amount,
                _ => 0,
            },
            withdraw_ou: match terms.action {
                Action::Withdraw { amount, .. } => amount,
                Action::Consolidate { .. } | Action::Deposit { .. } => 0,
            },
            boxes: [String::new(), String::new()],
        };
        call.context(&self.1.origin, &self.1.address, &window.relayer)?;
        ensure!(
            (call.valid_from_ms..call.expires_ms).contains(&now),
            "wallet movement is outside canonical window"
        );
        let mut tx = self.0.disk.begin().await?;
        let existing: Option<Movement> = self
            .0
            .disk
            .load(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?)
            .await?;
        tx.rollback().await?;
        let mut record = if let Some(record) = existing {
            ensure!(
                record.terms == terms
                    && matches!(record.progress, Progress::Preparing | Progress::Ready),
                "wallet retry changes terms or repeats a final movement"
            );
            record
        } else {
            let chosen = match &terms.action {
                Action::Deposit { .. } => Vec::new(),
                Action::Withdraw { amount, .. } => self.select(*amount, index).await?,
                Action::Consolidate { notes } => {
                    let mut available = self.candidates(index).await?;
                    let mut chosen = Vec::new();
                    for id in notes {
                        let position = available
                            .iter()
                            .position(|(coin, _)| coin.creation.commitment == *id)
                            .context("wallet consolidation note unavailable")?;
                        chosen.push(available.swap_remove(position));
                    }
                    chosen
                }
            };
            let total = Self::total(&chosen)?;
            let slots = u8::from(call.deposit_ou > 0 || total > call.withdraw_ou);
            self.reserve(MOVEMENT, id, chosen, slots, |inputs, output_slot| {
                Movement {
                    terms,
                    inputs,
                    output_slot,
                    progress: Progress::Preparing,
                    attempt: None,
                    signature: None,
                }
            })
            .await?
        };
        let (inputs, total) = self.movement_inputs(id, &record, index, false).await?;
        let roots = index.roots();
        if record.attempt.as_ref().is_some_and(|a| {
            a.roots == [pool::encode_field(roots.0), pool::encode_field(roots.1)]
                && a.count == roots.2
        }) {
            lease.with_current(super::super::PLAN_MAX_AGE, || Ok(()))?;
            return self.movement_proposal(user_id, id, &record);
        }
        ensure!(
            record.signature.is_none(),
            "signed deposit requires native reconciliation; new funding requires new consent"
        );
        let value = total
            .checked_add(call.deposit_ou)
            .context("wallet deposit value overflow")?
            .checked_sub(call.withdraw_ou)
            .context("wallet withdrawal exceeds reserved value")?;
        let draft = if let Some(slot) = record.output_slot {
            let owner = self.note_address(slot)?;
            Some(envelope::Draft::new(
                pool::decode_field(&owner.owner)?,
                value,
                &owner.view_public,
            )?)
        } else {
            ensure!(value == 0, "wallet output slot missing");
            None
        };
        if let Some(draft) = &draft {
            call.boxes[0].clone_from(&draft.ciphertext);
        }
        let context = call.context(&self.1.origin, &self.1.address, &window.relayer)?;
        let outputs = draft
            .iter()
            .map(|draft| draft.bind(&context))
            .collect::<Vec<_>>();
        record.attempt = Some(
            self.prove(
                index,
                &call,
                &window.relayer,
                &inputs,
                &outputs,
                now,
                prover,
            )
            .await?,
        );
        record.progress = Progress::Ready;
        let mut tx = self.0.disk.begin().await?;
        self.0
            .disk
            .replace(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?, &record)
            .await?;
        self.0.disk.commit(tx).await?;
        let (fresh, now) = self.current(index).await?;
        ensure!(
            (call.valid_from_ms..call.expires_ms).contains(&now),
            "wallet movement expired while proving"
        );
        fresh.with_current(super::super::PLAN_MAX_AGE, || {
            self.movement_proposal(user_id, id, &record)
        })
    }
    async fn movement_inputs(
        &self,
        id: [u8; 32],
        record: &Movement,
        index: &PoolIndex,
        spent: bool,
    ) -> Result<(super::ledger::Inputs, u64)> {
        if matches!(record.terms.action, Action::Deposit { .. }) {
            ensure!(
                record.inputs.is_empty() && record.output_slot.is_some(),
                "wallet deposit shape differs"
            );
            self.current(index).await?;
            Ok((Vec::new(), 0))
        } else {
            ensure!(
                record.signature.is_none(),
                "nondeposit movement has funding signature"
            );
            self.reserved(id, &record.inputs, index, spent).await
        }
    }
    fn movement_proposal(
        &self,
        user_id: [u8; 32],
        id: [u8; 32],
        record: &Movement,
    ) -> Result<Prepared> {
        let inner = Proposal {
            quote: id,
            attempt: record
                .attempt
                .clone()
                .context("wallet movement proof missing")?,
            source: self.1.clone(),
            change_slot: record.output_slot,
        };
        inner.statement()?;
        Ok(Prepared { id: user_id, inner })
    }
    pub async fn complete_movement(
        &self,
        user_id: [u8; 32],
        index: &PoolIndex,
        epoch: u64,
        output: Option<&Membership>,
    ) -> Result<()> {
        let _gate = self.0.gate.lock().await;
        let id = self.movement_id(user_id)?;
        self.current(index).await?;
        let mut record = self.load_movement(id).await?;
        if record.progress == Progress::Paid {
            return Ok(());
        }
        ensure!(
            record.progress == Progress::Ready,
            "wallet movement is not prepared"
        );
        let prepared = self.movement_proposal(user_id, id, &record)?;
        let relayer = super::super::native(&record.terms.relayer)?;
        let call = prepared.call()?;
        let execution = self
            .confirmed_exchange(
                epoch,
                prepared.parameters(),
                &relayer,
                call.deposit_ou,
                None,
            )
            .await?;
        ensure!(
            (call.valid_from_ms..call.expires_ms).contains(&execution.paid_at),
            "wallet movement confirmed outside accepted window"
        );
        self.movement_inputs(id, &record, index, true).await?;
        let incoming = match (record.output_slot, output) {
            (Some(slot), Some(path)) => {
                ensure!(
                    path.index == prepared.first_output_index()?,
                    "wallet output position differs"
                );
                let input = Incoming {
                    slot,
                    epoch,
                    commitment: prepared.outputs()[0],
                    membership: path,
                    output: 0,
                    call: &call,
                    relayer,
                };
                let coin = Coin {
                    slot,
                    creation: Creation::new(&input)?,
                    reserved: None,
                    spent: false,
                    income: None,
                };
                self.open_coin(&coin).await?;
                Some(coin)
            }
            (None, None) => None,
            _ => anyhow::bail!("wallet movement output missing or unexpected"),
        };
        self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        self.finish_notes(&mut tx, id, &record.inputs, true, incoming)
            .await?;
        record.progress = Progress::Paid;
        self.0
            .disk
            .replace(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?, &record)
            .await?;
        self.0.disk.commit(tx).await
    }
    /// An exposed proof retains its notes until canonical roots invalidate it.
    /// With `expired`, also require the committed clock to pass the deadline.
    pub async fn cancel_movement(
        &self,
        user_id: [u8; 32],
        index: &PoolIndex,
        expired: bool,
    ) -> Result<()> {
        let _gate = self.0.gate.lock().await;
        let id = self.movement_id(user_id)?;
        let (_, now) = self.current(index).await?;
        let mut record = self.load_movement(id).await?;
        if matches!(record.progress, Progress::Cancelled | Progress::Expired) {
            return Ok(());
        }
        ensure!(
            record.progress != Progress::Paid && (!expired || now >= record.terms.expires),
            "wallet movement is final or has not expired"
        );
        ensure!(
            record.signature.is_none(),
            "signed deposit requires native reconciliation"
        );
        if record.inputs.is_empty() {
            self.movement_inputs(id, &record, index, false).await?;
        } else {
            self.release_safe(id, &record.inputs, record.attempt.as_ref(), index)
                .await?;
        }
        self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        self.finish_notes(&mut tx, id, &record.inputs, false, None)
            .await?;
        record.progress = if expired {
            Progress::Expired
        } else {
            Progress::Cancelled
        };
        self.0
            .disk
            .replace(&mut tx, MOVEMENT, &self.0.disk.tag(MOVEMENT, &id)?, &record)
            .await?;
        self.0.disk.commit(tx).await
    }
}
