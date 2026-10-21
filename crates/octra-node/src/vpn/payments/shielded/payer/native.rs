//! Durable native relayer attempts. Queue acceptance is only staging. Every
//! new signature permanently reserves its declared fee before leaving the book.
//! Use a dedicated relayer: one live attempt per key serializes its nonce.
use super::{
    records::{Attempt, Intent},
    Payer, Progress, INTENT,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    native_json::Document,
    transaction::{self, OpType, Transaction},
};
use octra_node_runtime::{account_store, state_batch::StateBatch};
use octra_private_payments_experimental::{invoice::SignedInvoice, pool::PoolIndex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
pub(super) mod journal;
#[cfg(test)]
pub(crate) use journal::tests as journal_tests;
use journal::{Bank, Saved, BANK};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Purchase([u8; 32]),
    Movement([u8; 32]),
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicy {
    pub fee_ou: u64,
    pub lifetime_budget_ou: u64,
    pub max_attempts: u32,
}
impl FeePolicy {
    pub(super) fn validate(self) -> Result<()> {
        ensure!(
            self.fee_ou >= 1000
                && i64::try_from(self.fee_ou).is_ok()
                && self.lifetime_budget_ou >= self.fee_ou
                && i64::try_from(self.lifetime_budget_ou).is_ok()
                && (1..=journal::MAX_ATTEMPTS).contains(&self.max_attempts),
            "native relayer fee policy differs"
        );
        Ok(())
    }
}
pub struct SignedAttempt {
    pub operation: Operation,
    tx: Transaction,
    wallet: [u8; 32],
    bank: [u8; 32],
    sequence: u32,
}
impl SignedAttempt {
    /// Public native calldata/signature only. Keep the associated invoice and
    /// wallet request metadata private when relaying this envelope.
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }
    pub fn hash(&self) -> Result<String> {
        Ok(hex::encode(self.tx.hash()?))
    }
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
}
fn clock() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
fn parse(saved: &Saved) -> Result<Transaction> {
    Ok(Transaction::from_document(&Document::parse(
        saved.transaction.as_bytes(),
    )?)?)
}

impl Payer {
    async fn native_operation(
        &self,
        operation: Operation,
        index: &PoolIndex,
    ) -> Result<(Attempt, Vec<[u8; 32]>, [u8; 32])> {
        match operation {
            Operation::Movement(id) => self.movement_attempt(id, index).await,
            Operation::Purchase(quote) => {
                let mut tx = self.0.disk.begin().await?;
                let intent: Intent = self
                    .0
                    .disk
                    .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
                    .await?
                    .context("payer purchase missing")?;
                tx.rollback().await?;
                ensure!(
                    intent.progress == Progress::Ready,
                    "payer purchase is not ready for submission"
                );
                let signed = SignedInvoice::decode_private(&intent.invoice)?;
                let limits = super::super::Limits {
                    receipt_key: intent.accepted.receipt,
                    traffic_class: intent.accepted.class,
                    max_bytes: intent.accepted.bytes,
                    max_cost_ou: intent.accepted.cost,
                };
                self.ready(&signed, &limits, index, &intent).await?;
                Ok((
                    intent.attempt.context("payer purchase proof missing")?,
                    intent.inputs,
                    quote,
                ))
            }
        }
    }
    /// Persist the exact signed native transaction before returning it. Retries
    /// reuse a live nonce/signature. Replacements require consumption or native
    /// timestamp expiry, another canonical head, and remaining lifetime budget.
    pub async fn sign_native(
        &self,
        operation: Operation,
        index: &PoolIndex,
        key: &SigningKey,
        policy: FeePolicy,
    ) -> Result<SignedAttempt> {
        let _gate = self.0.gate.lock().await;
        policy.validate()?;
        let (attempt, inputs, id) = self.native_operation(operation, index).await?;
        Self::current_roots(&attempt, index)?;
        self.native_inputs(operation, id, &inputs, index, attempt.call.deposit)
            .await?;
        let (lease, now_ms) = self.current(index).await?;
        ensure!(
            (attempt.call.valid_from..attempt.call.expires).contains(&now_ms),
            "native private call expired"
        );
        let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
        let relayer = transaction::address_from_public_key(&public);
        ensure!(
            relayer == attempt.call.relayer.as_bytes(),
            "native private relayer key differs"
        );
        let ledger = StateBatch::from_snapshot(lease.committed().state().clone());
        let account =
            account_store::load(&ledger, &relayer)?.context("native relayer is unfunded")?;
        let parameters_hash: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&attempt.parameters)?).into();
        let head: [u8; 32] = Sha256::digest(serde_json::to_vec(lease.committed().head())?).into();
        let now = clock()?;
        let tag = self.0.disk.tag(BANK, &key.verifying_key().to_bytes())?;
        let deposit_signature = if attempt.call.deposit > 0 {
            let Operation::Movement(user_id) = operation else {
                anyhow::bail!("only an owned movement may deposit");
            };
            let marker = self.deposit_signature(user_id).await?;
            if marker.is_none() {
                ensure!(
                    self.native_sequences(&key.verifying_key().to_bytes(), operation)
                        .await?
                        .is_empty(),
                    "deposit lost its signed watermark; refusing another debit"
                );
            }
            marker
        } else {
            None
        };
        let mut tx = self.0.disk.begin().await?;
        let existing = self.load_native_bank(&mut tx, &tag).await?;
        let fresh = existing.is_none();
        let mut bank = existing.unwrap_or(Bank {
            version: 2,
            policy,
            reserved_ou: 0,
            count: 0,
        });
        ensure!(
            bank.policy == policy
                && bank.count <= policy.max_attempts
                && bank.reserved_ou
                    == policy
                        .fee_ou
                        .checked_mul(u64::from(bank.count))
                        .context("native fee counter overflow")?
                && bank.reserved_ou <= policy.lifetime_budget_ou,
            "native fee journal identity/counters differ"
        );
        if let Some(marker) = deposit_signature {
            ensure!(
                marker.public == key.verifying_key().to_bytes()
                    && marker.sequence > 0
                    && marker.sequence <= bank.count,
                "deposit signing identity/sequence differs"
            );
            let saved = self
                .load_native_entry(&mut tx, &tag, marker.sequence, &bank.policy)
                .await?;
            ensure!(
                saved.operation == operation
                    && saved.parameters_hash == parameters_hash
                    && saved.deposit_ou == attempt.call.deposit,
                "signed deposit terms differ"
            );
            let signed = parse(&saved)?;
            self.0.disk.commit(tx).await?;
            lease.with_current(super::super::PLAN_MAX_AGE, || Ok(()))?;
            return Ok(SignedAttempt {
                operation,
                tx: signed,
                wallet: self.0.wallet,
                bank: tag,
                sequence: marker.sequence,
            });
        }
        if bank.count > 0 {
            let saved = self
                .load_native_entry(&mut tx, &tag, bank.count, &bank.policy)
                .await?;
            let signed = parse(&saved)?;
            self.check_native(&signed, &public, saved.deposit_ou)?;
            if signed.nonce > account.nonce && (-5.0..=300.0).contains(&(now - signed.timestamp)) {
                ensure!(
                    saved.operation == operation
                        && saved.parameters_hash == parameters_hash
                        && saved.deposit_ou == attempt.call.deposit,
                    "native relayer has another unresolved transaction"
                );
                self.0.disk.commit(tx).await?;
                lease.with_current(super::super::PLAN_MAX_AGE, || Ok(()))?;
                return Ok(SignedAttempt {
                    operation,
                    tx: signed,
                    wallet: self.0.wallet,
                    bank: tag,
                    sequence: bank.count,
                });
            }
            ensure!(
                saved.head != head,
                "native replacement requires another canonical head"
            );
        }
        ensure!(
            bank.count < policy.max_attempts,
            "native relayer attempt budget exhausted"
        );
        let reserved = bank
            .reserved_ou
            .checked_add(policy.fee_ou)
            .context("native fee budget overflow")?;
        ensure!(
            reserved <= policy.lifetime_budget_ou
                && account.balance
                    >= num_bigint::BigInt::from(policy.fee_ou) + attempt.call.deposit,
            "native relayer fee budget/balance exhausted"
        );
        let mut signed = Transaction {
            from: relayer,
            to: self.1.address.to_vec(),
            amount: attempt.call.deposit.into(),
            nonce: account.nonce.successor(),
            ou: policy.fee_ou.into(),
            timestamp: now,
            signature: vec![],
            public_key: Some(public.clone()),
            message: Some(serde_json::to_vec(&attempt.parameters)?),
            encrypted_data: Some(b"exchange".to_vec()),
            op_type: OpType::CircleCall,
        };
        signed.signature = STANDARD
            .encode(key.sign(&signed.signing_bytes()?).to_bytes())
            .into_bytes();
        self.check_native(&signed, &public, attempt.call.deposit)?;
        ensure!(
            signed.nonce > account.nonce,
            "native relayer nonce exhausted"
        );
        let saved = Saved {
            operation,
            transaction: String::from_utf8(signed.to_json_bytes()?)?,
            parameters_hash,
            head,
            deposit_ou: attempt.call.deposit,
        };
        self.append_native_entry(&mut tx, &tag, &mut bank, &saved)
            .await?;
        if attempt.call.deposit > 0 {
            let Operation::Movement(user_id) = operation else {
                anyhow::bail!("native funding operation differs");
            };
            self.record_deposit_signature(
                &mut tx,
                user_id,
                super::movement::DepositSignature {
                    public: key.verifying_key().to_bytes(),
                    sequence: bank.count,
                },
            )
            .await?;
        }
        if fresh {
            self.0
                .disk
                .insert(&mut tx, BANK, &tag, &[0; 32], &bank)
                .await?;
        } else {
            self.0.disk.replace(&mut tx, BANK, &tag, &bank).await?;
        }
        self.0.disk.commit(tx).await?;
        lease.with_current(super::super::PLAN_MAX_AGE, || Ok(()))?;
        Ok(SignedAttempt {
            operation,
            tx: signed,
            wallet: self.0.wallet,
            bank: tag,
            sequence: bank.count,
        })
    }
    fn check_native(&self, tx: &Transaction, public: &[u8], deposit_ou: u64) -> Result<()> {
        ensure!(
            tx.to == self.1.address
                && tx.from == transaction::address_from_public_key(public)
                && tx.public_key.as_deref() == Some(public)
                && tx.op_type == OpType::CircleCall
                && i64::try_from(deposit_ou).is_ok()
                && tx.amount == deposit_ou.into()
                && tx.nonce.get() > 0
                && tx.ou >= 1000.into()
                && tx.timestamp.is_finite()
                && tx.timestamp >= 0.
                && tx.encrypted_data.as_deref() == Some(b"exchange")
                && tx.verify(public)
                && transaction::normalize_envelope(tx, Some(public))? == *tx,
            "native private transaction binding differs"
        );
        Ok(())
    }
    async fn native_inputs(
        &self,
        operation: Operation,
        id: [u8; 32],
        inputs: &[[u8; 32]],
        index: &PoolIndex,
        deposit_ou: u64,
    ) -> Result<()> {
        if deposit_ou > 0 {
            ensure!(
                matches!(operation, Operation::Movement(_))
                    && inputs.is_empty()
                    && i64::try_from(deposit_ou).is_ok(),
                "native funding input shape differs"
            );
            self.current(index).await?;
        } else {
            self.reserved(id, inputs, index, false).await?;
        }
        Ok(())
    }
    fn current_roots(attempt: &Attempt, index: &PoolIndex) -> Result<()> {
        let roots = index.roots();
        ensure!(
            attempt.roots
                == [
                    octra_private_payments_experimental::pool::encode_field(roots.0),
                    octra_private_payments_experimental::pool::encode_field(roots.1)
                ]
                && attempt.count == roots.2,
            "native private proof roots changed; rebase before signing or broadcasting"
        );
        Ok(())
    }
    pub async fn reserved_fees(&self, public: &[u8; 32]) -> Result<u64> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let bank = self
            .load_native_bank(&mut tx, &self.0.disk.tag(BANK, public)?)
            .await?;
        self.0.disk.commit(tx).await?;
        Ok(bank.map_or(0, |bank| bank.reserved_ou))
    }
    /// Recover a prior signed attempt without allocating a nonce or fee. The
    /// record remains private, and canonical confirmation is still separate.
    pub async fn native_attempt(&self, public: &[u8; 32], sequence: u32) -> Result<SignedAttempt> {
        self.0.disk.check()?;
        let tag = self.0.disk.tag(BANK, public)?;
        let mut tx = self.0.disk.begin().await?;
        let bank = self
            .load_native_bank(&mut tx, &tag)
            .await?
            .context("native fee journal missing")?;
        ensure!(
            sequence > 0 && sequence <= bank.count,
            "native attempt sequence differs"
        );
        let saved = self
            .load_native_entry(&mut tx, &tag, sequence, &bank.policy)
            .await?;
        let signed = parse(&saved)?;
        self.0.disk.commit(tx).await?;
        Ok(SignedAttempt {
            operation: saved.operation,
            tx: signed,
            wallet: self.0.wallet,
            bank: tag,
            sequence,
        })
    }
    /// Recover every attempt for an operation, including a signature committed
    /// immediately before its caller crashed. Scan only this relayer's bounded
    /// journal; no transaction or proving material is copied into a second book.
    pub async fn native_sequences(
        &self,
        public: &[u8; 32],
        operation: Operation,
    ) -> Result<Vec<u32>> {
        self.0.disk.check()?;
        let tag = self.0.disk.tag(BANK, public)?;
        let mut tx = self.0.disk.begin().await?;
        let mut sequences = Vec::new();
        if let Some(bank) = self.load_native_bank(&mut tx, &tag).await? {
            for sequence in 1..=bank.count {
                let saved = self
                    .load_native_entry(&mut tx, &tag, sequence, &bank.policy)
                    .await?;
                if saved.operation == operation {
                    sequences.push(sequence);
                }
            }
        }
        self.0.disk.commit(tx).await?;
        Ok(sequences)
    }
    pub(super) async fn saved_native(&self, attempt: &SignedAttempt) -> Result<()> {
        ensure!(
            attempt.wallet == self.0.wallet,
            "native attempt belongs to another wallet"
        );
        let mut tx = self.0.disk.begin().await?;
        let bank = self
            .load_native_bank(&mut tx, &attempt.bank)
            .await?
            .context("native fee journal missing")?;
        ensure!(
            attempt.sequence > 0 && attempt.sequence <= bank.count,
            "native attempt sequence differs"
        );
        let saved = self
            .load_native_entry(&mut tx, &attempt.bank, attempt.sequence, &bank.policy)
            .await?;
        self.0.disk.commit(tx).await?;
        let encoded = attempt.tx.to_json_bytes()?;
        ensure!(
            saved.operation == attempt.operation && saved.transaction.as_bytes() == encoded,
            "native attempt was not reserved"
        );
        Ok(())
    }
    /// Actual local bounded intake and peer announcement. Success means staged,
    /// never paid. Cancellation or announce failure retries this exact attempt.
    pub async fn broadcast<A: crate::Host>(
        &self,
        submission: &crate::rpc::Submission<A>,
        attempt: &SignedAttempt,
        index: &PoolIndex,
    ) -> Result<()> {
        let _gate = self.0.gate.lock().await;
        ensure!(
            Arc::ptr_eq(&self.1.directory.shared, &submission.node.shared),
            "native intake belongs to another node"
        );
        self.saved_native(attempt).await?;
        let (prepared, inputs, id) = self.native_operation(attempt.operation, index).await?;
        Self::current_roots(&prepared, index)?;
        self.native_inputs(attempt.operation, id, &inputs, index, prepared.call.deposit)
            .await?;
        ensure!(
            attempt.tx.message.as_deref()
                == Some(serde_json::to_vec(&prepared.parameters)?.as_slice())
                && attempt.tx.amount == prepared.call.deposit.into(),
            "native attempt was superseded by a new proof"
        );
        self.current(index).await?;
        let hash = attempt.hash()?.into_bytes();
        let staged = || -> Result<bool> {
            let same = submission.pending.inspect(|pool| {
                pool.find(&hash)
                    .map(|queued| queued == attempt.transaction())
            })?;
            ensure!(same != Some(false), "native staged envelope differs");
            Ok(same.unwrap_or(false))
        };
        if !staged()? {
            match submission.submit_native(attempt.tx.clone()).await {
                Ok(accepted) => ensure!(accepted == hash, "native intake hash differs"),
                // Another exact submission may win between the read and intake.
                // Inspect the healthy owned pool; never infer success merely
                // from a duplicate-nonce string or another envelope's hash.
                Err(error) if !staged()? => return Err(error.into()),
                Err(_) => {}
            }
        }
        self.current(index).await?;
        submission.announce(hash, None).await
    }
    /// Authenticate the exact confirmed transaction against the node's retained
    /// finality. This does not import change or retire reservations; complete()
    /// or complete_movement() still checks the canonical input/output evidence.
    pub async fn confirmed_native(&self, attempt: &SignedAttempt) -> Result<Option<u64>> {
        self.0.disk.check()?;
        self.saved_native(attempt).await?;
        let lease = crate::SnapshotLease::capture(self.1.directory.shared.clone())?;
        let hash = attempt.hash()?;
        let found = self
            .1
            .directory
            .history
            .transaction(lease.committed().head(), hash.as_bytes(), 32_768)
            .await?;
        let epoch = if let Some((head, record)) = found {
            ensure!(
                record.hash == hash,
                "native confirmed transaction hash differs"
            );
            ensure!(
                Transaction::from_document(&Document::parse(&record.transaction)?)? == attempt.tx,
                "native confirmed transaction envelope differs"
            );
            head.cursor.epoch.0
        } else if let Some(epoch) = self.confirmation_location(&hash).await? {
            epoch
        } else {
            return Ok(None);
        };
        let parameters: serde_json::Value = serde_json::from_slice(
            attempt
                .tx
                .message
                .as_deref()
                .context("native private parameters missing")?,
        )?;
        let relayer: [u8; 47] = attempt.tx.from.as_slice().try_into()?;
        let deposit_ou = u64::try_from(&attempt.tx.amount)?;
        self.confirmed_exchange(epoch, &parameters, &relayer, deposit_ou, Some(&attempt.tx))
            .await?;
        Ok(Some(epoch))
    }
    /// Reconcile a submitted attempt against canonical execution, reconstructing
    /// its creation-epoch paths even after other users append later notes.
    pub async fn reconcile_native(
        &self,
        attempt: &SignedAttempt,
        index: &PoolIndex,
    ) -> Result<Option<u64>> {
        self.current(index).await?;
        let Some(epoch) = self.confirmed_native(attempt).await? else {
            return Ok(None);
        };
        let execution = self.historical(epoch).await?;
        let count = self.1.state(&execution.after)?.count;
        match attempt.operation {
            Operation::Purchase(quote) => {
                let mut tx = self.0.disk.begin().await?;
                let intent: Intent = self
                    .0
                    .disk
                    .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
                    .await?
                    .context("payer purchase missing")?;
                tx.rollback().await?;
                let first: u32 = intent
                    .attempt
                    .context("payer proof missing")?
                    .count
                    .try_into()?;
                let operator = index.membership_at(first, count)?;
                let change = intent
                    .change_slot
                    .map(|_| {
                        index.membership_at(
                            first
                                .checked_add(1)
                                .context("payer output index overflow")?,
                            count,
                        )
                    })
                    .transpose()?;
                self.complete(quote, index, epoch, &operator, change.as_ref())
                    .await?;
            }
            Operation::Movement(id) => {
                let (first, has_output) = self.movement_output(id).await?;
                let output = has_output
                    .then(|| index.membership_at(first.try_into()?, count))
                    .transpose()?;
                self.complete_movement(id, index, epoch, output.as_ref())
                    .await?;
            }
        }
        Ok(Some(epoch))
    }
}
