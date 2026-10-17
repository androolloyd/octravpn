// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native key-switch plans, including equality proofs and configured historical
//! entitlements. Public inputs cannot manufacture an admitted history artifact.
pub(crate) mod classify;
mod migration;
mod payload;
use crate::{
    private_balance::{Evidence, Profile},
    private_crypto::isolated as crypto,
    private_error::{check, failure, Error},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    state::Ledger,
    state_sync::migration::Admission,
    transaction::{OpType, RuleMode, Transaction},
};
use payload::{Migration, Payload};
use sha2::{Digest, Sha256};
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub struct Policy {
    pub balance: Profile,
    pub owner: RuleMode,
    pub cipher: RuleMode,
}
fn rejected(reason: impl AsRef<[u8]>) -> Error {
    failure("key_switch_rejected", reason, None)
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
fn digest(raw: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(raw)).into_bytes()
}
fn short_hash(raw: Option<&[u8]>) -> Vec<u8> {
    raw.map_or_else(|| b"none".to_vec(), |raw| digest(raw)[..16].to_vec())
}
fn current<'a>(ledger: &'a Ledger, tx: &Transaction) -> Result<&'a [u8]> {
    ledger
        .account(&tx.from)
        .map(|a| a.encrypted_balance.as_deref().unwrap_or(b"0"))
        .ok_or_else(|| rejected("account not found"))
}
fn canonical(raw: &[u8]) -> Result<(crypto::PublicKey, Vec<u8>)> {
    let raw = octra_node_protocol::transaction::decode_base64(raw)
        .map_err(|e| rejected(format!("Invalid_argument({:?})", e.to_string())))?;
    if raw.len() > 5_000_000 {
        return Err(rejected("pvac pubkey too large (max 5MB)"));
    }
    if !(raw.len() >= 6 && &raw[..4] == b"PVAC" && (1..=5).contains(&raw[4]) && raw[5] == 1
        || raw.len() >= 5 && raw[0] == 0xec)
    {
        return Err(rejected("pvac pubkey has invalid envelope"));
    }
    let key = check(crypto::proof_pubkey(&raw), "key_switch_rejected", b"", None)?;
    let raw = key.to_bytes().map_err(unavailable)?;
    Ok((key, raw))
}
pub fn owner_requested(tx: &Transaction, mode: RuleMode) -> bool {
    matches!(Payload::parse(tx, mode), Ok(p) if p.migration == Migration::Owner)
}
pub fn cipher_requested(tx: &Transaction, mode: RuleMode) -> bool {
    Payload::cipher_selected(tx, mode)
}
pub fn requires_history(tx: &Transaction, policy: Policy) -> bool {
    Payload::parse(tx, policy.balance.fields)
        .is_ok_and(|payload| payload.migration.needs_audit(policy.cipher))
}

pub struct Verified {
    transaction: [u8; 32],
    source: Vec<u8>,
    old: Option<Vec<u8>>,
    new_key: Vec<u8>,
    new_cipher: Option<Vec<u8>>,
}
impl Verified {
    pub fn current_cipher(&self) -> &[u8] {
        &self.source
    }
    pub fn transition_hash(&self) -> String {
        crypto::transition_hash(
            b"octra:private_transition:key_switch",
            &[
                &short_hash(self.old.as_deref()),
                &short_hash(Some(&self.new_key)),
                &self.new_key,
                self.new_cipher.as_deref().unwrap_or_default(),
                &self.source,
            ],
        )
    }
    pub fn public_key(&self) -> &[u8] {
        &self.new_key
    }
    pub fn apply(
        &self,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        tx: &Transaction,
        persist: impl FnOnce(&[u8]) -> std::result::Result<(), crate::execution::Error>,
    ) -> Result<()> {
        if tx.hash().map_err(unavailable)? != self.transaction
            || current(ledger, tx)? != self.source
        {
            return Err(rejected(
                "encrypted balance changed during key switch verification",
            ));
        }
        let bound = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|h| *h != b"none");
        let old_hash = self.old.as_deref().map(digest);
        if bound != old_hash.as_deref() {
            return Err(unavailable("key-switch source public key changed"));
        }
        let saved = state.save().map_err(unavailable)?;
        ledger.begin_journal();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger
                .debit(&tx.from, &tx.ou, tx.nonce, None)
                .map_err(|e| failure("key_switch_failed", e.0, None))?;
            // Public content-addressed files may survive an aborted attempt;
            // authority remains exclusively in the rollback-protected tree.
            persist(&self.new_key).map_err(unavailable)?;
            state
                .set(&[b"pvac_hashes", &tx.from], digest(&self.new_key))
                .map_err(unavailable)?;
            if let Some(cipher) = &self.new_cipher {
                ledger.update_encrypted_balance(&tx.from, cipher.clone());
            }
            Ok(())
        }));
        match result {
            Ok(Ok(())) => ledger.commit_journal().map_err(unavailable),
            Ok(Err(error)) => {
                ledger.abort_journal();
                state.restore(saved).map_err(unavailable)?;
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
    ledger: &Ledger,
    tx: &Transaction,
    policy: Policy,
    epoch: i64,
    admission: Option<&Admission>,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<Verified> {
    resolve(ledger, tx, policy, epoch, admission, Evidence::Proof, key)
}
pub(crate) fn resolve<B: AsRef<[u8]>>(
    ledger: &Ledger,
    tx: &Transaction,
    policy: Policy,
    epoch: i64,
    admission: Option<&Admission>,
    evidence: Evidence<'_>,
    key: impl FnOnce() -> Result<Option<B>>,
) -> Result<Verified> {
    if tx.op_type != OpType::KeySwitch {
        return Err(unavailable("key-switch route mismatch"));
    }
    if policy.balance.strict && matches!(evidence, Evidence::Certified(_)) {
        return Err(unavailable(
            "active private rules require proof verification",
        ));
    }
    if cipher_requested(tx, policy.balance.fields)
        && (policy.cipher != RuleMode::Active || !policy.balance.strict)
    {
        return Err(rejected("unknown key_switch migration_mode = cipher_proof"));
    }
    let payload = Payload::parse(tx, policy.balance.fields)?;
    if payload.kat != hex::encode(octra_hfhe::seeded_rng::aes_kat()).as_bytes() {
        return Err(rejected("AES KAT mismatch - incompatible key"));
    }
    let (public, new_key) = canonical(&payload.new_key)?;
    let old = key()?.map(|key| key.as_ref().to_vec());
    let source = current(ledger, tx)?;
    let status = classify::status(source, old.as_deref(), policy.balance.strict)?;
    let new_cipher = migration::prepare(
        &payload,
        &status,
        source,
        old.as_deref(),
        &public,
        policy,
        epoch,
        admission,
        &tx.from,
        matches!(evidence, Evidence::Proof),
    )?;
    let plan = Verified {
        transaction: tx.hash().map_err(unavailable)?,
        source: source.to_vec(),
        old,
        new_key,
        new_cipher,
    };
    if let Evidence::Certified(expected) = evidence {
        if expected != plan.transition_hash().as_bytes() {
            return Err(failure(
                "preverify_transition_mismatch",
                "private transition does not match the certified receipt",
                None,
            ));
        }
    }
    Ok(plan)
}
