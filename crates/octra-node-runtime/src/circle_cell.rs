// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native state-bound private cell plans. Receipts carry the transition hash;
//! active execution reconstructs the plan and verifies the proof again.
use crate::{
    circle::CircleRuntime,
    circle_cell_crypto::{self as worker, Kind as WorkerKind},
    circle_error::{self, refused, unavailable, Failure},
    circle_operation as host, circle_store, circle_transport_store as outbox, execution,
    private_crypto,
    state_batch::{Snapshot, StateBatch},
};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    circle_cell::{Kind, ProofFields, Request},
    circle_policy::{
        hfhe::{Access, Proof},
        receipt,
    },
    circle_resources::Locator,
    circles::{AssetMeta, LocatorMode, ResourceMode},
    native_json::{Document, ReadError, ReadMode},
    state::Ledger,
    transaction::{decode_base64, OpType, Transaction},
};
use std::sync::Arc;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("circle cell input rejected: {0:?}")]
    Rejected(Vec<u8>),
    #[error("circle cell execution unavailable: {0}")]
    Unavailable(#[source] execution::Error),
}
type Result<T> = std::result::Result<T, Error>;
fn rejected(reason: impl Into<Vec<u8>>) -> Error {
    Error::Rejected(reason.into())
}
fn operational(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(execution::Error(reason.to_string()))
}
impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        match error {
            Failure::Refused(error) => Self::Rejected(error.reason),
            Failure::Unavailable(error) => Self::Unavailable(error),
        }
    }
}
impl From<private_crypto::Error> for Error {
    fn from(error: private_crypto::Error) -> Self {
        match error {
            private_crypto::Error::Rejected(reason) => Self::Rejected(reason),
            private_crypto::Error::Unavailable(error) => operational(error),
        }
    }
}
pub fn tag(tx: &Transaction) -> &'static str {
    if tx.op_type == OpType::CircleBalanceCellPut {
        "invalid_circle_balance_cell"
    } else {
        "invalid_circle_register_cell"
    }
}
pub struct Prepared {
    transaction: [u8; 32],
    transition: String,
    request: Request,
    raw_cipher: Vec<u8>,
    cipher: Vec<u8>,
    public: Arc<[u8]>,
    proof: Vec<u8>,
    amount: Vec<u8>,
    worker: WorkerKind,
}
fn proof_plan(
    request: &Request,
    fields: &ProofFields,
    kind: Proof,
) -> Result<(WorkerKind, Vec<u8>, Vec<u8>)> {
    let amount = request
        .amount_commitment
        .as_ref()
        .or(fields.amount.as_ref());
    match kind {
        Proof::None => {
            if fields.zero.is_some() || fields.range.is_some() || fields.receipt.is_some() {
                return Err(rejected(b"proof fields require a circle hfhe proof policy"));
            }
            Ok((WorkerKind::None, vec![], vec![]))
        }
        Proof::ZeroReceipt => {
            if request.kind == Kind::Balance {
                return Err(rejected(
                    b"zero receipt does not bind a balance cell amount commitment",
                ));
            }
            match (&fields.zero, &fields.range, &fields.receipt) {
                (Some(proof), None, Some(_)) => Ok((WorkerKind::Zero, proof.clone(), vec![])),
                _ => Err(rejected(b"zero proof and proof receipt are required")),
            }
        }
        Proof::BoundZero | Proof::BoundZeroReceipt => match (&fields.zero, &fields.range, amount) {
            (Some(proof), None, Some(amount)) => {
                Ok((WorkerKind::BoundZero, proof.clone(), amount.clone()))
            }
            _ => Err(rejected(b"zero proof and amount commitment are required")),
        },
        Proof::Range | Proof::RangeReceipt => match (&fields.zero, &fields.range, amount) {
            (None, Some(proof), Some(amount)) => {
                Ok((WorkerKind::Range, proof.clone(), amount.clone()))
            }
            _ => Err(rejected(b"range proof and amount commitment are required")),
        },
    }
}
pub fn prepare(
    runtime: &CircleRuntime,
    tx: &Transaction,
    state: &Snapshot,
    epoch: i64,
) -> Result<Prepared> {
    let kind = match tx.op_type {
        OpType::CircleBalanceCellPut => Kind::Balance,
        OpType::CircleRegisterCellPut => Kind::Register,
        _ => return Err(rejected(b"transaction is not a circle cell write")),
    };
    let raw = tx
        .message
        .as_deref()
        .ok_or_else(|| rejected(b"circle cell requires message payload"))?;
    let doc = Document::parse_native(raw, ReadMode::Safe).map_err(|error| match error {
        ReadError::Json { .. } => rejected(b"circle cell payload is invalid json"),
        ReadError::Unavailable(error) => operational(error),
    })?;
    let request = Request::parse(&doc, kind).map_err(Error::Rejected)?;
    let fields = ProofFields::parse(&doc).map_err(Error::Rejected)?;
    let encoded = tx
        .encrypted_data
        .as_deref()
        .ok_or_else(|| rejected(b"circle cell ciphertext is required"))?;
    let raw_cipher = decode_base64(encoded)
        .ok()
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| rejected(b"circle cell ciphertext is invalid"))?;
    let info = circle_store::info(state, &tx.to)
        .map_err(operational)?
        .ok_or_else(|| rejected(b"circle does not exist"))?;
    if info.owner != tx.from {
        return Err(rejected(
            b"only the owner can modify circle private state cells",
        ));
    }
    if info.resource != b"sealed_read" {
        return Err(rejected(
            b"private state cells require sealed_read circle mode",
        ));
    }
    let policy = circle_store::hfhe_policy(state, &tx.to).map_err(operational)?;
    let proof_kind = request.proof.unwrap_or(Proof::None);
    if proof_kind != policy.encrypt_proof {
        return Err(rejected(
            b"circle cell proof kind does not match hfhe policy",
        ));
    }
    let needs_relays =
        policy.modes[1].relay_scoped() || receipt::transport_required(&policy, proof_kind);
    let mut relays = vec![];
    if needs_relays {
        if fields.intent.is_empty() {
            return Err(rejected(b"intent_id is required by circle hfhe policy"));
        }
        let transport = outbox::policy(state, &tx.to)?;
        let claims = outbox::active_claims(state, &tx.to, &fields.intent, epoch)?;
        if !transport.ready(&claims) {
            return Err(rejected(b"circle outbox relay quorum is not ready"));
        }
        relays = claims.into_iter().map(|claim| claim.relay).collect();
        relays.sort();
        relays.dedup();
    }
    // Cell encryption has no separate subject: native owner_or_caller requires
    // ownership, while caller_self permits this authenticated caller.
    let allowed = if policy.modes[1] == Access::OwnerCaller {
        info.owner == tx.from
    } else {
        policy.modes[1].allows(&info.owner, &tx.from, &tx.from, &relays)
    };
    if !allowed {
        return Err(rejected(b"circle hfhe policy denied encryption"));
    }
    let key_state = outbox::key_policy(state, &tx.to, &request.key)?.state(epoch);
    if policy.require_live_key && key_state != octra_node_protocol::circle_policy::key::State::Live
    {
        return Err(rejected(b"circle key policy is not live"));
    }
    if state
        .get(&[b"pvac_hashes", &tx.from])
        .is_none_or(|hash| hash == b"none")
    {
        return Err(rejected(b"pvac key is not consensus bound"));
    }
    let public = runtime
        .public_key(state, &tx.from)
        .map_err(Error::Unavailable)?
        .ok_or_else(|| rejected(b"pvac pubkey is unavailable"))?;
    let (worker, proof, amount) = proof_plan(&request, &fields, proof_kind)?;
    let policy_hash = policy.hash();
    let cipher_hash = receipt::sha256(&raw_cipher);
    let amount_hash = if amount.is_empty() {
        vec![]
    } else {
        receipt::hash_commitment(&amount).map_err(Error::Rejected)?
    };
    let context = receipt::Context {
        circle: &tx.to,
        caller: &tx.from,
        key: &request.key,
        intent: &fields.intent,
        verb: b"encrypt",
        proof: proof_kind.as_bytes(),
        policy: &policy_hash,
        ciphertext: &cipher_hash,
        amount: &amount_hash,
    };
    let receipt_hash = match (
        proof_kind.receipt_required(),
        &request.receipt_hash,
        &fields.receipt,
    ) {
        (false, None, None) => vec![],
        (false, _, _) => return Err(rejected(b"proof receipt requires a receipt proof kind")),
        (true, Some(expected), Some(value)) => {
            let hash = receipt::verify(&doc, value, &context, &policy, &info.owner, &relays)
                .map_err(Error::Rejected)?;
            if &hash != expected {
                return Err(rejected(b"proof receipt hash mismatch"));
            }
            hash
        }
        (true, _, _) => {
            return Err(rejected(
                b"proof receipt and proof receipt hash are required",
            ))
        }
    };
    let transaction = tx.hash().map_err(operational)?;
    let transaction_hex = hex::encode(transaction);
    let proof_hash = receipt::sha256(&proof);
    let transition = receipt::sha256(&receipt::frame(
        b"octra:circle_cell_transition:v1",
        &[
            transaction_hex.as_bytes(),
            tx.op_type.as_str().as_bytes(),
            &request.state,
            &request.key,
            &policy_hash,
            key_state.as_bytes(),
            proof_kind.as_bytes(),
            &cipher_hash,
            &request.ciphertext_commitment,
            &amount,
            &proof_hash,
            &receipt_hash,
            &fields.intent,
        ],
    ));
    Ok(Prepared {
        transaction,
        transition: String::from_utf8(transition).map_err(operational)?,
        request,
        raw_cipher,
        cipher: [b"hfhe_v1|".as_slice(), encoded].concat(),
        public,
        proof,
        amount,
        worker,
    })
}
impl Prepared {
    pub fn transition_hash(&self) -> &str {
        &self.transition
    }
    pub fn source_cipher(&self) -> &[u8] {
        &self.raw_cipher
    }
    pub fn verify(&self, strict: bool, math: ScalarRule) -> Result<()> {
        worker::verify(
            &self.public,
            &self.cipher,
            &self.request.ciphertext_commitment,
            self.worker,
            &self.proof,
            &self.amount,
            strict,
            math,
        )
        .map_err(Error::from)
    }
    fn apply(
        &self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> std::result::Result<(), Failure> {
        if tx.hash().map_err(unavailable)? != self.transaction {
            return Err(unavailable("circle cell transaction binding changed"));
        }
        let info = host::owned(state, tx, b"private state cells")?;
        if info.resource != b"sealed_read" {
            return Err(refused(
                "circle_mode_invalid",
                b"private state cells require sealed_read circle mode",
            ));
        }
        let locator = Locator::sealed(&tx.to, None, Some(&self.request.state))?;
        host::debit(ledger, tx)?;
        let size = self.raw_cipher.len() as i64;
        let next = crate::circle_resource_ops::usage(state, &tx.to, &locator.key, size)?;
        if size > info.limits[1] {
            return Err(refused(
                "circle_asset_too_large",
                b"private state cell exceeds circle asset limit",
            ));
        }
        if next > info.limits[1] {
            return Err(refused(
                "circle_assets_limit_exceeded",
                b"private state cell exceeds circle asset budget",
            ));
        }
        let request = &self.request;
        let meta = AssetMeta {
            path_key: locator.key.clone(),
            canonical_path: locator.path,
            resource_key: locator.resource,
            content_type: request.content_type.clone(),
            encoding: request
                .encoding
                .clone()
                .unwrap_or_else(|| b"identity".to_vec()),
            size_bytes: size,
            blob_hash: receipt::sha256(&self.raw_cipher),
            body_mode: ResourceMode::Sealed,
            plaintext_hash: Some(request.plaintext.clone()),
            key_id: Some(request.key.clone()),
            padding_class: request.padding.clone(),
            locator_mode: LocatorMode::State,
            slot_ref: None,
            activate_after_epoch: request.activate,
            expire_after_epoch: request.expire,
            metadata_mode: request.metadata,
        };
        host::save_policy(state, tx, &info, request.snapshot(&locator.key))?;
        circle_store::save_asset(
            state,
            &tx.to,
            &meta,
            tx.encrypted_data.as_deref().unwrap_or_default(),
            next,
        )
        .map_err(unavailable)
    }
}
/// Native producer qualification uses an isolated ledger/tree, verifies under
/// the selected historical rule, then exercises the complete fee/storage path.
pub fn preverify(
    runtime: &CircleRuntime,
    tx: &Transaction,
    ledger: &Ledger,
    state: &Snapshot,
    epoch: i64,
    strict: bool,
    math: ScalarRule,
) -> Result<Prepared> {
    let plan = prepare(runtime, tx, state, epoch)?;
    plan.verify(strict, math)?;
    let mut preview_ledger =
        Ledger::from_accounts(ledger.accounts().clone()).map_err(operational)?;
    let mut preview_state = StateBatch::from_snapshot(state.clone());
    preview_state.begin().map_err(operational)?;
    let completion = execute(
        runtime,
        tx,
        &mut preview_ledger,
        &mut preview_state,
        epoch,
        Some(plan.transition.as_bytes()),
        strict,
        math,
    )
    .map_err(Error::Unavailable)?;
    match completion {
        execution::Completion::Confirmed { .. } => Ok(plan),
        execution::Completion::Rejected(refusal) => Err(rejected(
            [refusal.tag.as_bytes(), b":", &refusal.reason].concat(),
        )),
        execution::Completion::Deferred { .. } => Err(operational("circle cell preview deferred")),
    }
}
pub(crate) fn execute(
    runtime: &CircleRuntime,
    tx: &Transaction,
    ledger: &mut Ledger,
    state: &mut StateBatch,
    epoch: i64,
    expected: Option<&[u8]>,
    reverify: bool,
    math: ScalarRule,
) -> std::result::Result<execution::Completion, execution::Error> {
    let result = (|| {
        let expected =
            expected.ok_or_else(|| rejected(b"circle cell preverify receipt is required"))?;
        let plan = prepare(runtime, tx, &state.snapshot(), epoch)?;
        if plan.transition.as_bytes() != expected {
            return Err(rejected(b"circle cell transition hash mismatch"));
        }
        if reverify {
            plan.verify(true, math)?;
        }
        Ok(plan)
    })();
    let applied = match result {
        Ok(plan) => plan.apply(tx, ledger, state),
        Err(Error::Rejected(reason)) => Err(refused(tag(tx), reason)),
        Err(Error::Unavailable(error)) => Err(Failure::Unavailable(error)),
    };
    circle_error::completion(applied)
}
