//! Durable prepaid purchases and separate local delivery accounting. Purchase
//! the explicit class caps before forwarding; interrupted handoffs retain
//! uncertain capacity. Canonical purchase confirmation belongs to the runner.
//! This journal stores public authorization material, never secrets.
//! The runner must keep one stable path per plan and only Create for a genuinely
//! new plan. Full directory rollback or deletion by the host owner requires an
//! independent operator/chain high-water mark; a local checksum cannot detect it.
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    payments::{
        Budget, Connect, Direction, PlanBinding, SignedConnect, SignedUsage, Tariff, Usage,
    },
    sig::{verify, KeyPair, PublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Arc};

pub(crate) mod storage;
use storage::Store;

/// Creation is an explicit fresh-plan operation. Recovery never infers creation
/// from a missing file or an incomplete previous initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    Create,
    Resume,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    binding: PlanBinding,
    tariff: Tariff,
    original_budget_ou: u64,
    prepaid_bytes: Vec<u64>,
    receipt_key: PublicKey,
    #[serde(default, skip_serializing_if = "is_false")]
    stock: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    identity: Identity,
    connection_sequence: u64,
    usage_sequence: u64,
    local_bytes: Vec<u64>,
    authorized_bytes: Vec<u64>,
    receipts: Vec<Option<SignedUsage>>,
    #[serde(default, skip_serializing_if = "is_zero")]
    handoff_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    uncertain_bytes: Vec<u64>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde's callback takes a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde's callback takes a reference"
)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    sequence: u64,
    traffic_class: u8,
    bytes: u64,
}

/// Opaque single-use handoff identity. Dropping it leaves the durable pending
/// record held; only an explicit unsent cancellation releases its capacity.
#[must_use = "confirm successful forwarding or cancel a definitely unsent handoff"]
pub(crate) struct Reservation {
    sequence: u64,
}

#[derive(Debug)]
pub(crate) struct PrepaidExhausted;
impl std::fmt::Display for PrepaidExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("prepaid traffic class capacity exhausted")
    }
}
impl std::error::Error for PrepaidExhausted {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: State,
    checksum: String,
}

fn checksum(state: &State) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"Octranet client prepaid state v2\0");
    hash.update(serde_json::to_vec(state)?);
    Ok(hex::encode(hash.finalize()))
}

impl State {
    fn capacity_totals(&self) -> Result<Vec<u64>> {
        ensure!(
            self.uncertain_bytes.is_empty() || self.uncertain_bytes.len() == self.local_bytes.len(),
            "client uncertain counter shape differs"
        );
        ensure!(
            !self.uncertain_bytes.is_empty()
                || (self.handoff_sequence == 0 && self.pending.is_none()),
            "new handoff history lacks uncertain counters"
        );
        let mut totals = self
            .local_bytes
            .iter()
            .enumerate()
            .map(|(class, local)| {
                local
                    .checked_add(self.uncertain_bytes.get(class).copied().unwrap_or(0))
                    .context("client uncertain byte counter overflow")
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(pending) = &self.pending {
            ensure!(
                pending.sequence > 0
                    && pending.sequence == self.handoff_sequence
                    && pending.bytes > 0,
                "client pending handoff identity differs"
            );
            let total = totals
                .get_mut(usize::from(pending.traffic_class))
                .context("client pending class missing")?;
            *total = total
                .checked_add(pending.bytes)
                .context("client pending byte counter overflow")?;
        }
        Ok(totals)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 2,
            "postpaid or unsupported client payment journal version"
        );
        self.identity.binding.validate()?;
        ensure!(
            self.identity.tariff.hash_hex()? == self.identity.binding.manifest_hash,
            "client tariff differs from the accepted plan manifest"
        );
        ensure!(
            self.identity.original_budget_ou > 0,
            "zero original plan budget"
        );
        let classes = self.identity.tariff.classes().len();
        ensure!(
            self.local_bytes.len() == classes
                && self.authorized_bytes.len() == classes
                && self.receipts.len() == classes
                && self.identity.prepaid_bytes.len() == classes,
            "client payment counter shape differs from the tariff"
        );
        validate_purchase(
            &self.identity.tariff,
            self.identity.original_budget_ou,
            &self.identity.prepaid_bytes,
        )?;
        ensure!(
            self.authorized_bytes.iter().all(|bytes| *bytes == 0)
                || self.authorized_bytes == self.identity.prepaid_bytes,
            "client purchase differs from explicit immutable target"
        );
        ensure!(
            self.capacity_totals()?
                .iter()
                .zip(&self.authorized_bytes)
                .all(|(used, purchased)| used <= purchased),
            "client delivery exposure exceeds purchased capacity"
        );
        Budget::new(
            self.identity.tariff.clone(),
            self.identity.original_budget_ou,
            self.capacity_totals()?,
        )?;
        Budget::new(
            self.identity.tariff.clone(),
            self.identity.original_budget_ou,
            self.authorized_bytes.clone(),
        )?;
        let mut sequences = BTreeSet::new();
        for (class, authorized) in self.authorized_bytes.iter().enumerate() {
            match &self.receipts[class] {
                Some(receipt) => {
                    receipt.verify()?;
                    ensure!(
                        *authorized > 0
                            && receipt.receipt_key == self.identity.receipt_key
                            && receipt.usage.binding() == self.identity.binding
                            && usize::from(receipt.usage.traffic_class) == class
                            && receipt.usage.total_bytes == *authorized
                            && receipt.usage.sequence <= self.usage_sequence,
                        "stored client receipt differs from its immutable plan or counters"
                    );
                    ensure!(
                        sequences.insert(receipt.usage.sequence),
                        "duplicate stored receipt sequence"
                    );
                }
                None => ensure!(
                    *authorized == 0,
                    "authorized bytes lack a durable signed receipt"
                ),
            }
        }
        ensure!(
            sequences.last().copied().unwrap_or(0) == self.usage_sequence,
            "client usage sequence differs from durable receipt high-water mark"
        );
        Ok(())
    }
}

/// One serialized payer for one immutable plan. Unix paths are owner-only;
/// platforms without a verified private-storage implementation fail closed.
pub(crate) struct Journal {
    store: Store,
    state: State,
    key: Arc<KeyPair>,
    poisoned: bool,
}

impl Journal {
    pub(crate) fn open(
        path: &Path,
        binding: PlanBinding,
        tariff: Tariff,
        original_budget_ou: u64,
        prepaid_bytes: Vec<u64>,
        key: Arc<KeyPair>,
        mode: OpenMode,
    ) -> Result<Self> {
        Self::open_mode(
            path,
            binding,
            tariff,
            original_budget_ou,
            prepaid_bytes,
            (key, false),
            mode,
        )
    }
    pub(crate) fn open_stock(
        path: &Path,
        plan: &crate::payment_runner::Plan,
        key: Arc<KeyPair>,
        mode: OpenMode,
    ) -> Result<Self> {
        Self::open_mode(
            path,
            plan.binding.clone(),
            plan.tariff.clone(),
            plan.original_budget_ou,
            plan.prepaid_bytes.clone(),
            (key, true),
            mode,
        )
    }
    fn open_mode(
        path: &Path,
        binding: PlanBinding,
        tariff: Tariff,
        original_budget_ou: u64,
        prepaid_bytes: Vec<u64>,
        (key, stock): (Arc<KeyPair>, bool),
        mode: OpenMode,
    ) -> Result<Self> {
        binding.validate()?;
        ensure!(
            tariff.hash_hex()? == binding.manifest_hash,
            "tariff differs from plan manifest"
        );
        ensure!(original_budget_ou > 0, "zero original plan budget");
        validate_purchase(&tariff, original_budget_ou, &prepaid_bytes)?;
        let possession = b"Octranet client payment key possession v1\0";
        verify(&key.public, possession, &key.sign(possession))
            .context("receipt key does not match its signing secret")?;
        let identity = Identity {
            binding,
            tariff,
            original_budget_ou,
            prepaid_bytes,
            receipt_key: key.public,
            stock,
        };
        let mut store = Store::open(path, mode)?;
        let mut state = match mode {
            OpenMode::Create => {
                let classes = identity.tariff.classes().len();
                let state = State {
                    version: 2,
                    identity,
                    connection_sequence: 0,
                    usage_sequence: 0,
                    local_bytes: vec![0; classes],
                    authorized_bytes: vec![0; classes],
                    receipts: vec![None; classes],
                    handoff_sequence: 0,
                    pending: None,
                    uncertain_bytes: vec![0; classes],
                };
                state.validate()?;
                let envelope = Envelope {
                    checksum: checksum(&state)?,
                    payload: state.clone(),
                };
                store.commit(&serde_json::to_vec(&envelope)?)?;
                state
            }
            OpenMode::Resume => {
                let envelope: Envelope = serde_json::from_slice(&store.read()?)
                    .context("invalid or incomplete client payment journal; refusing reset")?;
                ensure!(
                    envelope.checksum == checksum(&envelope.payload)?,
                    "client payment journal checksum mismatch"
                );
                ensure!(
                    envelope.payload.identity == identity,
                    "client payment journal identity, tariff, budget or key changed"
                );
                envelope.payload.validate()?;
                envelope.payload
            }
        };
        let recovered = if let Some(pending) = state.pending.take() {
            let uncertain = &mut state.uncertain_bytes[usize::from(pending.traffic_class)];
            *uncertain = uncertain
                .checked_add(pending.bytes)
                .context("client uncertain byte counter overflow")?;
            true
        } else {
            false
        };
        if recovered {
            state.validate()?;
            let envelope = Envelope {
                checksum: checksum(&state)?,
                payload: state.clone(),
            };
            store.commit(&serde_json::to_vec(&envelope)?)?;
        }
        Ok(Self {
            store,
            state,
            key,
            poisoned: false,
        })
    }

    fn ready(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "client payment journal write was ambiguous; reopen before further authorization"
        );
        self.store.check()
    }

    fn commit(&mut self, next: State) -> Result<()> {
        self.ready()?;
        next.validate()?;
        let envelope = Envelope {
            checksum: checksum(&next)?,
            payload: next.clone(),
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(error)
                .context("client payment journal commit failed; authorization stopped");
        }
        self.state = next;
        Ok(())
    }

    /// Persist the next sequence before releasing its signed connect request.
    /// A reconnect never resets class counters, budget or receipt history.
    pub(crate) fn connect(&mut self, wireguard_key: [u8; 32]) -> Result<SignedConnect> {
        self.ready()?;
        let mut next = self.state.clone();
        next.connection_sequence = next
            .connection_sequence
            .checked_add(1)
            .context("client connection sequence exhausted")?;
        let request = Connect {
            binding: next.identity.binding.clone(),
            sequence: next.connection_sequence,
            wireguard_key,
        };
        let signed = if next.identity.stock {
            SignedConnect::sign_stock(request, &self.key)?
        } else {
            SignedConnect::sign(request, &self.key)?
        };
        self.commit(next)?;
        Ok(signed)
    }

    /// Non-mutating prepaid preflight. The runner must serialize its I/O and
    /// confirmation path; this is not a reservation for concurrent sends.
    pub(crate) fn check(&self, packet: &[u8], direction: Direction) -> Result<u8> {
        self.ready()?;
        let class = self
            .state
            .identity
            .tariff
            .classify_ipv4(packet, direction)?;
        let total = self.state.capacity_totals()?[usize::from(class)]
            .checked_add(u64::try_from(packet.len())?)
            .context("client prepaid byte counter overflow")?;
        if total > self.state.authorized_bytes[usize::from(class)] {
            return Err(PrepaidExhausted.into());
        }
        Ok(class)
    }

    /// Persist intent before any network or TUN handoff. The runner serializes
    /// application packets; a pending operation cannot be overwritten.
    pub(crate) fn reserve(&mut self, packet: &[u8], direction: Direction) -> Result<Reservation> {
        ensure!(
            self.state.pending.is_none(),
            "client handoff still pending; reopen to recover uncertain capacity"
        );
        let class = self.check(packet, direction)?;
        let mut next = self.state.clone();
        next.handoff_sequence = next
            .handoff_sequence
            .checked_add(1)
            .context("client handoff sequence exhausted")?;
        let sequence = next.handoff_sequence;
        next.pending = Some(Pending {
            sequence,
            traffic_class: class,
            bytes: u64::try_from(packet.len())?,
        });
        self.commit(next)?;
        Ok(Reservation { sequence })
    }

    /// Confirm only a complete successful local handoff. A failure leaves the
    /// pre-handoff record recoverable, even if the send itself already worked.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Consuming the token prevents reuse"
    )]
    pub(crate) fn confirm(&mut self, reservation: Reservation) -> Result<()> {
        self.ready()?;
        let mut next = self.state.clone();
        let pending = next.pending.take().context("client handoff missing")?;
        ensure!(
            pending.sequence == reservation.sequence,
            "client handoff identity differs"
        );
        let local = &mut next.local_bytes[usize::from(pending.traffic_class)];
        *local = local
            .checked_add(pending.bytes)
            .context("client byte counter overflow")?;
        self.commit(next)
    }

    /// Release only when the caller knows no application packet was handed off.
    /// Unknown send outcomes must leave the reservation pending instead.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Consuming the token prevents reuse"
    )]
    pub(crate) fn cancel(&mut self, reservation: Reservation) -> Result<()> {
        self.ready()?;
        let mut next = self.state.clone();
        let pending = next.pending.take().context("client handoff missing")?;
        ensure!(
            pending.sequence == reservation.sequence,
            "client handoff identity differs"
        );
        self.commit(next)
    }

    #[cfg(test)]
    pub(crate) fn count(&mut self, packet: &[u8], direction: Direction) -> Result<u8> {
        let class = self.check(packet, direction)?;
        let reservation = self.reserve(packet, direction)?;
        self.confirm(reservation)?;
        Ok(class)
    }

    /// Persist the explicit purchase before returning its signature. Neither
    /// local delivery nor any operator-proposed counter can increase this cap.
    /// Resume returns the identical receipts for idempotent canonical retry.
    pub(crate) fn purchases(&mut self) -> Result<Vec<SignedUsage>> {
        self.ready()?;
        let mut next = self.state.clone();
        let mut changed = false;
        for (class, &bytes) in self.state.identity.prepaid_bytes.iter().enumerate() {
            if bytes == next.authorized_bytes[class] {
                continue;
            }
            ensure!(
                bytes > next.authorized_bytes[class],
                "prepaid authorization counter regressed"
            );
            next.usage_sequence = next
                .usage_sequence
                .checked_add(1)
                .context("client usage sequence exhausted")?;
            let usage = Usage::from_binding(
                next.identity.binding.clone(),
                u8::try_from(class)?,
                next.usage_sequence,
                bytes,
            )?;
            next.receipts[class] = Some(SignedUsage::sign(usage, &self.key)?);
            next.authorized_bytes[class] = bytes;
            changed = true;
        }
        if changed {
            self.commit(next)?;
        }
        self.pending_receipts()
    }

    pub(crate) fn pending_receipts(&self) -> Result<Vec<SignedUsage>> {
        self.ready()?;
        Ok(self.state.receipts.iter().flatten().cloned().collect())
    }

    pub(crate) fn totals(&self) -> &[u64] {
        &self.state.local_bytes
    }
    pub(crate) fn authorized_totals(&self) -> &[u64] {
        &self.state.authorized_bytes
    }
    #[cfg(test)]
    pub(crate) fn uncertain_totals(&self) -> &[u64] {
        &self.state.uncertain_bytes
    }
    pub(crate) fn held_totals(&self) -> Result<Vec<u64>> {
        Ok(self
            .state
            .capacity_totals()?
            .iter()
            .zip(&self.state.local_bytes)
            .map(|(capacity, confirmed)| capacity - confirmed)
            .collect())
    }
    pub(crate) fn remaining_ou(&self) -> Result<u64> {
        self.ready()?;
        Ok(Budget::new(
            self.state.identity.tariff.clone(),
            self.state.identity.original_budget_ou,
            self.state.authorized_bytes.clone(),
        )?
        .remaining_ou())
    }
}

pub(crate) fn validate_purchase(tariff: &Tariff, budget: u64, targets: &[u64]) -> Result<()> {
    ensure!(
        targets.len() == tariff.classes().len(),
        "prepaid purchase class count differs"
    );
    ensure!(
        targets.iter().any(|bytes| *bytes > 0),
        "prepaid purchase requires a finite byte target"
    );
    Budget::new(tariff.clone(), budget, targets.to_vec())?;
    Ok(())
}

#[cfg(test)]
mod tests;
