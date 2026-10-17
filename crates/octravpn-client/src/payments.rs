//! Durable payer authorization. Counting is called only after confirmed local
//! forwarding; dropped or ambiguously queued packets must not enter this state.
//! Canonical plan admission and authenticated operator counters belong to the
//! runner. This journal stores public authorization material, never secrets.
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

mod storage;
use storage::Store;

/// Creation is an explicit fresh-plan operation. Recovery never infers creation
/// from a missing file or an incomplete previous initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenMode {
    Create,
    Resume,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    binding: PlanBinding,
    tariff: Tariff,
    original_budget_ou: u64,
    receipt_key: PublicKey,
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: State,
    checksum: String,
}

fn checksum(state: &State) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"Octranet client payment state v1\0");
    hash.update(serde_json::to_vec(state)?);
    Ok(hex::encode(hash.finalize()))
}

impl State {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported client payment journal version"
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
                && self.receipts.len() == classes,
            "client payment counter shape differs from the tariff"
        );
        Budget::new(
            self.identity.tariff.clone(),
            self.identity.original_budget_ou,
            self.local_bytes.clone(),
        )?;
        Budget::new(
            self.identity.tariff.clone(),
            self.identity.original_budget_ou,
            self.authorized_bytes.clone(),
        )?;
        let mut sequences = BTreeSet::new();
        for (class, (local, authorized)) in self
            .local_bytes
            .iter()
            .zip(&self.authorized_bytes)
            .enumerate()
        {
            ensure!(
                authorized <= local,
                "authorization exceeds confirmed local traffic"
            );
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
        key: Arc<KeyPair>,
        mode: OpenMode,
    ) -> Result<Self> {
        binding.validate()?;
        ensure!(
            tariff.hash_hex()? == binding.manifest_hash,
            "tariff differs from plan manifest"
        );
        ensure!(original_budget_ou > 0, "zero original plan budget");
        let possession = b"Octranet client payment key possession v1\0";
        verify(&key.public, possession, &key.sign(possession))
            .context("receipt key does not match its signing secret")?;
        let identity = Identity {
            binding,
            tariff,
            original_budget_ou,
            receipt_key: key.public,
        };
        let mut store = Store::open(path, mode)?;
        let state = match mode {
            OpenMode::Create => {
                let classes = identity.tariff.classes().len();
                let state = State {
                    version: 1,
                    identity,
                    connection_sequence: 0,
                    usage_sequence: 0,
                    local_bytes: vec![0; classes],
                    authorized_bytes: vec![0; classes],
                    receipts: vec![None; classes],
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
        let signed = SignedConnect::sign(
            Connect {
                binding: next.identity.binding.clone(),
                sequence: next.connection_sequence,
                wireguard_key,
            },
            &self.key,
        )?;
        self.commit(next)?;
        Ok(signed)
    }

    /// Non-mutating budget preflight. The runner must serialize its I/O and
    /// confirmation path; this is not a reservation for concurrent sends.
    pub(crate) fn check(&self, packet: &[u8], direction: Direction) -> Result<u8> {
        self.ready()?;
        let class = self
            .state
            .identity
            .tariff
            .classify_ipv4(packet, direction)?;
        let mut budget = Budget::new(
            self.state.identity.tariff.clone(),
            self.state.identity.original_budget_ou,
            self.state.local_bytes.clone(),
        )?;
        budget.reserve(class, u64::try_from(packet.len())?)?;
        Ok(class)
    }

    /// Call only after the runner confirms forwarding this complete raw IPv4
    /// packet. There is no method that turns queued/ambiguous sends into usage.
    /// Synchronous durable commits favor correctness over packet throughput.
    pub(crate) fn count(&mut self, packet: &[u8], direction: Direction) -> Result<u8> {
        let class = self.check(packet, direction)?;
        let mut next = self.state.clone();
        next.local_bytes[usize::from(class)] = next.local_bytes[usize::from(class)]
            .checked_add(u64::try_from(packet.len())?)
            .context("client byte counter overflow")?;
        self.commit(next)?;
        Ok(class)
    }

    /// The runner authenticates these counters to the same plan/operator first.
    /// New authorizations never exceed either party's confirmed cumulative
    /// count. A regressing operator cannot revoke an already-issued receipt.
    /// Return all latest receipts, permitting idempotent transport retry.
    pub(crate) fn receipts(&mut self, operator_totals: &[u64]) -> Result<Vec<SignedUsage>> {
        self.ready()?;
        ensure!(
            operator_totals.len() == self.state.local_bytes.len(),
            "operator class counter shape differs"
        );
        let mut next = self.state.clone();
        let mut changed = false;
        for (class, operator_total) in operator_totals.iter().enumerate() {
            ensure!(
                *operator_total >= next.authorized_bytes[class],
                "operator counters regressed below durable authorization"
            );
            let bytes = next.local_bytes[class].min(*operator_total);
            if bytes == next.authorized_bytes[class] {
                continue;
            }
            ensure!(
                bytes > next.authorized_bytes[class],
                "local authorization counter regressed"
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
    pub(crate) fn binding(&self) -> &PlanBinding {
        &self.state.identity.binding
    }
    pub(crate) fn remaining_ou(&self) -> Result<u64> {
        self.ready()?;
        Ok(Budget::new(
            self.state.identity.tariff.clone(),
            self.state.identity.original_budget_ou,
            self.state.local_bytes.clone(),
        )?
        .remaining_ou())
    }
}

#[cfg(test)]
mod tests;
