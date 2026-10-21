//! Private transport bookkeeping. Signed snapshots are observations, not money
//! proofs; only the operator's canonical packet guard authorizes forwarding.
use super::{Identity, Journal, KeyPair, OpenMode, State};
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    payments::{PrivateTarget, SignedShieldedStatus},
    sealed::{Key, Protection},
    Address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateIdentity {
    target: PrivateTarget,
    operator_generation: u64,
}

pub(super) fn protection(identity: &Identity, key: &KeyPair) -> Result<Protection> {
    let mut hash = Sha256::new();
    hash.update(b"Octranet private client journal v1\0");
    hash.update(serde_json::to_vec(identity)?);
    let scope: [u8; 32] = hash.finalize().into();
    Ok(Protection::new(
        Key::from_bytes(*key.secret_bytes()).derive(b"private client journal", &scope)?,
        scope,
    ))
}

impl State {
    pub(super) fn validate_private(&self) -> Result<()> {
        let Some(private) = &self.identity.private else {
            ensure!(
                self.private_status.is_none(),
                "public journal contains private accounting"
            );
            return Ok(());
        };
        private.target.pool.validate()?;
        octravpn_core::parse_native_address(private.target.directory.display())?;
        ensure!(
            private.target.chain_origin != [0; 32]
                && private.target.pool == self.identity.binding.deployment
                && self.identity.binding.payer
                    == Address::from_pubkey(&self.identity.receipt_key.0)
                && self.identity.binding.generation == 1
                && self.identity.binding.plan > 0
                && Address::from_pubkey(&private.target.operator.0)
                    == *self.identity.tariff.operator()
                && private.operator_generation > 0
                && self.service_receipts.is_empty()
                && self.service_conflict.is_none(),
            "private transport identity differs"
        );
        if let Some(signed) = &self.private_status {
            signed.verify()?;
            let view = &signed.status;
            ensure!(
                signed.operator_key == private.target.operator
                    && view.connection.binding == self.identity.binding
                    && view.operator_generation == private.operator_generation
                    && view.tariff == self.identity.tariff
                    && view.quote_ceiling_ou == self.identity.original_budget_ou
                    && view.connection.sequence <= self.connection_sequence,
                "private status differs from immutable journal pins"
            );
        }
        Ok(())
    }
}

impl Journal {
    pub(crate) fn open_private(
        path: &Path,
        plan: &crate::private_runner::Plan,
        key: Arc<KeyPair>,
        mode: OpenMode,
    ) -> Result<Self> {
        plan.validate()?;
        ensure!(
            plan.binding.payer == Address::from_pubkey(&key.public.0),
            "private journal receipt identity differs"
        );
        Self::open_mode(
            path,
            plan.binding.clone(),
            plan.tariff.clone(),
            plan.quote_ceiling_ou,
            plan.prepaid_bytes.clone(),
            (
                key,
                false,
                Some(PrivateIdentity {
                    target: plan.target.clone(),
                    operator_generation: plan.operator_generation,
                }),
            ),
            mode,
        )
    }

    /// Persist counters before using the snapshot. Held bytes may change within
    /// a delivery slot; committed counters cannot equivocate or regress, even
    /// across reconnect. No observation increases the locally accepted cap.
    pub(crate) fn observe_private_status(&mut self, signed: &SignedShieldedStatus) -> Result<()> {
        self.ready()?;
        ensure!(
            self.state.identity.private.is_some(),
            "private status requires encrypted bookkeeping"
        );
        ensure!(
            signed.status.connection.sequence == self.state.connection_sequence
                && signed.status.connection.wireguard_key
                    == crate::wireguard::public_key(&self.key),
            "private status is not for the current local connection"
        );
        let mut next = self.state.clone();
        next.private_status = Some(signed.clone());
        next.validate_private()?;
        if let Some(previous) = &self.state.private_status {
            let prior = &previous.status;
            let current = &signed.status;
            ensure!(
                current.connection.sequence >= prior.connection.sequence
                    && current.service_sequence >= prior.service_sequence
                    && current.canonical_ms >= prior.canonical_ms
                    && current.paid_ou >= prior.paid_ou
                    && current
                        .purchased_totals
                        .iter()
                        .zip(&prior.purchased_totals)
                        .all(|(a, b)| a >= b)
                    && current
                        .committed_totals
                        .iter()
                        .zip(&prior.committed_totals)
                        .all(|(a, b)| a >= b),
                "private service accounting regressed"
            );
            if current.service_sequence == prior.service_sequence {
                ensure!(
                    current.committed_totals == prior.committed_totals,
                    "private service delivery slot changed"
                );
            }
            if current.connection.sequence == prior.connection.sequence {
                ensure!(
                    current.connection == prior.connection
                        && current.server_wireguard_key == prior.server_wireguard_key,
                    "private connection changed within its watermark"
                );
            }
        }
        self.commit(next)
            .context("private service snapshot persistence failed")
    }
}

#[cfg(test)]
pub(crate) mod tests;
