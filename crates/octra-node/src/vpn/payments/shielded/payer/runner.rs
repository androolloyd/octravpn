//! One finite private purchase, driven by canonical state. Every external
//! request and native signature is durable before transmission. Cancellation
//! retries the same identity; replies never authorize packet forwarding.
mod catalog;
pub mod client;
mod control;
pub mod route;
mod settlement;

use super::{native::FeePolicy, Payer};
use crate::vpn::payments::shielded::index::Index;
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::{
    payments::{PlanBinding, PrivateExchange, PrivateTarget},
    KeyPair,
};
use serde::{Deserialize, Serialize};

const JOB: u8 = 10;
const REPLY: u8 = 11;
const MAX_JOBS: i64 = 16_384;

/// Explicit local consent, supplied independently of the operator's reply.
/// Native transaction fees have a separate, lifetime-bounded relayer policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub target: PrivateTarget,
    pub offer: u64,
    pub operator_generation: u64,
    pub manifest_hash: String,
    pub ceiling_ou: u64,
    pub traffic_class: u8,
    pub bytes: u64,
    pub max_cost_ou: u64,
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub invoice_lifetime_ms: u64,
    pub relayer_public: [u8; 32],
    pub fees: FeePolicy,
    /// Further finite allowances on this same channel. Empty preserves the
    /// original sealed single-class representation and request identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional: Vec<Allowance>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub traffic_class: u8,
    pub bytes: u64,
    pub max_cost_ou: u64,
}

pub enum State {
    Syncing,
    Opened,
    Quoted,
    /// Staged or retransmitted, with no assertion of inclusion or funding.
    Submitted {
        hash: String,
    },
    /// One class is canonically paid; the complete accepted bundle is not yet
    /// ready for transport admission.
    ClassCredited {
        traffic_class: u8,
    },
    /// Canonically paid and acknowledged by the operator. Transport admission
    /// must still authenticate its own current, plan-bound funding guard.
    Credited {
        binding: PlanBinding,
        credit_id: [u8; 32],
        epoch: u64,
    },
}

#[derive(Clone)]
pub struct Purchase {
    payer: Payer,
    id: [u8; 32],
    terms: Terms,
}

/// Services belong to the same canonical node as the payer's accepted pool.
/// The transport implementation must provide authenticated encryption.
pub struct Services<'a, A: crate::Host> {
    pub index: &'a Index,
    pub submission: &'a crate::rpc::Submission<A>,
    pub control: &'a dyn PrivateExchange,
    pub relayer: &'a SigningKey,
    pub prover: &'a Prover,
}

impl Terms {
    pub fn classes(&self) -> impl Iterator<Item = Allowance> + '_ {
        std::iter::once(Allowance {
            traffic_class: self.traffic_class,
            bytes: self.bytes,
            max_cost_ou: self.max_cost_ou,
        })
        .chain(self.additional.iter().copied())
    }
    fn class(&self, slot: usize) -> Result<Allowance> {
        self.classes()
            .nth(slot)
            .context("private allowance slot differs")
    }
    pub fn prepaid(&self, tariff: &octravpn_core::payments::Tariff) -> Result<Vec<u64>> {
        self.validate()?;
        ensure!(
            tariff.hash_hex()? == self.manifest_hash
                && *tariff.operator()
                    == octravpn_core::Address::from_pubkey(&self.target.operator.0),
            "private tariff differs from accepted consent"
        );
        let mut bytes = vec![0; tariff.classes().len()];
        for class in self.classes() {
            ensure!(
                tariff.charge(class.traffic_class, class.bytes)? <= class.max_cost_ou,
                "private allowance exceeds accepted price"
            );
            *bytes
                .get_mut(usize::from(class.traffic_class))
                .context("private class missing from tariff")? = class.bytes;
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        self.fees.validate()?;
        self.target.pool.validate()?;
        octravpn_core::parse_native_address(self.target.directory.display())?;
        let hash = hex::decode(&self.manifest_hash)?;
        ensure!(
            self.target.chain_origin != [0; 32]
                && self.operator_generation > 0
                && hash.len() == 32
                && hex::encode(hash) == self.manifest_hash
                && self.ceiling_ou > 0
                && i64::try_from(self.ceiling_ou).is_ok()
                && self.max_cost_ou > 0
                && self.max_cost_ou <= self.ceiling_ou
                && self.bytes > 0
                && i64::try_from(self.bytes).is_ok()
                && usize::from(self.traffic_class) < octravpn_core::payments::MAX_CLASSES
                && self.expires_ms > self.valid_from_ms
                && self.expires_ms - self.valid_from_ms <= 86_400_000
                && (1..=86_400_000).contains(&self.invoice_lifetime_ms)
                && self.invoice_lifetime_ms <= self.expires_ms - self.valid_from_ms,
            "private purchase terms differ"
        );
        ensure!(
            !ed25519_dalek::VerifyingKey::from_bytes(&self.relayer_public)?.is_weak(),
            "weak private relayer key"
        );
        ensure!(
            self.additional.len() < octravpn_core::payments::MAX_CLASSES,
            "too many private allowance classes"
        );
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0_u64;
        for class in self.classes() {
            ensure!(
                usize::from(class.traffic_class) < octravpn_core::payments::MAX_CLASSES
                    && seen.insert(class.traffic_class)
                    && class.bytes > 0
                    && i64::try_from(class.bytes).is_ok()
                    && class.max_cost_ou > 0,
                "invalid or duplicate private allowance class"
            );
            total = total
                .checked_add(class.max_cost_ou)
                .context("private allowance cost overflow")?;
        }
        ensure!(
            total <= self.ceiling_ou,
            "private allowances exceed shared channel ceiling"
        );
        Ok(())
    }
}

impl Purchase {
    fn validate(&self) -> Result<()> {
        self.payer.0.disk.check()?;
        self.terms.validate()?;
        let source = &self.payer.1;
        ensure!(
            self.id != [0; 32] && matches_source(&self.terms.target, source),
            "private purchase source differs"
        );
        Ok(())
    }

    fn tag(&self, kind: u8, phase: u8) -> Result<[u8; 32]> {
        self.payer
            .0
            .disk
            .tag(kind, &[self.id.as_slice(), &[phase]].concat())
    }

    /// Local receipt identity for this purchase's authenticated connection.
    /// It is never derived from or submitted as the native relayer identity.
    pub fn receipt_identity(&self) -> Result<KeyPair> {
        self.validate()?;
        let key = self.payer.0.key.derive_bytes(
            b"private purchase receipt v1",
            &[self.payer.0.wallet.as_slice(), &self.id].concat(),
        )?;
        Ok(KeyPair::from_secret_bytes(&key))
    }

    /// Resolve the authenticated channel without quoting, proving, signing or
    /// submitting a payment. A route can persist its bound client journal before
    /// spending. None means the local canonical pool index is still syncing.
    pub async fn open(
        &self,
        index: &Index,
        control: &dyn PrivateExchange,
    ) -> Result<Option<PlanBinding>> {
        let _gate = self.payer.0.purchases.lock().await;
        self.validate()?;
        route::require_unowned(self).await?;
        client::require_unmanaged(self).await?;
        ensure!(
            index.belongs_to(&self.payer.1),
            "private purchase index belongs elsewhere"
        );
        if !index.sync(128).await?.complete {
            return Ok(None);
        }
        let view = index.view().await?;
        let (_, now) = self.payer.current(view.index()).await?;
        let (binding, _) = self.open_at(now, control).await?;
        view.with_current(|_| Ok(()))?;
        Ok(Some(binding))
    }

    async fn open_at(
        &self,
        now: u64,
        control: &dyn PrivateExchange,
    ) -> Result<(PlanBinding, bool)> {
        if let Some(saved) = self.reply(0).await? {
            return Ok((self.opened(&saved)?, false));
        }
        self.check_offer().await?;
        let request = self.open_request().await?;
        request.request.check_time(now)?;
        let reply = self.exchange(0, &request, control).await?;
        Ok((self.opened(&reply)?, true))
    }

    /// Perform at most one control exchange or native submission. Call again
    /// as canonical heads arrive. No consensus, wall-clock timer or operator
    /// acknowledgement can manufacture the required finality here.
    pub async fn step<A: crate::Host>(&self, services: Services<'_, A>) -> Result<State> {
        let _gate = self.payer.0.purchases.lock().await;
        self.validate()?;
        route::require_unowned(self).await?;
        client::require_unmanaged(self).await?;
        Box::pin(self.step_at(services)).await
    }

    // The caller owns the shared purchase mutex. A client-owned phase may only
    // reach this path after checking its held encrypted child journal.
    async fn step_at<A: crate::Host>(&self, services: Services<'_, A>) -> Result<State> {
        ensure!(
            services.relayer.verifying_key().to_bytes() == self.terms.relayer_public,
            "private purchase relayer differs"
        );
        ensure!(
            services.index.belongs_to(&self.payer.1),
            "private purchase index belongs elsewhere"
        );
        if !services.index.sync(128).await?.complete {
            return Ok(State::Syncing);
        }
        let view = services.index.view().await?;
        let (_, now) = self.payer.current(view.index()).await?;
        let (binding, created) = self.open_at(now, services.control).await?;
        if created {
            return Ok(State::Opened);
        }
        for slot in 0..=self.terms.additional.len() {
            let quote_phase = self.quote_phase(slot)?;
            if slot < self.terms.additional.len()
                && self.reply(self.receipt_phase(slot)?).await?.is_some()
            {
                ensure!(
                    self.recorded_class_credit(slot).await? == Some(binding.clone()),
                    "earlier private class lost its canonical payment"
                );
                continue;
            }
            let Some(quoted) = self.reply(quote_phase).await? else {
                self.check_offer().await?;
                ensure!(
                    now.checked_add(self.terms.invoice_lifetime_ms)
                        .is_some_and(|expires| expires <= self.terms.expires_ms),
                    "private quote would outlive accepted window"
                );
                let request = self.quote_request(binding.plan, slot).await?;
                request.request.check_time(now)?;
                if let Err(error) = self.exchange(quote_phase, &request, services.control).await {
                    if error
                        .downcast_ref::<octra_private_payments_experimental::invoice::NotYetValid>()
                        .is_some()
                    {
                        // Retry the original durable request after catch-up.
                        // Nothing is reserved, proved or signed for this quote.
                        return Ok(State::Syncing);
                    }
                    return Err(error);
                }
                return Ok(State::Quoted);
            };
            let invoice = self.quoted(&quoted, binding.plan, slot)?;
            let state = Box::pin(self.settle(&services, &invoice, binding, slot)).await?;
            return Ok(
                if matches!(state, State::Credited { .. }) && slot < self.terms.additional.len() {
                    State::ClassCredited {
                        traffic_class: self.terms.class(slot)?.traffic_class,
                    }
                } else {
                    state
                },
            );
        }
        anyhow::bail!("private allowance bundle has no final class")
    }
}

pub(super) fn matches_source(target: &PrivateTarget, source: &super::Pool) -> bool {
    target.chain_origin == source.origin
        && target.pool.domain == hex::encode(source.domain.digest())
        && target.pool.program.display() == source.circle()
        && target.directory.display() == source.directory.config.program
        && octravpn_core::Address::from_pubkey(&target.operator.0) == source.directory.operator
}
