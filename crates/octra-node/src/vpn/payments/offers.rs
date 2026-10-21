//! Common directory projection for public plans and private purchase quotes.
//! Reading a bonded offer grants neither custody nor packet capacity.
use super::{check_application, digest, Application, Fields, Payments, PLAN_MAX_AGE};
use crate::SnapshotLease;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::transaction::decode_base64;
use octra_node_runtime::{
    account_store,
    state_batch::{Snapshot, StateBatch},
};
use octravpn_core::{
    payments::{Deployment, Tariff},
    Address, PublicKey,
};

#[derive(Clone, Debug)]
pub struct OfferData {
    pub application: Application,
    pub deployment: Deployment,
    pub offer: u64,
    pub lineage: u64,
    pub operator: Address,
    /// Only the current bonded generation has an authenticated signing key.
    pub receipt_key: Option<PublicKey>,
    pub operator_generation: u64,
    pub operator_stopped_ms: u64,
    pub operator_stake_ou: u64,
    pub minimum_stake_ou: u64,
    pub offer_start_ms: u64,
    pub offer_end_ms: u64,
    pub manifest_hash: String,
    pub tariff: Tariff,
    pub canonical_ms: u64,
}

pub(super) struct Projection {
    pub data: OfferData,
    pub liquid: bool,
    pub provider_available: bool,
    pub quote_started: bool,
    pub purchase_open: bool,
}

/// Only the node's current canonical publication can mint this capability.
/// Private consumers must verify their pool receipt against publication(),
/// then guard the final nonblocking handoff with that same lease.
pub struct Offer {
    state: Projection,
    lease: SnapshotLease,
}
impl std::ops::Deref for Offer {
    type Target = OfferData;
    fn deref(&self) -> &Self::Target {
        &self.state.data
    }
}
impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offer")
            .field("offer", &self.offer)
            .field("purchasable", &self.purchasable())
            .finish_non_exhaustive()
    }
}
impl Offer {
    /// Already purchased capacity may outlive a retired rate. Bond validity is
    /// distinct from the new-purchase window and never grants bytes by itself.
    pub fn bonded(&self) -> bool {
        self.state.liquid && self.state.provider_available && self.lease.is_live(PLAN_MAX_AGE)
    }
    pub fn purchasable(&self) -> bool {
        self.bonded() && self.state.purchase_open
    }
    pub fn publication(&self) -> &SnapshotLease {
        &self.lease
    }

    /// The closure must perform no awaits, proof work, journal or blocking IO.
    pub fn with_current<T>(&self, action: impl FnOnce(&OfferData) -> Result<T>) -> Result<T> {
        self.lease.with_current(PLAN_MAX_AGE, || {
            ensure!(
                self.state.liquid && self.state.provider_available && self.state.purchase_open,
                "Octranet offer is not purchasable"
            );
            action(&self.state.data)
        })
    }
}

impl Payments {
    /// Read an offer without requiring or inventing a public payer plan.
    pub async fn offer(&self, offer: u64) -> Result<Offer> {
        let lease = SnapshotLease::capture(self.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        let committed = lease.committed();
        self.check_value_effects(committed).await?;
        let now = self.canonical_time(committed).await?;
        let state = self.read_offer(committed.state(), offer, now)?;
        self.visible_tariff(committed, &state.data.manifest_hash, &state.data.tariff)
            .await?;
        self.retain_tariff(offer, state.data.tariff.clone()).await?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(Offer { state, lease })
    }

    pub(super) fn directory<'a>(&'a self, snapshot: &'a Snapshot) -> Result<Fields<'a>> {
        check_application(
            self.config.application,
            snapshot,
            &self.config.program,
            &self.config.code_hash,
            Some(self.config.factory.as_bytes()),
        )?;
        check_application(
            self.config.application,
            snapshot,
            &self.config.factory,
            &self.config.factory_code_hash,
            None,
        )?;
        let state = Fields::new(snapshot, &self.config);
        if self.config.application == Application::Circle {
            ensure!(
                state.uint(b"circle_initialized", &[])? == 1,
                "Octranet Circle is not initialized"
            );
        }
        ensure!(
            state.text(b"domain", &[])? == self.config.domain,
            "Octranet deployment domain differs"
        );
        Ok(state)
    }

    pub(super) fn read_offer(
        &self,
        snapshot: &Snapshot,
        offer: u64,
        now: u64,
    ) -> Result<Projection> {
        self.offer_fields(&self.directory(snapshot)?, offer, now, None)
    }

    pub(super) fn offer_fields(
        &self,
        state: &Fields<'_>,
        offer: u64,
        now: u64,
        retained: Option<Tariff>,
    ) -> Result<Projection> {
        let count = state.uint(b"offer_count", &[])?;
        ensure!(offer < count, "Octranet offer differs");
        let offer_key = offer.to_string();
        let series = state.uint(b"offer_series", &[&offer_key])?;
        let series_key = series.to_string();
        ensure!(
            series == self.config.offer
                && series < count
                && state.uint(b"offer_series", &[&series_key])? == series,
            "Octranet offer lineage differs"
        );
        let operator = state.text(b"offer_owner", &[&offer_key])?;
        ensure!(
            operator == self.operator.display(),
            "Octranet offer operator differs"
        );
        ensure!(
            state.uint(b"offer_sealed", &[&offer_key])? == 1,
            "Octranet offer not sealed"
        );
        let manifest = state.text(b"offer_manifest", &[&offer_key])?;
        digest(&manifest)?;
        let tariff = if let Some(tariff) = retained {
            ensure!(
                tariff.hash_hex()? == manifest,
                "Octranet retained tariff hash differs"
            );
            tariff
        } else {
            self.tariff(state.snapshot, &manifest)?
        };
        ensure!(
            tariff.operator() == &self.operator,
            "Octranet tariff operator differs"
        );
        ensure!(
            state.uint(b"offer_classes", &[&offer_key])? == tariff.classes().len() as u64,
            "Octranet class count differs"
        );
        for (class, terms) in tariff.classes().iter().enumerate() {
            ensure!(
                state.uint(b"offer_rate", &[&offer_key, &class.to_string()])?
                    == terms.rate_ou_per_mib,
                "Octranet class rate differs"
            );
        }
        let minimum = state.uint(b"min_operator_stake", &[])?;
        let locked = state.uint(b"locked_value", &[])?;
        let cap = state.uint(b"max_locked_value", &[])?;
        ensure!(
            minimum >= 100_000_000 && cap > minimum && locked <= cap,
            "Octranet custody accounting differs"
        );
        let liquid = account_store::load(
            &StateBatch::from_snapshot(state.snapshot.clone()),
            self.config.program.as_bytes(),
        )?
        .is_some_and(|a| a.balance >= locked.into());
        let generation = state.uint(b"offer_generation", &[&offer_key])?;
        ensure!(
            state.text(b"offer_owner", &[&series_key])? == operator
                && state.uint(b"offer_generation", &[&series_key])? == generation,
            "Octranet offer lineage operator differs"
        );
        let current = state.uint(b"operator_generation", &[&operator])?;
        let stake = state.uint(b"operator_stake", &[&operator])?;
        let receipt_key = if generation == current && stake > 0 {
            let text = state.text(b"operator_receipt_key", &[&operator])?;
            let raw = decode_base64(text.as_bytes())?;
            let key: [u8; 32] = raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("Octranet operator receipt key size differs"))?;
            ensure!(
                STANDARD.encode(key) == text && Address::from_pubkey(&key) == self.operator,
                "Octranet bonded receipt key differs from operator wallet"
            );
            Some(PublicKey(key))
        } else {
            None
        };
        let stopped = state.uint(b"operator_stopped", &[&operator, &generation.to_string()])?;
        ensure!(
            stopped == 0 || stopped <= now,
            "Octranet operator stop clock differs"
        );
        let start = state.uint(b"offer_start_ms", &[&offer_key])?;
        let end = state.uint(b"offer_end_ms", &[&offer_key])?;
        let cancelled = state.uint(b"offer_cancelled", &[&offer_key])?;
        ensure!(
            start > 0 && (end == 0 || end > start) && cancelled <= 1,
            "Octranet offer quote clock differs"
        );
        let started = now >= start && cancelled == 0;
        Ok(Projection {
            data: OfferData {
                application: self.config.application,
                deployment: self.deployment.clone(),
                offer,
                lineage: series,
                operator: self.operator.clone(),
                receipt_key,
                operator_generation: generation,
                operator_stopped_ms: stopped,
                operator_stake_ou: stake,
                minimum_stake_ou: minimum,
                offer_start_ms: start,
                offer_end_ms: end,
                manifest_hash: manifest,
                tariff,
                canonical_ms: now,
            },
            liquid,
            provider_available: generation > 0
                && generation == current
                && stopped == 0
                && state.uint(b"operator_unlock", &[&operator])? == 0
                && stake >= minimum,
            quote_started: started,
            purchase_open: started && (end == 0 || now < end),
        })
    }
}
