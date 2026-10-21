//! Only the canonical host mints the final packet guard. Durable private
//! purchases are independent of the operator's current service eligibility.
use super::Wallet;
use crate::{vpn::payments::PLAN_MAX_AGE, SnapshotLease};
use anyhow::{ensure, Result};
use async_trait::async_trait;
use octravpn_core::{
    payments::{PlanBinding, SignedUsage},
    Address, PublicKey,
};
use octravpn_node::payments::{Authority, Config, Funds, Grant, Guard, Mode, Service, Settlement};
use std::sync::Arc;

struct Publication {
    lease: SnapshotLease,
    eligible: bool,
}
impl Guard for Publication {
    fn live(&self) -> bool {
        self.lease.is_live(PLAN_MAX_AGE)
    }
    fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.lease.with_current(PLAN_MAX_AGE, || {
            ensure!(self.eligible, "private operator is no longer eligible");
            action()
        })
    }
}

impl Wallet {
    pub(crate) fn belongs_to(&self, shared: &Arc<crate::Shared>) -> bool {
        Arc::ptr_eq(&self.0.source.directory.shared, shared)
    }
    /// Reuses the ordinary WireGuard, per-class metering and route lifecycle.
    /// Only shielded status/ack routes are mounted; quote funding itself must
    /// already have passed receive(), not an HTTP success flag.
    pub async fn bind_service(&self, config: Config) -> Result<Service> {
        ensure!(
            Address::from_pubkey(&config.operator_key.public.0) == self.0.source.directory.operator,
            "private service operator key differs"
        );
        let authority = Arc::new(self.clone());
        Service::bind_shielded(config, authority.clone(), authority, self.meter_key()?).await
    }
}

#[async_trait]
impl Authority for Wallet {
    fn mode(&self) -> Mode {
        Mode::Shielded
    }
    fn updates(&self) -> Option<tokio::sync::watch::Receiver<()>> {
        Some(self.0.source.directory.shared.1.subscribe())
    }
    async fn plan(&self, binding: &PlanBinding) -> Result<Grant> {
        let info = self.channel(binding.plan).await?;
        ensure!(
            &info.binding == binding,
            "private transport channel differs"
        );
        let source = &self.0.source;
        let lease = SnapshotLease::capture(source.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        let committed = lease.committed();
        source.directory.check_value_effects(committed).await?;
        let now = source.directory.canonical_time(committed).await?;
        let pool = source.state(committed.state())?;
        info.floor
            .check(committed.head().cursor.epoch.0, pool.count, now)?;
        let offer = source.directory.offer_fields(
            &source.directory.directory(committed.state())?,
            binding.offer,
            now,
            Some(info.tariff.clone()),
        )?;
        ensure!(
            offer.data.operator_generation == info.operator_generation,
            "private channel operator generation differs"
        );
        let eligible = offer.liquid && offer.provider_available && offer.quote_started;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(Grant {
            binding: info.binding,
            receipt_key: PublicKey(info.receipt_key),
            operator_generation: info.operator_generation,
            tariff: info.tariff,
            funds: Funds::Shielded {
                quote_ceiling_ou: info.budget_ou,
                paid_ou: info.paid_ou,
            },
            redeemed_totals: info.purchased,
            canonical_ms: now,
            admissible: eligible,
            guard: Arc::new(Publication { lease, eligible }),
        })
    }
}

#[async_trait]
impl Settlement for Wallet {
    /// This acknowledgement never buys bytes or submits a public purchase.
    /// Only the wallet's previously confirmed private credits can cover it.
    async fn confirm(&self, usage: SignedUsage) -> Result<()> {
        usage.verify()?;
        let grant = self.claim_plan(&usage.usage.binding()).await?;
        ensure!(
            grant.receipt_key == usage.receipt_key,
            "private purchase receipt key differs"
        );
        ensure!(
            grant
                .redeemed_totals
                .get(usize::from(usage.usage.traffic_class))
                .is_some_and(|paid| *paid >= usage.usage.total_bytes),
            "private purchase does not cover authorization"
        );
        ensure!(grant.guard.live(), "private payment publication changed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::FundingFloor;
    #[test]
    fn a_cached_credit_floor_requires_a_current_view_covering_all_three_coordinates() {
        let floor = FundingFloor {
            epoch: 20,
            count: 50,
            millis: 1000,
        };
        assert!(floor.check(20, 50, 1000).is_ok());
        assert!(floor.check(21, 51, 1001).is_ok());
        assert!(floor.check(19, 50, 1000).is_err());
        assert!(floor.check(20, 49, 1000).is_err());
        assert!(floor.check(20, 50, 999).is_err());
    }
}
