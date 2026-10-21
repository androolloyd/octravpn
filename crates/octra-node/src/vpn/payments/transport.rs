//! The packet capability is bound to the same revocable publication as Plan.
use super::{Payments, Plan};
use anyhow::{ensure, Result};
use async_trait::async_trait;
use octra_node_runtime::canonical::Head;
use octravpn_core::payments::PlanBinding;
use octravpn_node::payments::{Authority, Funds, Grant, Guard};
use std::sync::Arc;

struct Publication {
    plan: Plan,
    shared: Arc<crate::Shared>,
    head: Head,
}
impl Guard for Publication {
    fn live(&self) -> bool {
        self.plan.live()
    }
    fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let lease = self
            .plan
            .lease
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("payment lease missing"))?;
        self.shared.with_current(&self.head, &lease.revocation, || {
            ensure!(self.plan.admissible(), "payment plan expired");
            action()
        })
    }
}

#[async_trait]
impl Authority for Payments {
    fn updates(&self) -> Option<tokio::sync::watch::Receiver<()>> {
        Some(self.shared.1.subscribe())
    }
    async fn plan(&self, binding: &PlanBinding) -> Result<Grant> {
        let plan = Self::plan(self, binding.plan).await?;
        self.transport_grant(plan, binding)
    }
    async fn claim_plan(&self, binding: &PlanBinding) -> Result<Grant> {
        let plan = Self::claim_plan(self, binding.plan).await?;
        self.transport_grant(plan, binding)
    }
}

impl Payments {
    fn transport_grant(&self, plan: Plan, binding: &PlanBinding) -> Result<Grant> {
        let actual = PlanBinding {
            deployment: plan.deployment.clone(),
            payer: plan.payer.clone(),
            generation: plan.generation,
            plan: plan.plan,
            offer: plan.offer,
            manifest_hash: plan.manifest_hash.clone(),
        };
        ensure!(&actual == binding, "payment transport plan differs");
        let serving = self.shared.current()?;
        ensure!(plan.live(), "payment publication changed");
        Ok(Grant {
            binding: actual,
            receipt_key: plan.receipt_key,
            operator_generation: plan.operator_generation,
            tariff: plan.tariff.clone(),
            funds: Funds::Channel {
                original_budget_ou: plan.original_budget_ou,
                remaining_ou: plan.remaining_ou,
                claim_deadline_ms: plan.claim_deadline_ms,
            },
            redeemed_totals: plan.redeemed_bytes.clone(),
            canonical_ms: plan.canonical_ms,
            // Eligibility is immutable state; lease revocation is separate.
            // Publication races suspend connections rather than retiring them.
            admissible: plan.eligible,
            guard: Arc::new(Publication {
                plan,
                shared: self.shared.clone(),
                head: serving.committed.head().clone(),
            }),
        })
    }
}
