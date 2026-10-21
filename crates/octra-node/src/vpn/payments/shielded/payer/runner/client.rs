//! Durable bridge between finite native consent and a private client journal.
//! Preparing is offline. Only canonical native credit permits admission.
use super::{Purchase, Services, State};
use anyhow::{ensure, Context, Result};
use octravpn_client::{
    AcceptedPrivatePlan, JournalMode, MultiRoutePins, PendingPrivateClient, PreparedPrivateClient,
    PrivatePaymentClient, PrivatePaymentOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const PHASE: u8 = 13;

/// Immutable transport consent. Receipt keys come from the native purchase;
/// callers cannot substitute an identity or choose a fresh-journal fallback.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub plan: AcceptedPrivatePlan,
    pub journal: PathBuf,
    pub interface_name: String,
    pub hop: Option<Hop>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hop {
    pub pins: MultiRoutePins,
    pub position: usize,
    pub count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    version: u8,
    purchase: [u8; 32],
    transport: Transport,
}

pub struct Prepared {
    purchase: Purchase,
    phase: Phase,
    client: PendingPrivateClient,
    credited: bool,
    route: Option<Arc<super::route::Route>>,
    retained: Vec<super::super::reconnect::Permit>,
}

impl Purchase {
    /// Call open() first to obtain the authenticated, nonfinancial binding.
    /// A new client phase must precede the first quote. A recorded phase always
    /// resumes its original journal; missing state never creates a replacement.
    pub async fn prepare_client(&self, transport: Transport) -> Result<Prepared> {
        self.prepare_guarded(transport, None).await
    }
    pub(super) async fn prepare_guarded(
        &self,
        mut transport: Transport,
        route: Option<Arc<super::route::Route>>,
    ) -> Result<Prepared> {
        let _purchases = self.payer.0.purchases.lock().await;
        self.validate()?;
        if let Some(route) = &route {
            route.check().await?;
            route.accepts(self, &transport)?;
        } else {
            super::route::require_unowned(self).await?;
        }
        transport.journal = canonical_parent(&transport.journal)?;
        self.check_transport(&transport).await?;
        let phase = Phase {
            version: 1,
            purchase: self.id,
            transport,
        };
        let disk = &self.payer.0.disk;
        let tag = self.tag(PHASE, 0)?;
        // Check the encrypted record bound before creating any child state.
        disk.encode(PHASE, &tag, &phase)?;
        let _gate = self.payer.0.gate.lock().await;
        let mut tx = disk.begin().await?;
        let saved: Option<Phase> = disk.load(&mut tx, PHASE, &tag).await?;
        let embedded = self.client_binding(&mut tx).await?;
        tx.rollback().await?;
        let binding = digest(&phase)?;
        ensure!(
            embedded.is_none_or(|saved| saved == binding),
            "private client binding differs"
        );
        let mode = if let Some(saved) = saved {
            same(&saved, &phase)?;
            JournalMode::Resume
        } else {
            ensure!(
                embedded.is_none(),
                "private client phase missing; refusing recreation"
            );
            ensure!(
                self.reply(1).await?.is_none(),
                "new private client phase must precede payment quote"
            );
            JournalMode::Create
        };
        let options = PrivatePaymentOptions {
            plan: phase.transport.plan.clone(),
            journal: phase.transport.journal.clone(),
            receipt_key: Arc::new(self.receipt_identity()?),
            interface_name: phase.transport.interface_name.clone(),
            mode,
        };
        let client = match &phase.transport.hop {
            Some(hop) => {
                PendingPrivateClient::for_hop(options, hop.pins, hop.position, hop.count).await?
            }
            None => PendingPrivateClient::new(options).await?,
        };
        client.check().await?;
        if matches!(mode, JournalMode::Create) || embedded.is_none() {
            // Cancellation before this commit can leave an unadmitted orphan
            // directory. Exclusive Create then refuses it; no counters reset.
            let mut tx = disk.begin().await?;
            if matches!(mode, JournalMode::Create) {
                disk.insert(&mut tx, PHASE, &tag, &[0; 32], &phase).await?;
            }
            self.bind_client(&mut tx, binding).await?;
            disk.commit(tx).await?;
        }
        Ok(Prepared {
            purchase: self.clone(),
            phase,
            client,
            credited: false,
            route,
            retained: Vec::new(),
        })
    }

    async fn check_transport(&self, transport: &Transport) -> Result<()> {
        let binding = self.opened(
            &self
                .reply(0)
                .await?
                .context("private channel is not open")?,
        )?;
        let plan = &transport.plan;
        ensure!(
            plan.binding == binding
                && plan.target == self.terms.target
                && plan.operator_generation == self.terms.operator_generation
                && plan.quote_ceiling_ou == self.terms.ceiling_ou
                && plan.tariff.hash_hex()? == self.terms.manifest_hash
                && plan.prepaid_bytes == self.terms.prepaid(&plan.tariff)?,
            "private client differs from finite purchase consent"
        );
        let path = &transport.journal;
        ensure!(
            path.is_absolute()
                && path.components().all(|part| !matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )),
            "private client journal requires a normalized absolute path"
        );
        let book = self
            .payer
            .0
            .disk
            .path()
            .parent()
            .context("private book parent missing")?;
        ensure!(
            !path.starts_with(book) && !book.starts_with(path),
            "private client journal overlaps custody book"
        );
        Ok(())
    }
}

pub(super) fn canonical_parent(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && path.components().all(|part| !matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )),
        "private client journal requires a normalized absolute path"
    );
    Ok(std::fs::canonicalize(
        path.parent()
            .context("private client journal parent missing")?,
    )?
    .join(
        path.file_name()
            .context("private client journal name missing")?,
    ))
}

impl Prepared {
    async fn check(&self) -> Result<()> {
        self.purchase.validate()?;
        for permit in &self.retained {
            permit.check()?;
        }
        if let Some(route) = &self.route {
            route.check().await?;
        }
        self.client.check().await?;
        let _gate = self.purchase.payer.0.gate.lock().await;
        let disk = &self.purchase.payer.0.disk;
        let mut tx = disk.begin().await?;
        let saved: Phase = disk
            .load(&mut tx, PHASE, &self.purchase.tag(PHASE, 0)?)
            .await?
            .context("private client phase disappeared")?;
        ensure!(
            self.purchase.client_binding(&mut tx).await? == Some(digest(&self.phase)?),
            "private purchase lost its client binding"
        );
        tx.rollback().await?;
        same(&saved, &self.phase)
    }

    /// Reauthenticate an already recorded canonical payment without spending.
    /// Retained native finality and the current node lease must still verify.
    /// False means there is no recorded credit, never permission to buy again.
    pub async fn resume_credit(&mut self) -> Result<bool> {
        let _purchases = self.purchase.payer.0.purchases.lock().await;
        self.credited = false;
        self.retained.clear();
        self.check().await?;
        let Some(binding) = self.purchase.recorded_credit().await? else {
            return Ok(false);
        };
        ensure!(
            binding == self.phase.transport.plan.binding,
            "resumed private credit binding differs"
        );
        self.credited = true;
        Ok(true)
    }

    /// Entry-only recovery of already settled capacity. This grants no fresh
    /// node publication and cannot run a purchase while the node is suspended.
    pub(super) async fn resume_entry<A: crate::Host>(
        &mut self,
        node: &crate::Node<A>,
    ) -> Result<()> {
        let _purchases = self.purchase.payer.0.purchases.lock().await;
        self.credited = false;
        self.retained.clear();
        self.check().await?;
        self.route
            .as_ref()
            .context("retained entry has no route owner")?
            .require_armed_entry(&self.purchase)
            .await?;
        let (binding, permits) = self.purchase.recorded_entry(node).await?;
        ensure!(
            binding == self.phase.transport.plan.binding,
            "retained entry binding differs"
        );
        for permit in &permits {
            permit.check()?;
        }
        self.retained = permits;
        self.credited = true;
        Ok(())
    }

    /// Retains the same native request, note reservation, fee and nonce journal
    /// as Purchase::step. Client state must still exist before every attempt.
    pub async fn step<A: crate::Host>(&mut self, services: Services<'_, A>) -> Result<State> {
        let _purchases = self.purchase.payer.0.purchases.lock().await;
        self.credited = false;
        self.check().await?;
        let state = Box::pin(self.purchase.step_at(services)).await?;
        if let State::Credited { binding, .. } = &state {
            ensure!(
                *binding == self.phase.transport.plan.binding,
                "private paid binding differs from client phase"
            );
            self.credited = true;
        }
        Ok(state)
    }

    /// Resume requires a canonical step or retained-finality revalidation; a
    /// saved phase or operator reply alone cannot assert funding. Admission
    /// also checks the live private meter.
    pub async fn admit(self) -> Result<PreparedPrivateClient> {
        ensure!(
            self.credited,
            "private client requires canonical payment step"
        );
        self.check().await?;
        self.client.admit().await
    }

    pub async fn open(self) -> Result<PrivatePaymentClient> {
        Box::pin(self.admit().await?.open()).await
    }
}

pub(super) async fn require_unmanaged(purchase: &Purchase) -> Result<()> {
    let disk = &purchase.payer.0.disk;
    let mut tx = disk.begin().await?;
    let phase: Option<Phase> = disk.load(&mut tx, PHASE, &purchase.tag(PHASE, 0)?).await?;
    let embedded = purchase.client_binding(&mut tx).await?;
    tx.rollback().await?;
    ensure!(
        phase.is_none() && embedded.is_none(),
        "private purchase belongs to its prepared client; standalone scheduling refused"
    );
    Ok(())
}

fn digest(phase: &Phase) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"Octranet private native client phase v1\0");
    hash.update(serde_json::to_vec(phase)?);
    Ok(hash.finalize().into())
}

#[cfg(test)]
impl Purchase {
    pub(crate) async fn lose_client_phase_case(&self) {
        let _gate = self.payer.0.gate.lock().await;
        let disk = &self.payer.0.disk;
        let mut tx = disk.begin().await.unwrap();
        assert_eq!(
            sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=?")
                .bind(i64::from(PHASE))
                .bind(self.tag(PHASE, 0).unwrap().as_slice())
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        disk.commit(tx).await.unwrap();
    }
}

fn same(saved: &Phase, expected: &Phase) -> Result<()> {
    ensure!(
        serde_json::to_vec(saved)? == serde_json::to_vec(expected)?,
        "private client phase changes accepted transport"
    );
    Ok(())
}
