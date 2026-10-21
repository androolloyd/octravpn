use super::{same, Owner, Purchase, Route, Saved, INTENT, OWNER};
use anyhow::{ensure, Context, Result};

impl Route {
    pub(super) async fn network_state(
        &self,
        network: Option<&octravpn_client::PrivateRouteNetwork>,
    ) -> Result<()> {
        self.check().await?;
        if let Some(network) = network {
            network.validate(&self.profiles())?;
        }
        let _gate = self.root.0.gate.lock().await;
        let disk = &self.root.0.disk;
        let mut tx = disk.begin().await?;
        let mut saved: Saved = disk
            .load(&mut tx, INTENT, &self.tag()?)
            .await?
            .context("route intent disappeared")?;
        same(&saved.consent, &self.consent)?;
        ensure!(saved.ready, "route initialization incomplete");
        saved.network_armed = network.is_some();
        saved.network = network.cloned();
        disk.replace(&mut tx, INTENT, &self.tag()?, &saved).await?;
        disk.commit(tx).await
    }
    pub(super) async fn require_fresh_jobs(&self) -> Result<()> {
        for purchase in &self.purchases {
            let _purchases = purchase.payer.0.purchases.lock().await;
            let disk = &purchase.payer.0.disk;
            let mut tx = disk.begin().await?;
            let job: Option<serde_json::Value> = disk
                .load(
                    &mut tx,
                    super::super::JOB,
                    &purchase.tag(super::super::JOB, 0)?,
                )
                .await?;
            let owner: Option<Owner> = disk.load(&mut tx, OWNER, &purchase.tag(OWNER, 0)?).await?;
            ensure!(
                job.is_none() && owner.is_none(),
                "new route requires fresh purchase identities"
            );
            tx.rollback().await?;
        }
        Ok(())
    }
    pub(super) fn tag(&self) -> Result<[u8; 32]> {
        self.root.0.disk.tag(INTENT, &self.consent.id)
    }
    pub(super) async fn initialize(&self, resume: bool) -> Result<bool> {
        let _gate = self.root.0.gate.lock().await;
        let disk = &self.root.0.disk;
        disk.check()?;
        let mut tx = disk.begin().await?;
        let saved: Option<Saved> = disk.load(&mut tx, INTENT, &self.tag()?).await?;
        if resume {
            let saved = saved.context("private route intent missing; refusing recreation")?;
            same(&saved.consent, &self.consent)?;
            tx.rollback().await?;
            return Ok(saved.ready);
        }
        ensure!(
            saved.is_none(),
            "private route intent already exists; resume it"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(INTENT))
            .fetch_one(&mut *tx)
            .await?;
        ensure!(count < 4096, "private route intent capacity exhausted");
        disk.insert(
            &mut tx,
            INTENT,
            &self.tag()?,
            &[0; 32],
            &Saved {
                consent: super::Consent {
                    version: self.consent.version,
                    id: self.consent.id,
                    hops: self.consent.hops.clone(),
                },
                ready: false,
                network_armed: false,
                network: None,
            },
        )
        .await?;
        disk.commit(tx).await?;
        Ok(false)
    }
    pub(super) async fn load(&self) -> Result<Saved> {
        let disk = &self.root.0.disk;
        disk.check()?;
        let mut tx = disk.begin().await?;
        let saved = disk
            .load(&mut tx, INTENT, &self.tag()?)
            .await?
            .context("private route intent disappeared")?;
        tx.rollback().await?;
        Ok(saved)
    }
    pub(super) async fn mark_ready(&self) -> Result<()> {
        let _gate = self.root.0.gate.lock().await;
        let disk = &self.root.0.disk;
        let mut tx = disk.begin().await?;
        let mut saved: Saved = disk
            .load(&mut tx, INTENT, &self.tag()?)
            .await?
            .context("private route intent disappeared")?;
        same(&saved.consent, &self.consent)?;
        saved.ready = true;
        disk.replace(&mut tx, INTENT, &self.tag()?, &saved).await?;
        disk.commit(tx).await
    }
    pub(super) async fn claim(
        &self,
        purchase: &Purchase,
        position: usize,
        ready: bool,
        resume: bool,
    ) -> Result<()> {
        let _purchases = purchase.payer.0.purchases.lock().await;
        purchase.validate()?;
        if !ready {
            ensure!(
                purchase
                    .payer
                    .recorded_request(purchase.request_id(0)?, purchase.receipt_identity()?.public)
                    .await?
                    .is_none(),
                "partially initialized route already contacted an operator"
            );
        }
        let _gate = purchase.payer.0.gate.lock().await;
        let disk = &purchase.payer.0.disk;
        let mut tx = disk.begin().await?;
        let tag = purchase.tag(OWNER, 0)?;
        let saved: Option<Owner> = disk.load(&mut tx, OWNER, &tag).await?;
        let job: Option<serde_json::Value> = disk
            .load(
                &mut tx,
                super::super::JOB,
                &purchase.tag(super::super::JOB, 0)?,
            )
            .await?;
        if let Some(saved) = saved {
            ensure!(resume, "new route cannot adopt previous ownership");
            ensure!(
                job.is_some(),
                "route purchase disappeared; refusing recreation"
            );
            same(&saved, &self.owner(position))?;
            ensure!(
                purchase.check_stored(&mut tx).await? == Some(self.owner(position)),
                "route purchase embedded ownership differs"
            );
            tx.rollback().await?;
        } else {
            ensure!(
                !ready && job.is_none(),
                "route ownership missing or job already belongs to standalone consent"
            );
            ensure!(
                purchase
                    .store_owned(&mut tx, Some(&self.owner(position)))
                    .await?,
                "new route job was not created"
            );
            disk.insert(&mut tx, OWNER, &tag, &[0; 32], &self.owner(position))
                .await?;
            disk.commit(tx).await?;
        }
        Ok(())
    }
}
