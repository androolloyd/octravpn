//! Explicit bounded preparation before snapshot/pruning. Witnesses authenticate
//! history; none of these operations writes a customer credit or counter.
use super::{Credit, Wallet, CREDIT, MAX_CREDITS};
use crate::vpn::payments::shielded::history::{self, Progress, Proof};
use anyhow::{ensure, Result};
use sqlx::Row;
use std::collections::BTreeSet;
const KIND: u8 = 6;
impl Wallet {
    #[cfg(test)]
    pub(crate) async fn remove_recovery_chunk(&self, epoch: u64) {
        let key = self.0.disk.tag(KIND, &epoch.to_be_bytes()).unwrap();
        sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=(SELECT tag FROM wallet_records WHERE kind=? AND bucket=? LIMIT 1)")
            .bind(i64::from(KIND+1)).bind(i64::from(KIND+1)).bind(key.as_slice()).execute(&self.0.disk.pool).await.unwrap();
    }
    /// Public historical data; its association with this wallet stays private.
    pub async fn export_recovery(&self, epoch: u64) -> Result<Vec<u8>> {
        self.recovery_proof(epoch)
            .await?
            .ok_or_else(|| anyhow::anyhow!("portable history missing"))?
            .encode()
    }
    pub(super) async fn recovery_proof(&self, epoch: u64) -> Result<Option<Proof>> {
        history::storage::load(&self.0.disk, KIND, epoch).await
    }
    pub async fn import_recovery(&self, proof: &Proof) -> Result<()> {
        proof.verify(&self.0.source).await?;
        let mut tx = self.0.disk.begin().await?;
        history::storage::save(&self.0.disk, &mut tx, KIND, proof).await?;
        self.0.disk.commit(tx).await?;
        self.0.verified.lock().await.clear();
        Ok(())
    }
    pub async fn retain_epoch(&self, epoch: u64, anchor: u64) -> Result<()> {
        let prior = self.recovery_proof(epoch).await?;
        let proof = Proof::capture(&self.0.source, epoch, anchor, prior).await?;
        self.import_recovery(&proof).await
    }
    /// Use the exact epoch selected for checkpoint export. Repeat bounded calls
    /// until remaining is zero, then retain that checkpoint with the journals.
    pub async fn prepare_recovery(&self, anchor: u64, maximum: usize) -> Result<Progress> {
        ensure!(
            (1..=8).contains(&maximum),
            "portable recovery batch exceeds limit"
        );
        self.0.disk.check()?;
        let rows = sqlx::query("SELECT tag,value FROM wallet_records WHERE kind=? LIMIT ?")
            .bind(i64::from(CREDIT))
            .bind(i64::try_from(MAX_CREDITS + 1)?)
            .fetch_all(&self.0.disk.pool)
            .await?;
        ensure!(
            rows.len() <= MAX_CREDITS,
            "portable credit scan exceeds limit"
        );
        let mut epochs = BTreeSet::new();
        for row in rows {
            let tag: Vec<u8> = row.try_get("tag")?;
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("portable credit tag differs"))?;
            let value: Vec<u8> = row.try_get("value")?;
            let credit: Credit = self.0.disk.decode(CREDIT, &tag, &value)?;
            ensure!(
                self.0.disk.tag(CREDIT, &credit.credit_id)? == tag,
                "portable credit identity differs"
            );
            if credit.proof.epoch <= anchor {
                epochs.insert(credit.proof.epoch);
            }
        }
        let mut prepared = 0;
        let mut remaining = 0;
        for epoch in epochs {
            let prior = self.recovery_proof(epoch).await?;
            if let Some(proof) = &prior {
                ensure!(
                    proof.anchor() <= anchor,
                    "portable history anchor regressed"
                );
                if proof.anchor() == anchor {
                    proof.verify(&self.0.source).await?;
                    continue;
                }
            }
            if prepared == maximum {
                remaining += 1;
                continue;
            }
            let proof = Proof::capture(&self.0.source, epoch, anchor, prior).await?;
            self.import_recovery(&proof).await?;
            prepared += 1;
        }
        Ok(Progress {
            prepared,
            remaining,
            anchor,
        })
    }
}
