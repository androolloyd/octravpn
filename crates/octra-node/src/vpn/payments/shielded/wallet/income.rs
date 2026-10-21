//! Exclusive local custody assignment. This moves no on-chain funds and never
//! changes a customer's already purchased bytes. Spend keys stay in this wallet.
use super::{native, Credit, Wallet, CREDIT};
use anyhow::{ensure, Context, Result};
use futures::TryStreamExt;
use octra_private_payments_experimental::{
    native_stealth,
    pool::{self, call::Call, envelope, Membership, Note, PoolIndex, SpendKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use zeroize::Zeroizing;
const ASSIGNMENT: u8 = 5;
const MAX_INCOME: usize = 16_384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    payer: [u8; 32],
    credit: [u8; 32],
}
pub(in crate::vpn::payments::shielded) struct Material {
    pub(in crate::vpn::payments::shielded) slot: u64,
    pub(in crate::vpn::payments::shielded) epoch: u64,
    pub(in crate::vpn::payments::shielded) commitment: [u8; 32],
    pub(in crate::vpn::payments::shielded) membership: Membership,
    pub(in crate::vpn::payments::shielded) call: Call,
    pub(in crate::vpn::payments::shielded) relayer: [u8; 47],
}
impl Wallet {
    pub(in crate::vpn::payments::shielded) fn income_pool(&self) -> &std::sync::Arc<super::Pool> {
        &self.0.source
    }
    pub(in crate::vpn::payments::shielded) fn income_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"Octranet operator income v1\0");
        hash.update(self.0.wallet_id);
        hash.update(self.0.source.origin);
        hash.update(self.0.source.address);
        hash.update(self.0.source.code_hash.as_bytes());
        hash.finalize().into()
    }
    /// Local unlocked-wallet metadata only. These IDs authorize no spend.
    pub async fn income_ids(&self) -> Result<Vec<[u8; 32]>> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let mut rows = sqlx::query("SELECT tag,value FROM wallet_records WHERE kind=? LIMIT ?")
            .bind(i64::from(CREDIT))
            .bind(i64::try_from(MAX_INCOME + 1)?)
            .fetch(&mut *tx);
        let mut ids = Vec::new();
        while let Some(row) = rows.try_next().await? {
            ensure!(
                ids.len() < MAX_INCOME,
                "operator income index exceeds bound"
            );
            let tag: Vec<u8> = row.try_get("tag")?;
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("income tag size differs"))?;
            let raw: Vec<u8> = row.try_get("value")?;
            let credit: Credit = self.0.disk.decode(CREDIT, &tag, &raw)?;
            ensure!(
                tag == self.0.disk.tag(CREDIT, &credit.credit_id)?,
                "operator income identity differs"
            );
            ids.push(credit.credit_id);
        }
        drop(rows);
        tx.rollback().await?;
        Ok(ids)
    }
    pub(in crate::vpn::payments::shielded) async fn owned_income(
        &self,
        id: [u8; 32],
        index: &PoolIndex,
    ) -> Result<(Material, Note, SpendKey)> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let credit: Credit = self
            .0
            .disk
            .load(&mut tx, CREDIT, &self.0.disk.tag(CREDIT, &id)?)
            .await?
            .context("operator income credit missing")?;
        tx.rollback().await?;
        ensure!(
            credit.credit_id == id && self.0.source.credit_id(credit.proof.commitment) == id,
            "operator income commitment identity differs"
        );
        let membership = credit.proof.membership()?;
        ensure!(
            credit.proof.epoch > 0,
            "operator income has no creation epoch"
        );
        let lease = self
            .0
            .source
            .current_member(index, credit.proof.index, credit.proof.commitment)
            .await?;
        if credit.proof.epoch > self.0.source.directory.history.anchor().epoch.0 {
            self.0
                .source
                .locate(credit.proof.epoch, credit.proof.commitment, &membership)
                .await?;
        }
        let call = credit.proof.call()?;
        let relayer = native(&credit.proof.relayer)?;
        let context = call.context(&self.0.source.origin, &self.0.source.address, &relayer)?;
        let (spend, claimant) = self.credentials(credit.slot)?;
        let seed = Zeroizing::new(claimant.to_bytes());
        let view = Zeroizing::new(native_stealth::view_secret(&seed));
        let note = envelope::open(
            self.0.source.domain,
            spend.owner(self.0.source.domain),
            &view,
            &call.boxes[0],
            &context,
            pool::decode_field(&credit.proof.commitment)?,
        )?;
        // Existing journal ownership and current native membership establish
        // spendable income, without re-granting a customer's purchased bytes.
        lease.with_current(super::super::PLAN_MAX_AGE, || Ok(()))?;
        Ok((
            Material {
                slot: credit.slot,
                epoch: credit.proof.epoch,
                commitment: credit.proof.commitment,
                membership,
                call,
                relayer,
            },
            note,
            spend,
        ))
    }
    pub(in crate::vpn::payments::shielded) async fn assigned_to(
        &self,
        id: [u8; 32],
    ) -> Result<Option<[u8; 32]>> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let assignment: Option<Assignment> = self
            .0
            .disk
            .load(&mut tx, ASSIGNMENT, &self.0.disk.tag(ASSIGNMENT, &id)?)
            .await?;
        tx.rollback().await?;
        assignment
            .map(|a| {
                ensure!(a.credit == id, "income assignment identity differs");
                Ok(a.payer)
            })
            .transpose()
    }
    pub(in crate::vpn::payments::shielded) async fn assign_income(
        &self,
        payer: [u8; 32],
        id: [u8; 32],
        index: &PoolIndex,
    ) -> Result<(Material, Note, SpendKey)> {
        ensure!(payer != [0; 32], "income payer identity is empty");
        let material = self.owned_income(id, index).await?;
        let mut tx = self.0.disk.begin().await?;
        let tag = self.0.disk.tag(ASSIGNMENT, &id)?;
        if let Some(a) = self
            .0
            .disk
            .load::<Assignment>(&mut tx, ASSIGNMENT, &tag)
            .await?
        {
            ensure!(
                a.credit == id && a.payer == payer,
                "operator income belongs to another payer book"
            );
        } else {
            self.0
                .disk
                .insert(
                    &mut tx,
                    ASSIGNMENT,
                    &tag,
                    &self.0.disk.tag(ASSIGNMENT, &payer)?,
                    &Assignment { payer, credit: id },
                )
                .await?;
        }
        self.0.disk.commit(tx).await?;
        Ok(material)
    }
    pub(in crate::vpn::payments::shielded) async fn open_assigned_income(
        &self,
        payer: [u8; 32],
        id: [u8; 32],
        index: &PoolIndex,
    ) -> Result<(Material, Note, SpendKey)> {
        ensure!(
            self.assigned_to(id).await? == Some(payer),
            "operator income assignment differs"
        );
        self.owned_income(id, index).await
    }
}
