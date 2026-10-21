//! One-owner operator income can join an existing payer book without an
//! on-chain detour or exporting spend keys. The original wallet stays unlocked
//! as a local credential provider; assignment is exclusive and durable there.
use super::super::wallet::{income::Material, Wallet};
use super::{
    records::{Coin, Creation, Income},
    Incoming, Payer, COIN, MAX_COINS, ZERO,
};
use anyhow::{ensure, Context, Result};
use octra_private_payments_experimental::pool::{Note, PoolIndex, SpendKey};

impl Material {
    fn coin(&self, wallet: [u8; 32], credit: [u8; 32]) -> Result<Coin> {
        let input = Incoming {
            slot: self.slot,
            epoch: self.epoch,
            commitment: self.commitment,
            membership: &self.membership,
            output: 0,
            call: &self.call,
            relayer: self.relayer,
        };
        Ok(Coin {
            slot: self.slot,
            creation: Creation::new(&input)?,
            reserved: None,
            spent: false,
            income: Some(Income { wallet, credit }),
        })
    }
}
impl Payer {
    fn register_income(&self, wallet: &Wallet) -> Result<[u8; 32]> {
        ensure!(
            self.1.same_custody(wallet.income_pool()),
            "income wallet has another custody source or node"
        );
        let id = wallet.income_id();
        let mut providers = self
            .0
            .incomes
            .write()
            .map_err(|_| anyhow::anyhow!("income provider lock poisoned"))?;
        ensure!(
            providers.contains_key(&id) || providers.len() < 64,
            "income provider capacity exhausted"
        );
        providers.insert(id, wallet.clone());
        Ok(id)
    }
    /// Import a canonically owned operator note once. A crash after assignment
    /// but before import retries into this same persisted payer identity.
    pub async fn claim_income(
        &self,
        wallet: &Wallet,
        credit: [u8; 32],
        index: &PoolIndex,
    ) -> Result<bool> {
        let _gate = self.0.gate.lock().await;
        let provider = self.register_income(wallet)?;
        self.current(index).await?;
        let (material, note, key) = wallet.owned_income(credit, index).await?;
        let coin = material.coin(provider, credit)?;
        if index.spent(&super::pool::encode_field(
            note.nullifier(self.1.domain, &key)?,
        ))? {
            return Ok(false);
        }
        let tag = self.coin_tag(&coin.creation.commitment)?;
        let mut tx = self.0.disk.begin().await?;
        if let Some(existing) = self.0.disk.load::<Coin>(&mut tx, COIN, &tag).await? {
            ensure!(
                existing.income == coin.income
                    && existing.slot == coin.slot
                    && existing.creation == coin.creation,
                "income note already belongs elsewhere"
            );
            tx.rollback().await?;
            ensure!(
                wallet.assigned_to(credit).await? == Some(self.0.wallet),
                "income assignment is missing or changed"
            );
            return Ok(false);
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(COIN))
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            usize::try_from(count)? < MAX_COINS,
            "payer note capacity exhausted"
        );
        tx.rollback().await?;
        // Admission to this bounded book precedes irreversible assignment.
        // Every note-creating path shares the payer gate, so another local
        // import cannot consume the last slot during the cross-wallet commit.
        drop(wallet.assign_income(self.0.wallet, credit, index).await?);
        let mut tx = self.0.disk.begin().await?;
        self.0
            .disk
            .insert(&mut tx, COIN, &tag, &ZERO, &coin)
            .await?;
        self.0.disk.commit(tx).await?;
        self.current(index).await?;
        Ok(true)
    }
    /// Reattach on every process reopen. Already imported notes retain their
    /// spent/reserved state; income assigned to a different book is skipped.
    pub async fn attach_income(&self, wallet: &Wallet, index: &PoolIndex) -> Result<usize> {
        self.current(index).await?;
        self.register_income(wallet)?;
        let mut imported = 0;
        for credit in wallet.income_ids().await? {
            if wallet
                .assigned_to(credit)
                .await?
                .is_some_and(|owner| owner != self.0.wallet)
            {
                continue;
            }
            imported += usize::from(self.claim_income(wallet, credit, index).await?);
        }
        self.current(index).await?;
        Ok(imported)
    }
    pub(super) async fn open_income(
        &self,
        coin: &Coin,
        income: &Income,
        index: &PoolIndex,
    ) -> Result<(Note, SpendKey)> {
        let provider = self
            .0
            .incomes
            .read()
            .map_err(|_| anyhow::anyhow!("income provider lock poisoned"))?
            .get(&income.wallet)
            .cloned()
            .context("unlock and attach the assigned operator wallet before spending its income")?;
        ensure!(
            self.1.same_custody(provider.income_pool()),
            "income custody source changed"
        );
        let (material, note, key) = provider
            .open_assigned_income(self.0.wallet, income.credit, index)
            .await?;
        let expected = material.coin(income.wallet, income.credit)?;
        ensure!(
            coin.slot == expected.slot && coin.creation == expected.creation,
            "income note material differs"
        );
        Ok((note, key))
    }
}

#[cfg(test)]
impl Payer {
    pub(crate) async fn assign_income_before_import(
        &self,
        wallet: &Wallet,
        credit: [u8; 32],
        index: &PoolIndex,
    ) {
        // A stopped process can leave the first database committed while the
        // payer import has not started. No keys leave this test-only helper.
        drop(
            wallet
                .assign_income(self.0.wallet, credit, index)
                .await
                .unwrap(),
        );
    }
}
