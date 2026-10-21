//! Shared note selection, durable reservation, proof work and reconciliation.
//! Callers hold the payer gate; no secret leaves the owned proof worker.
use super::{
    records::{Attempt, CallRecord, Coin, Meta},
    Payer, COIN, INTENT, MAX_COINS, META, ZERO,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_private_payments_experimental::pool::{
    self, call::Call, transaction::Prover, Note, PoolIndex, Spend, SpendKey,
};
use serde::Serialize;
use sqlx::{Sqlite, Transaction};

pub(super) type Inputs = Vec<(Coin, Note, SpendKey)>;
impl Payer {
    pub(super) fn check_prover(&self, prover: &Prover) -> Result<()> {
        ensure!(
            prover.verification_key()? == STANDARD.decode(&self.1.config.verification_key_b64)?,
            "payer prover does not match the accepted pool key"
        );
        Ok(())
    }
    pub(super) async fn input(&self, id: &[u8; 32]) -> Result<Coin> {
        let mut tx = self.0.disk.begin().await?;
        let coin = self
            .0
            .disk
            .load(&mut tx, COIN, &self.coin_tag(id)?)
            .await?
            .context("payer input note missing")?;
        tx.rollback().await?;
        Ok(coin)
    }
    pub(super) async fn candidates(&self, index: &PoolIndex) -> Result<Vec<(Coin, u64)>> {
        let mut candidates = Vec::new();
        for coin in self.coins().await? {
            if coin.spent || coin.reserved.is_some() {
                continue;
            }
            let (note, key) = self.open_coin_at(&coin, index).await?;
            if !index.spent(&pool::encode_field(note.nullifier(self.1.domain, &key)?))? {
                candidates.push((coin, note.value()));
            }
        }
        candidates.sort_by_key(|(_, value)| *value);
        Ok(candidates)
    }
    pub(super) async fn select(&self, cost: u64, index: &PoolIndex) -> Result<Vec<(Coin, u64)>> {
        ensure!(cost > 0, "payer amount is zero");
        let mut candidates = self.candidates(index).await?;
        let chosen = if let Some(position) = candidates.iter().position(|(_, value)| *value >= cost)
        {
            vec![candidates.swap_remove(position)]
        } else {
            let first = candidates.pop().context("payer has no available note")?;
            let second = candidates
                .pop()
                .context("payer needs another available note")?;
            vec![first, second]
        };
        let total = Self::total(&chosen)?;
        ensure!(
            total >= cost,
            "payer has insufficient value in two notes; consolidate first"
        );
        Ok(chosen)
    }
    pub(super) fn total(chosen: &[(Coin, u64)]) -> Result<u64> {
        let total = chosen.iter().try_fold(0_u64, |sum, (_, value)| {
            sum.checked_add(*value).context("payer input overflow")
        })?;
        ensure!(
            i64::try_from(total).is_ok(),
            "payer input exceeds native value range"
        );
        Ok(total)
    }
    pub(super) async fn reserve<T: Serialize>(
        &self,
        kind: u8,
        id: [u8; 32],
        chosen: Vec<(Coin, u64)>,
        slots: u8,
        create: impl FnOnce(Vec<[u8; 32]>, Option<u64>) -> T,
    ) -> Result<T> {
        ensure!(
            ((1..=2).contains(&chosen.len())
                || (chosen.is_empty() && kind == super::movement::MOVEMENT && slots == 1))
                && slots <= 1,
            "payer reservation shape differs"
        );
        let mut tx = self.0.disk.begin().await?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind IN (?,?)")
                .bind(i64::from(INTENT))
                .bind(i64::from(super::movement::MOVEMENT))
                .fetch_one(&mut *tx)
                .await?;
        ensure!(count < 65_536, "payer operation capacity exhausted");
        let mut meta: Meta = self
            .0
            .disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("payer metadata missing")?;
        let output_slot = if slots == 1 {
            let slot = meta.next_slot;
            meta.next_slot = slot
                .checked_add(1)
                .context("payer output slots exhausted")?;
            Some(slot)
        } else {
            None
        };
        let mut inputs = Vec::new();
        for (coin, _) in chosen {
            let id_coin = coin.creation.commitment;
            let tag = self.coin_tag(&id_coin)?;
            let mut latest: Coin = self
                .0
                .disk
                .load(&mut tx, COIN, &tag)
                .await?
                .context("payer input disappeared")?;
            ensure!(
                !latest.spent && latest.reserved.is_none(),
                "payer input was already reserved"
            );
            latest.reserved = Some(id);
            self.0.disk.replace(&mut tx, COIN, &tag, &latest).await?;
            inputs.push(id_coin);
        }
        let record = create(inputs, output_slot);
        self.0
            .disk
            .insert(&mut tx, kind, &self.0.disk.tag(kind, &id)?, &ZERO, &record)
            .await?;
        self.0.disk.replace(&mut tx, META, &ZERO, &meta).await?;
        self.0.disk.commit(tx).await?;
        Ok(record)
    }
    pub(super) async fn reserved(
        &self,
        id: [u8; 32],
        inputs: &[[u8; 32]],
        index: &PoolIndex,
        spent: bool,
    ) -> Result<(Inputs, u64)> {
        ensure!((1..=2).contains(&inputs.len()), "payer input count differs");
        let mut opened = Vec::new();
        let mut total = 0_u64;
        for commitment in inputs {
            let coin = self.input(commitment).await?;
            ensure!(
                !coin.spent && coin.reserved == Some(id),
                "payer input reservation differs"
            );
            let (note, key) = self.open_coin_at(&coin, index).await?;
            ensure!(
                index.spent(&pool::encode_field(note.nullifier(self.1.domain, &key)?))? == spent,
                "payer input spend differs; reconcile canonical execution"
            );
            total = total
                .checked_add(note.value())
                .context("payer input overflow")?;
            opened.push((coin, note, key));
        }
        ensure!(
            i64::try_from(total).is_ok(),
            "payer input exceeds native value range"
        );
        Ok((opened, total))
    }
    pub(super) async fn prove(
        &self,
        index: &PoolIndex,
        call: &Call,
        relayer: &[u8; 47],
        inputs: &Inputs,
        outputs: &[Note],
        now: u64,
        prover: &Prover,
    ) -> Result<Attempt> {
        self.check_prover(prover)?;
        let context = call.context(&self.1.origin, &self.1.address, relayer)?;
        let spends = inputs
            .iter()
            .map(|(coin, note, key)| Spend {
                note,
                key,
                index: coin.creation.index,
            })
            .collect::<Vec<_>>();
        let (circuit, _) = index.prepare(
            self.1.domain,
            &spends,
            outputs,
            call.deposit_ou,
            call.withdraw_ou,
            context,
        )?;
        call.validate(
            &circuit.statement,
            &self.1.origin,
            &self.1.address,
            relayer,
            now,
        )?;
        let statement = circuit.statement.clone();
        let permit = self.0.provers.clone().acquire_owned().await?;
        let prover = prover.clone();
        let proof = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            prover.prove(circuit)
        })
        .await??;
        let roots = index.roots();
        Ok(Attempt {
            roots: [pool::encode_field(roots.0), pool::encode_field(roots.1)],
            count: roots.2,
            outputs: statement.outputs.map(pool::encode_field),
            call: CallRecord::new(call, relayer)?,
            parameters: pool::transaction::parameters(&statement, call, &proof)?,
        })
    }
    pub(super) async fn finish_notes(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        id: [u8; 32],
        inputs: &[[u8; 32]],
        spent: bool,
        incoming: Option<Coin>,
    ) -> Result<()> {
        for commitment in inputs {
            let tag = self.coin_tag(commitment)?;
            let mut coin: Coin = self
                .0
                .disk
                .load(tx, COIN, &tag)
                .await?
                .context("payer input disappeared")?;
            ensure!(
                coin.reserved == Some(id) && !coin.spent,
                "payer reservation changed during finalization"
            );
            coin.reserved = None;
            coin.spent = spent;
            self.0.disk.replace(tx, COIN, &tag, &coin).await?;
        }
        if let Some(coin) = incoming {
            let tag = self.coin_tag(&coin.creation.commitment)?;
            if let Some(prior) = self.0.disk.load::<Coin>(tx, COIN, &tag).await? {
                ensure!(
                    prior.slot == coin.slot
                        && prior.income == coin.income
                        && prior.creation == coin.creation,
                    "payer output already belongs elsewhere"
                );
            } else {
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                        .bind(i64::from(COIN))
                        .fetch_one(&mut **tx)
                        .await?;
                ensure!(
                    usize::try_from(count)? < MAX_COINS,
                    "payer note capacity exhausted"
                );
                self.0.disk.insert(tx, COIN, &tag, &ZERO, &coin).await?;
            }
        }
        Ok(())
    }
    pub(super) async fn release_safe(
        &self,
        id: [u8; 32],
        inputs: &[[u8; 32]],
        attempt: Option<&Attempt>,
        index: &PoolIndex,
    ) -> Result<()> {
        if let Some(attempt) = attempt {
            let roots = index.roots();
            ensure!(
                attempt.roots != [pool::encode_field(roots.0), pool::encode_field(roots.1)],
                "payer exposed proof roots have not been invalidated"
            );
        }
        self.reserved(id, inputs, index, false).await?;
        Ok(())
    }
}
