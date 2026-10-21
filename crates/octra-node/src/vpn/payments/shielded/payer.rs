//! Local payer keys, canonical owned notes and durable finite purchase intents.
//! No operator receives a witness or spend key. A prepared proof is not paid.
mod control;
pub mod funding;
mod income;
mod ledger;
pub mod movement;
pub mod native;
mod purchase;
mod reconnect;
mod records;
mod recovery;
#[cfg(test)]
pub(crate) use reconnect::qualification as qualify_reconnect;
pub mod runner;
pub mod service;
pub mod startup;
use super::{storage::Disk, Pool};
use anyhow::{ensure, Context, Result};
use futures::TryStreamExt;
use octra_private_payments_experimental::{
    native_stealth,
    pool::{self, call::Call, envelope, Membership, Note, PoolIndex, SpendKey},
};
use octravpn_core::sealed::Key;
pub use records::Progress;
use records::{Attempt, Coin, Creation, Intent, Meta};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;
const META: u8 = 0;
const COIN: u8 = 1;
const INTENT: u8 = 2;
const ZERO: [u8; 32] = [0; 32];
const MAX_COINS: usize = 16_384;

pub struct NoteAddress {
    pub slot: u64,
    pub owner: [u8; 32],
    pub view_public: [u8; 32],
}
pub struct AvailableNote {
    pub commitment: [u8; 32],
    pub value_ou: u64,
}
pub struct Incoming<'a> {
    pub slot: u64,
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub membership: &'a Membership,
    pub output: u8,
    pub call: &'a Call,
    pub relayer: [u8; 47],
}
/// Public native calldata only. This contains no witness and proves no
/// canonical inclusion. Keep the associated invoice/intent private.
pub struct Proposal {
    pub quote: [u8; 32],
    attempt: Attempt,
    source: Arc<Pool>,
    change_slot: Option<u64>,
}
impl Proposal {
    pub fn parameters(&self) -> &serde_json::Value {
        &self.attempt.parameters
    }
    pub fn call(&self) -> Result<Call> {
        self.attempt.call.call()
    }
    pub fn outputs(&self) -> [[u8; 32]; 2] {
        self.attempt.outputs
    }
    pub fn first_output_index(&self) -> Result<u32> {
        Ok(self.attempt.count.try_into()?)
    }
    pub fn change_slot(&self) -> Option<u64> {
        self.change_slot
    }
    pub fn statement(&self) -> Result<pool::Statement> {
        let call = self.call()?;
        let context = call.context(
            &self.source.origin,
            &self.source.address,
            &super::native(&self.attempt.call.relayer)?,
        )?;
        let statement = pool::transaction::statement(
            self.source.domain,
            (
                pool::decode_field(&self.attempt.roots[0])?,
                pool::decode_field(&self.attempt.roots[1])?,
                self.attempt.count,
            ),
            context,
            &call,
            &self.attempt.parameters,
        )?;
        ensure!(
            statement.outputs.map(pool::encode_field) == self.attempt.outputs,
            "payer proposal output identity differs"
        );
        Ok(statement)
    }
}
struct Inner {
    disk: Disk,
    key: Key,
    wallet: [u8; 32],
    gate: Mutex<()>,
    purchases: Mutex<()>,
    provers: Arc<Semaphore>,
    incomes: RwLock<BTreeMap<[u8; 32], super::wallet::Wallet>>,
}
#[derive(Clone)]
pub struct Payer(Arc<Inner>, Arc<Pool>);
impl Payer {
    /// Price consent varies by operator; notes, reservations, keys, proving
    /// capacity and relayer nonces remain in one shared book.
    pub fn for_operator(&self, source: Arc<Pool>) -> Result<Self> {
        ensure!(
            self.1.same_custody(&source),
            "operator view has another custody source or node"
        );
        Ok(Self(self.0.clone(), source))
    }
    pub async fn create(path: &Path, key: Key, source: Arc<Pool>) -> Result<Self> {
        Self::open(path, key, source, true).await
    }
    pub async fn resume(path: &Path, key: Key, source: Arc<Pool>) -> Result<Self> {
        Self::open(path, key, source, false).await
    }
    async fn open(path: &Path, key: Key, source: Arc<Pool>, create: bool) -> Result<Self> {
        let mut hash = Sha256::new();
        hash.update(b"Octranet private payer wallet v1\0");
        hash.update(source.origin);
        hash.update(source.address);
        hash.update(source.code_hash.as_bytes());
        let scope: [u8; 32] = hash.finalize().into();
        let key = key.derive(b"payer wallet", &scope)?;
        let disk = Disk::open(path, key.clone(), scope, create).await?;
        let mut tx = disk.begin().await?;
        let meta: Meta = if create {
            use rand::RngCore;
            let mut wallet = ZERO;
            rand::rngs::OsRng.try_fill_bytes(&mut wallet)?;
            let meta = Meta {
                version: 1,
                scope,
                wallet,
                next_slot: 1,
            };
            disk.insert(&mut tx, META, &ZERO, &ZERO, &meta).await?;
            meta
        } else {
            disk.load(&mut tx, META, &ZERO)
                .await?
                .context("private payer metadata is missing")?
        };
        ensure!(
            meta.version == 1 && meta.scope == scope && meta.wallet != ZERO && meta.next_slot > 0,
            "private payer identity differs"
        );
        disk.commit(tx).await?;
        Ok(Self(
            Arc::new(Inner {
                disk,
                key,
                wallet: meta.wallet,
                gate: Mutex::new(()),
                purchases: Mutex::new(()),
                provers: Arc::new(Semaphore::new(1)),
                incomes: RwLock::new(BTreeMap::new()),
            }),
            source,
        ))
    }
    /// Reserve the key slot durably before returning its receiving address.
    pub async fn address(&self) -> Result<NoteAddress> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let mut meta: Meta = self
            .0
            .disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("payer metadata missing")?;
        let slot = meta.next_slot;
        meta.next_slot = slot.checked_add(1).context("payer key slots exhausted")?;
        self.0.disk.replace(&mut tx, META, &ZERO, &meta).await?;
        self.0.disk.commit(tx).await?;
        self.note_address(slot)
    }
    fn credentials(&self, slot: u64) -> Result<(SpendKey, Zeroizing<[u8; 32]>)> {
        let context = [self.0.wallet.as_slice(), &slot.to_be_bytes()].concat();
        let view = self.0.key.derive_bytes(b"view", &context)?;
        for attempt in 0_u32..256 {
            let raw = self.0.key.derive_bytes(
                b"spend",
                &[context.as_slice(), &attempt.to_be_bytes()].concat(),
            )?;
            if let Ok(spend) = SpendKey::from_bytes(&raw) {
                return Ok((spend, view));
            }
        }
        anyhow::bail!("payer key derivation exhausted")
    }
    fn note_address(&self, slot: u64) -> Result<NoteAddress> {
        let (spend, view) = self.credentials(slot)?;
        Ok(NoteAddress {
            slot,
            owner: pool::encode_field(spend.owner(self.1.domain)),
            view_public: native_stealth::view_public(&view),
        })
    }
    pub async fn receive(&self, input: Incoming<'_>) -> Result<bool> {
        let _gate = self.0.gate.lock().await;
        self.0.disk.check()?;
        let creation = Creation::new(&input)?;
        let mut tx = self.0.disk.begin().await?;
        let meta: Meta = self
            .0
            .disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("payer metadata missing")?;
        ensure!(
            input.slot > 0 && input.slot < meta.next_slot,
            "payer receiving slot was not reserved"
        );
        let tag = self.coin_tag(&creation.commitment)?;
        if let Some(coin) = self.0.disk.load::<Coin>(&mut tx, COIN, &tag).await? {
            ensure!(
                coin.slot == input.slot && coin.income.is_none() && coin.creation == creation,
                "payer note already belongs elsewhere"
            );
            tx.rollback().await?;
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
        let coin = Coin {
            slot: input.slot,
            creation,
            reserved: None,
            spent: false,
            income: None,
        };
        self.open_coin(&coin).await?;
        let mut tx = self.0.disk.begin().await?;
        if self
            .0
            .disk
            .load::<Coin>(&mut tx, COIN, &tag)
            .await?
            .is_some()
        {
            tx.rollback().await?;
            return Ok(false);
        }
        // Recheck under the writer transaction so simultaneous imports cannot
        // exceed the bounded wallet, even though proof work ran outside it.
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(COIN))
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            usize::try_from(count)? < MAX_COINS,
            "payer note capacity exhausted"
        );
        self.0
            .disk
            .insert(&mut tx, COIN, &tag, &ZERO, &coin)
            .await?;
        self.0.disk.commit(tx).await?;
        Ok(true)
    }
    async fn open_coin(&self, coin: &Coin) -> Result<(Note, SpendKey)> {
        ensure!(
            coin.income.is_none(),
            "operator income requires a current ownership witness"
        );
        let path = coin.creation.membership()?;
        self.locate(coin.creation.epoch, coin.creation.commitment, &path)
            .await?;
        self.decrypt_coin(coin)
    }
    // Only existing, authenticated financial-journal entries reach this path.
    // Current membership permits spending an owned note after pruning; it does
    // not establish its purchase time or grant operator traffic capacity.
    async fn open_coin_at(&self, coin: &Coin, index: &PoolIndex) -> Result<(Note, SpendKey)> {
        self.0.disk.check()?;
        let floor = self.1.directory.history.anchor().epoch.0;
        if let Some(income) = &coin.income {
            return self.open_income(coin, income, index).await;
        }
        if coin.creation.epoch > floor {
            return self.open_coin(coin).await;
        }
        ensure!(
            floor > 0 && coin.creation.epoch > 0,
            "payer note has no creation epoch"
        );
        let lease = self
            .1
            .current_member(index, coin.creation.index, coin.creation.commitment)
            .await?;
        let opened = self.decrypt_coin(coin)?;
        lease.with_current(super::PLAN_MAX_AGE, || Ok(()))?;
        Ok(opened)
    }
    fn decrypt_coin(&self, coin: &Coin) -> Result<(Note, SpendKey)> {
        let call = coin.creation.call.call()?;
        let relayer = super::native(&coin.creation.call.relayer)?;
        let context = call.context(&self.1.origin, &self.1.address, &relayer)?;
        let (spend, view) = self.credentials(coin.slot)?;
        let note = envelope::open(
            self.1.domain,
            spend.owner(self.1.domain),
            &view,
            call.boxes
                .get(usize::from(coin.creation.output))
                .context("payer note output differs")?,
            &context,
            pool::decode_field(&coin.creation.commitment)?,
        )?;
        Ok((note, spend))
    }
    fn coin_tag(&self, id: &[u8; 32]) -> Result<[u8; 32]> {
        self.0.disk.tag(COIN, id)
    }
    fn intent_tag(&self, id: &[u8; 32]) -> Result<[u8; 32]> {
        self.0.disk.tag(INTENT, id)
    }
    async fn current(&self, index: &PoolIndex) -> Result<(crate::SnapshotLease, u64)> {
        self.0.disk.check()?;
        self.1.current_index(index).await
    }
    async fn coins(&self) -> Result<Vec<Coin>> {
        let mut tx = self.0.disk.begin().await?;
        let mut rows = sqlx::query("SELECT tag,value FROM wallet_records WHERE kind=? LIMIT ?")
            .bind(i64::from(COIN))
            .bind(i64::try_from(MAX_COINS + 1)?)
            .fetch(&mut *tx);
        let mut coins = Vec::new();
        while let Some(row) = rows.try_next().await? {
            ensure!(coins.len() < MAX_COINS, "payer note capacity exceeded");
            let tag: Vec<u8> = row.try_get("tag")?;
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("payer note tag differs"))?;
            let raw: Vec<u8> = row.try_get("value")?;
            let coin: Coin = self.0.disk.decode(COIN, &tag, &raw)?;
            ensure!(
                self.coin_tag(&coin.creation.commitment)? == tag,
                "payer note identity differs"
            );
            coins.push(coin);
        }
        drop(rows);
        tx.rollback().await?;
        Ok(coins)
    }
    pub async fn available_ou(&self, index: &PoolIndex) -> Result<u64> {
        let _gate = self.0.gate.lock().await;
        let mut sum = 0_u64;
        for coin in self.coins().await? {
            if !coin.spent && coin.reserved.is_none() {
                let (note, key) = self.open_coin_at(&coin, index).await?;
                if !index.spent(&pool::encode_field(note.nullifier(self.1.domain, &key)?))? {
                    sum = sum
                        .checked_add(note.value())
                        .context("payer balance overflow")?;
                }
            }
        }
        self.current(index).await?;
        Ok(sum)
    }
    pub async fn available_notes(&self, index: &PoolIndex) -> Result<Vec<AvailableNote>> {
        let _gate = self.0.gate.lock().await;
        self.current(index).await?;
        let notes = self
            .candidates(index)
            .await?
            .into_iter()
            .map(|(coin, value_ou)| AvailableNote {
                commitment: coin.creation.commitment,
                value_ou,
            })
            .collect();
        self.current(index).await?;
        Ok(notes)
    }
    pub async fn progress(&self, quote: [u8; 32]) -> Result<Option<Progress>> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let intent: Option<Intent> = self
            .0
            .disk
            .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
            .await?;
        tx.rollback().await?;
        Ok(intent.map(|i| i.progress))
    }
}
