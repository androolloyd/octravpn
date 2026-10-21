//! Individually sealed native attempts and atomic migration of the original
//! inline journal. Counters never decrease when old attempts finish or expire.
use super::{parse, FeePolicy, Operation, Payer};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, Transaction};
pub(super) const BANK: u8 = 5;
const ENTRY: u8 = 6;
pub(super) const MAX_ATTEMPTS: u32 = 65_536;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    pub(super) operation: Operation,
    pub(super) transaction: String,
    pub(super) parameters_hash: [u8; 32],
    pub(super) head: [u8; 32],
    #[serde(default)]
    pub(super) deposit_ou: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bank {
    pub(super) version: u8,
    pub(super) policy: FeePolicy,
    pub(super) reserved_ou: u64,
    pub(super) count: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    policy: FeePolicy,
    reserved_ou: u64,
    attempts: Vec<Saved>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Stored {
    Current(Bank),
    Legacy(Legacy),
}

impl Bank {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 2
                && (1..=MAX_ATTEMPTS).contains(&self.policy.max_attempts)
                && self.count <= self.policy.max_attempts
                && self.policy.fee_ou >= 1000
                && i64::try_from(self.policy.fee_ou).is_ok()
                && i64::try_from(self.policy.lifetime_budget_ou).is_ok()
                && self.policy.lifetime_budget_ou >= self.policy.fee_ou
                && self.reserved_ou
                    == self
                        .policy
                        .fee_ou
                        .checked_mul(u64::from(self.count))
                        .context("native fee counter overflow")?
                && self.reserved_ou <= self.policy.lifetime_budget_ou,
            "native fee journal identity/counters differ"
        );
        Ok(())
    }
}
impl Payer {
    fn native_entry_tag(&self, bank: &[u8; 32], sequence: u32) -> Result<[u8; 32]> {
        self.0
            .disk
            .tag(ENTRY, &[bank.as_slice(), &sequence.to_be_bytes()].concat())
    }
    async fn native_entry_count(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        bank: &[u8; 32],
    ) -> Result<u32> {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=? AND bucket=?")
                .bind(i64::from(ENTRY))
                .bind(bank.as_slice())
                .fetch_one(&mut **tx)
                .await?;
        Ok(u32::try_from(count)?)
    }
    fn check_native_entry(&self, bank: &[u8; 32], policy: &FeePolicy, saved: &Saved) -> Result<()> {
        let signed = parse(saved)?;
        let public = signed
            .public_key
            .as_deref()
            .context("native journal signer missing")?;
        self.check_native(&signed, public, saved.deposit_ou)?;
        ensure!(
            saved.deposit_ou == 0 || matches!(saved.operation, Operation::Movement(_)),
            "native purchase has a deposit value"
        );
        let key: [u8; 32] = STANDARD
            .decode(public)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("native signer size differs"))?;
        let hash: [u8; 32] = Sha256::digest(
            signed
                .message
                .as_deref()
                .context("native journal parameters missing")?,
        )
        .into();
        ensure!(
            *bank == self.0.disk.tag(BANK, &key)?
                && signed.ou == policy.fee_ou.into()
                && saved.parameters_hash == hash,
            "native journal signer/fee/parameters differ"
        );
        Ok(())
    }
    pub(super) async fn load_native_entry(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        bank: &[u8; 32],
        sequence: u32,
        policy: &FeePolicy,
    ) -> Result<Saved> {
        ensure!(
            sequence > 0 && sequence <= policy.max_attempts,
            "native entry sequence differs"
        );
        let saved = self
            .0
            .disk
            .load(tx, ENTRY, &self.native_entry_tag(bank, sequence)?)
            .await?
            .context("native attempt record missing")?;
        self.check_native_entry(bank, policy, &saved)?;
        Ok(saved)
    }
    pub(super) async fn load_native_bank(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        tag: &[u8; 32],
    ) -> Result<Option<Bank>> {
        // Only reached after wallet metadata authentication. Index creation and
        // migration remain part of the caller's transaction, not wallet open.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS wallet_record_bucket ON wallet_records(kind,bucket)",
        )
        .execute(&mut **tx)
        .await?;
        let stored: Option<Stored> = self.0.disk.load(tx, BANK, tag).await?;
        let Some(stored) = stored else {
            ensure!(
                self.native_entry_count(tx, tag).await? == 0,
                "native fee metadata missing for retained attempts"
            );
            return Ok(None);
        };
        let bank = match stored {
            Stored::Current(bank) => bank,
            Stored::Legacy(legacy) => {
                ensure!(
                    legacy.policy.max_attempts <= 16
                        && legacy.attempts.len() <= 16
                        && self.native_entry_count(tx, tag).await? == 0,
                    "legacy native journal shape differs"
                );
                let bank = Bank {
                    version: 2,
                    policy: legacy.policy,
                    reserved_ou: legacy.reserved_ou,
                    count: u32::try_from(legacy.attempts.len())?,
                };
                bank.validate()?;
                for (index, saved) in legacy.attempts.iter().enumerate() {
                    self.check_native_entry(tag, &bank.policy, saved)?;
                    let sequence = u32::try_from(index + 1)?;
                    self.0
                        .disk
                        .insert(
                            tx,
                            ENTRY,
                            &self.native_entry_tag(tag, sequence)?,
                            tag,
                            saved,
                        )
                        .await?;
                }
                self.0.disk.replace(tx, BANK, tag, &bank).await?;
                bank
            }
        };
        bank.validate()?;
        ensure!(
            self.native_entry_count(tx, tag).await? == bank.count,
            "native attempt records differ from fee counter"
        );
        if bank.count > 0 {
            self.load_native_entry(tx, tag, bank.count, &bank.policy)
                .await?;
        }
        Ok(Some(bank))
    }
    pub(super) async fn append_native_entry(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        tag: &[u8; 32],
        bank: &mut Bank,
        saved: &Saved,
    ) -> Result<()> {
        bank.validate()?;
        self.check_native_entry(tag, &bank.policy, saved)?;
        ensure!(
            bank.count < bank.policy.max_attempts,
            "native relayer attempt budget exhausted"
        );
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(ENTRY))
            .fetch_one(&mut **tx)
            .await?;
        ensure!(
            total < i64::from(MAX_ATTEMPTS),
            "native wallet attempt storage exhausted"
        );
        bank.count = bank
            .count
            .checked_add(1)
            .context("native attempt counter overflow")?;
        bank.reserved_ou = bank
            .reserved_ou
            .checked_add(bank.policy.fee_ou)
            .context("native fee counter overflow")?;
        bank.validate()?;
        self.0
            .disk
            .insert(
                tx,
                ENTRY,
                &self.native_entry_tag(tag, bank.count)?,
                tag,
                saved,
            )
            .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    /// Reconstruct the exact v1 inline layout from genuine signed attempts.
    /// This fixture is never compiled into a running node.
    pub(crate) async fn legacy(payer: &Payer, public: &[u8; 32]) {
        let tag = payer.0.disk.tag(BANK, public).unwrap();
        let mut tx = payer.0.disk.begin().await.unwrap();
        let bank = payer
            .load_native_bank(&mut tx, &tag)
            .await
            .unwrap()
            .unwrap();
        assert!(bank.count <= 16 && bank.policy.max_attempts <= 16);
        let mut attempts = Vec::new();
        for sequence in 1..=bank.count {
            attempts.push(
                payer
                    .load_native_entry(&mut tx, &tag, sequence, &bank.policy)
                    .await
                    .unwrap(),
            );
        }
        let old = Legacy {
            policy: bank.policy,
            reserved_ou: bank.reserved_ou,
            attempts,
        };
        payer
            .0
            .disk
            .replace(&mut tx, BANK, &tag, &old)
            .await
            .unwrap();
        sqlx::query("DELETE FROM wallet_records WHERE kind=? AND bucket=?")
            .bind(i64::from(ENTRY))
            .bind(tag.as_slice())
            .execute(&mut *tx)
            .await
            .unwrap();
        payer.0.disk.commit(tx).await.unwrap();
    }
    pub(crate) async fn record_failure_is_closed(payer: &Payer, public: &[u8; 32]) {
        let tag = payer.0.disk.tag(BANK, public).unwrap();
        let mut tx = payer.0.disk.begin().await.unwrap();
        let bank = payer
            .load_native_bank(&mut tx, &tag)
            .await
            .unwrap()
            .unwrap();
        let entry_tag = payer.native_entry_tag(&tag, bank.count).unwrap();
        // Roll back damage rather than manufacture a replacement wallet.
        sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=?")
            .bind(i64::from(ENTRY))
            .bind(entry_tag.as_slice())
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(payer.load_native_bank(&mut tx, &tag).await.is_err());
        tx.rollback().await.unwrap();
        let mut tx = payer.0.disk.begin().await.unwrap();
        sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=?")
            .bind(i64::from(BANK))
            .bind(tag.as_slice())
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(payer.load_native_bank(&mut tx, &tag).await.is_err());
        tx.rollback().await.unwrap();
    }
    pub(crate) async fn expire_last(
        payer: &Payer,
        key: &ed25519_dalek::SigningKey,
    ) -> super::super::SignedAttempt {
        use ed25519_dalek::Signer;
        let public = key.verifying_key().to_bytes();
        let tag = payer.0.disk.tag(BANK, &public).unwrap();
        let mut tx = payer.0.disk.begin().await.unwrap();
        let bank = payer
            .load_native_bank(&mut tx, &tag)
            .await
            .unwrap()
            .unwrap();
        let mut saved = payer
            .load_native_entry(&mut tx, &tag, bank.count, &bank.policy)
            .await
            .unwrap();
        let mut signed = parse(&saved).unwrap();
        signed.timestamp = super::super::clock().unwrap() - 301.;
        signed.signature = STANDARD
            .encode(key.sign(&signed.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        saved.transaction = String::from_utf8(signed.to_json_bytes().unwrap()).unwrap();
        payer
            .check_native_entry(&tag, &bank.policy, &saved)
            .unwrap();
        payer
            .0
            .disk
            .replace(
                &mut tx,
                ENTRY,
                &payer.native_entry_tag(&tag, bank.count).unwrap(),
                &saved,
            )
            .await
            .unwrap();
        payer.0.disk.commit(tx).await.unwrap();
        payer.native_attempt(&public, bank.count).await.unwrap()
    }
}
