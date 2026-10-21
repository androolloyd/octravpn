//! Portable confirmation locators remain hints until the stored execution
//! witness is reauthenticated against this node's retained certificate.
use super::super::{
    history::{self, Proof},
    Historical, Placement,
};
use super::{native::SignedAttempt, Payer};
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{native_json::Document, transaction::Transaction};
use octra_private_payments_experimental::pool::Membership;
use serde::{Deserialize, Serialize};
const KIND: u8 = 7;
const LOCATOR: u8 = 9;
const ZERO: [u8; 32] = [0; 32];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Location {
    hash: String,
    epoch: u64,
}
impl Payer {
    pub(super) async fn recovery_proof(&self, epoch: u64) -> Result<Option<Proof>> {
        history::storage::load(&self.0.disk, KIND, epoch).await
    }
    pub(super) async fn historical(&self, epoch: u64) -> Result<Historical> {
        let proof = if epoch <= self.1.directory.history.anchor().epoch.0 {
            self.recovery_proof(epoch).await?
        } else {
            None
        };
        self.1.historical(epoch, proof.as_ref()).await
    }
    pub(super) async fn locate(
        &self,
        epoch: u64,
        commitment: [u8; 32],
        membership: &Membership,
    ) -> Result<Placement> {
        let proof = if epoch <= self.1.directory.history.anchor().epoch.0 {
            self.recovery_proof(epoch).await?
        } else {
            None
        };
        self.1
            .locate_from(epoch, commitment, membership, proof.as_ref())
            .await
    }
    pub(super) async fn confirmed_exchange(
        &self,
        epoch: u64,
        parameters: &serde_json::Value,
        relayer: &[u8; 47],
        deposit_ou: u64,
        expected: Option<&Transaction>,
    ) -> Result<Historical> {
        if epoch > self.1.directory.history.anchor().epoch.0 {
            return self
                .1
                .confirmed_exchange(epoch, parameters, relayer, deposit_ou, expected)
                .await;
        }
        let proof = self.recovery_proof(epoch).await?;
        self.1
            .confirmed_exchange_from(
                epoch,
                parameters,
                relayer,
                deposit_ou,
                expected,
                proof.as_ref(),
            )
            .await
    }
    pub(super) async fn confirmation_location(&self, hash: &str) -> Result<Option<u64>> {
        let mut tx = self.0.disk.begin().await?;
        let location: Option<Location> = self
            .0
            .disk
            .load(
                &mut tx,
                LOCATOR,
                &self.0.disk.tag(LOCATOR, hash.as_bytes())?,
            )
            .await?;
        tx.rollback().await?;
        location
            .map(|l| {
                ensure!(
                    l.hash == hash && l.epoch > 0,
                    "portable confirmation identity differs"
                );
                Ok(l.epoch)
            })
            .transpose()
    }
    /// Preserve a real confirmed attempt before pruning, even when the process
    /// has not yet reconciled its purchase/change or movement into the book.
    pub async fn retain_native(&self, attempt: &SignedAttempt, anchor: u64) -> Result<()> {
        self.saved_native(attempt).await?;
        let hash = attempt.hash()?;
        let lease = crate::SnapshotLease::capture(self.1.directory.shared.clone())?;
        let found = self
            .1
            .directory
            .history
            .transaction(lease.committed().head(), hash.as_bytes(), 32_768)
            .await?;
        let epoch = if let Some((head, record)) = found {
            ensure!(
                record.hash == hash
                    && Transaction::from_document(&Document::parse(&record.transaction)?)?
                        == *attempt.transaction(),
                "portable native envelope differs"
            );
            head.cursor.epoch.0
        } else {
            self.confirmation_location(&hash)
                .await?
                .context("native attempt has no retained confirmation")?
        };
        let proof =
            Proof::capture(&self.1, epoch, anchor, self.recovery_proof(epoch).await?).await?;
        let parameters = serde_json::from_slice(
            attempt
                .transaction()
                .message
                .as_deref()
                .context("portable native parameters missing")?,
        )?;
        let relayer = attempt.transaction().from.as_slice().try_into()?;
        self.1
            .confirmed_exchange_from(
                epoch,
                &parameters,
                &relayer,
                u64::try_from(&attempt.transaction().amount)?,
                Some(attempt.transaction()),
                Some(&proof),
            )
            .await?;
        let mut tx = self.0.disk.begin().await?;
        history::storage::save(&self.0.disk, &mut tx, KIND, &proof).await?;
        let key = self.0.disk.tag(LOCATOR, hash.as_bytes())?;
        let location = Location { hash, epoch };
        let old: Option<Location> = self.0.disk.load(&mut tx, LOCATOR, &key).await?;
        if let Some(old) = old {
            ensure!(
                old.hash == location.hash && old.epoch == epoch,
                "portable confirmation changed"
            );
        } else {
            self.0
                .disk
                .insert(&mut tx, LOCATOR, &key, &ZERO, &location)
                .await?;
        }
        self.0.disk.commit(tx).await
    }
}
