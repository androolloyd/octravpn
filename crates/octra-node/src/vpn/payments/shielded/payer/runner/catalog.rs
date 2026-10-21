//! Job identities stay inside the encrypted book so a restart needs no
//! separately maintained list of request IDs.
use super::{Payer, Purchase, Terms, JOB, MAX_JOBS};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    version: u8,
    id: [u8; 32],
    terms: Terms,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<super::route::Owner>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_phase: Option<[u8; 32]>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Saved {
    Current(Job),
    Legacy(Terms),
}
impl Purchase {
    /// Explicit finite consent. The same ID cannot change its terms. Older
    /// records are upgraded only when the caller supplies their original ID.
    pub async fn create(payer: Payer, id: [u8; 32], terms: Terms) -> Result<Self> {
        let _gate = payer.0.purchases.lock().await;
        let result = Self {
            payer: payer.clone(),
            id,
            terms,
        };
        result.validate()?;
        let mut tx = payer.0.disk.begin().await?;
        if result.store(&mut tx).await? {
            payer.0.disk.commit(tx).await?;
        } else {
            tx.rollback().await?;
        }
        Ok(result)
    }

    // The caller holds the purchase mutex. Route consent uses this within the
    // same transaction as its ownership marker, before discovery can see a job.
    pub(super) async fn store(&self, tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<bool> {
        self.store_owned(tx, None).await
    }

    pub(super) async fn store_owned(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        owner: Option<&super::route::Owner>,
    ) -> Result<bool> {
        let tag = self.tag(JOB, 0)?;
        let saved = self.payer.0.disk.load::<Saved>(tx, JOB, &tag).await?;
        if let Some(saved) = &saved {
            let terms = match saved {
                Saved::Current(job) => {
                    ensure!(
                        job.version == 1 && job.id == self.id,
                        "private job identity differs"
                    );
                    if let Some(owner) = owner {
                        ensure!(
                            job.owner.as_ref() == Some(owner),
                            "route job changes embedded ownership"
                        );
                    }
                    &job.terms
                }
                Saved::Legacy(terms) => {
                    ensure!(
                        owner.is_none(),
                        "route cannot adopt legacy standalone consent"
                    );
                    terms
                }
            };
            ensure!(
                *terms == self.terms,
                "private purchase ID changes accepted terms"
            );
        } else {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                .bind(i64::from(JOB))
                .fetch_one(&mut **tx)
                .await?;
            ensure!(count < MAX_JOBS, "private purchase capacity exhausted");
        }
        let job = Job {
            version: 1,
            id: self.id,
            terms: self.terms.clone(),
            owner: owner.cloned(),
            client_phase: None,
        };
        match saved {
            None => {
                self.payer
                    .0
                    .disk
                    .insert(tx, JOB, &tag, &[0; 32], &job)
                    .await?;
            }
            Some(Saved::Legacy(_)) => self.payer.0.disk.replace(tx, JOB, &tag, &job).await?,
            Some(Saved::Current(_)) => return Ok(false),
        }
        Ok(true)
    }

    pub(super) async fn check_stored(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<Option<super::route::Owner>> {
        Ok(self.read_job(tx).await?.owner)
    }

    pub(super) async fn client_binding(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<Option<[u8; 32]>> {
        Ok(self.read_job(tx).await?.client_phase)
    }

    pub(super) async fn bind_client(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        binding: [u8; 32],
    ) -> Result<()> {
        let mut job = self.read_job(tx).await?;
        ensure!(
            job.client_phase.is_none_or(|saved| saved == binding),
            "private purchase changes client binding"
        );
        if job.client_phase.is_none() {
            job.client_phase = Some(binding);
            self.payer
                .0
                .disk
                .replace(tx, JOB, &self.tag(JOB, 0)?, &job)
                .await?;
        }
        Ok(())
    }

    async fn read_job(&self, tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<Job> {
        let saved = self
            .payer
            .0
            .disk
            .load::<Saved>(tx, JOB, &self.tag(JOB, 0)?)
            .await?;
        let Some(Saved::Current(job)) = saved else {
            anyhow::bail!("private purchase missing or changed version");
        };
        ensure!(
            job.version == 1 && job.id == self.id && job.terms == self.terms,
            "private purchase changes consent"
        );
        Ok(job)
    }

    pub async fn resume(payer: Payer, id: [u8; 32]) -> Result<Self> {
        let mut tx = payer.0.disk.begin().await?;
        let tag = payer.0.disk.tag(JOB, &[id.as_slice(), &[0]].concat())?;
        let saved = payer
            .0
            .disk
            .load::<Saved>(&mut tx, JOB, &tag)
            .await?
            .context("private purchase is missing")?;
        tx.rollback().await?;
        let terms = match saved {
            Saved::Current(job) => {
                ensure!(
                    job.version == 1 && job.id == id,
                    "private job identity differs"
                );
                job.terms
            }
            Saved::Legacy(terms) => terms,
        };
        Self::create(payer, id, terms).await
    }

    /// Discover every job for this operator. Other operator views share the
    /// custody book but cannot drive each other's requests. Any legacy record
    /// needs an explicit resume with its original ID before discovery succeeds.
    pub async fn discover(payer: Payer) -> Result<Vec<Self>> {
        let _gate = payer.0.purchases.lock().await;
        payer.0.disk.check()?;
        let mut tx = payer.0.disk.begin().await?;
        let rows =
            sqlx::query("SELECT tag,value FROM wallet_records WHERE kind=? ORDER BY tag LIMIT ?")
                .bind(i64::from(JOB))
                .bind(MAX_JOBS + 1)
                .fetch_all(&mut *tx)
                .await?;
        ensure!(
            rows.len() <= usize::try_from(MAX_JOBS)?,
            "private purchase capacity exceeded"
        );
        let mut jobs = Vec::new();
        for row in rows {
            let tag: Vec<u8> = row.try_get("tag")?;
            let raw: Vec<u8> = row.try_get("value")?;
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("private job tag differs"))?;
            let Saved::Current(job) = payer.0.disk.decode(JOB, &tag, &raw)? else {
                anyhow::bail!("legacy purchase needs explicit resume with its original ID");
            };
            ensure!(
                job.version == 1 && job.id != [0; 32],
                "private job identity differs"
            );
            job.terms.validate()?;
            let result = Self {
                payer: payer.clone(),
                id: job.id,
                terms: job.terms,
            };
            ensure!(result.tag(JOB, 0)? == tag, "private job tag differs");
            if super::matches_source(&result.terms.target, &payer.1) {
                result.validate()?;
                jobs.push(result);
            }
        }
        tx.rollback().await?;
        Ok(jobs)
    }

    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn terms(&self) -> &Terms {
        &self.terms
    }
}

#[cfg(test)]
impl Purchase {
    pub(crate) async fn foreign_directory_case(payer: Payer, id: [u8; 32], terms: Terms) {
        terms.validate().unwrap();
        let mut tx = payer.0.disk.begin().await.unwrap();
        let tag = payer
            .0
            .disk
            .tag(JOB, &[id.as_slice(), &[0]].concat())
            .unwrap();
        let job = Job {
            version: 1,
            id,
            terms,
            owner: None,
            client_phase: None,
        };
        payer
            .0
            .disk
            .insert(&mut tx, JOB, &tag, &[0; 32], &job)
            .await
            .unwrap();
        payer.0.disk.commit(tx).await.unwrap();
        assert_eq!(Self::discover(payer).await.unwrap().len(), 1);
    }

    pub(crate) async fn legacy_recovery_case(payer: Payer, id: [u8; 32], terms: Terms) {
        let mut tx = payer.0.disk.begin().await.unwrap();
        let tag = payer
            .0
            .disk
            .tag(JOB, &[id.as_slice(), &[0]].concat())
            .unwrap();
        payer
            .0
            .disk
            .replace(&mut tx, JOB, &tag, &terms)
            .await
            .unwrap();
        payer.0.disk.commit(tx).await.unwrap();
        assert!(Self::discover(payer.clone()).await.is_err());
        let migrated = Self::resume(payer.clone(), id).await.unwrap();
        assert!(migrated.terms() == &terms);
        assert_eq!(Self::discover(payer).await.unwrap()[0].id(), id);
    }
}
