//! One explicitly approved native deposit. Restarts discover its encrypted
//! identity and reconcile the original signature before doing any more work.
use super::{
    movement::Window,
    native::{FeePolicy, Operation},
    Payer,
};
use crate::vpn::payments::shielded::index::Index;
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_private_payments_experimental::pool::transaction::Prover;
use serde::{Deserialize, Serialize};
use sqlx::Row;
const JOB: u8 = 12;
const MAX_JOBS: i64 = 16_384;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub amount_ou: u64,
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub relayer_public: [u8; 32],
    pub fees: FeePolicy,
}
impl Terms {
    fn window(&self) -> Result<Window> {
        let public = octravpn_core::b64::encode(self.relayer_public);
        let address = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
        Ok(Window {
            valid_from_ms: self.valid_from_ms,
            expires_ms: self.expires_ms,
            relayer: address
                .as_slice()
                .try_into()
                .context("funding native address differs")?,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    version: u8,
    id: [u8; 32],
    terms: Terms,
}
pub struct Funding {
    payer: Payer,
    job: Job,
}
pub enum State {
    Syncing,
    Submitted { hash: String },
    Funded { epoch: u64 },
}
pub struct Services<'a, A: crate::Host> {
    pub index: &'a Index,
    pub submission: &'a crate::rpc::Submission<A>,
    pub relayer: &'a SigningKey,
    pub prover: &'a Prover,
}
impl Funding {
    fn validate(&self) -> Result<()> {
        self.payer.0.disk.check()?;
        let terms = &self.job.terms;
        terms.fees.validate()?;
        ensure!(
            self.job.version == 1
                && self.job.id != [0; 32]
                && terms.amount_ou > 0
                && terms.amount_ou <= self.payer.1.config.custody_cap_ou
                && i64::try_from(terms.amount_ou).is_ok()
                && terms.expires_ms > terms.valid_from_ms
                && terms.expires_ms - terms.valid_from_ms <= 86_400_000,
            "private funding consent differs"
        );
        ensure!(
            !ed25519_dalek::VerifyingKey::from_bytes(&terms.relayer_public)?.is_weak(),
            "weak funding relayer key"
        );
        Ok(())
    }
    pub async fn create(payer: Payer, id: [u8; 32], terms: Terms) -> Result<Self> {
        let _gate = payer.0.purchases.lock().await;
        let result = Self {
            payer: payer.clone(),
            job: Job {
                version: 1,
                id,
                terms,
            },
        };
        result.validate()?;
        payer
            .check_deposit_consent(id, result.job.terms.amount_ou, result.job.terms.window()?)
            .await?;
        let tag = payer.0.disk.tag(JOB, &id)?;
        let mut tx = payer.0.disk.begin().await?;
        if let Some(saved) = payer.0.disk.load::<Job>(&mut tx, JOB, &tag).await? {
            ensure!(
                saved.version == 1 && saved.id == id && saved.terms == result.job.terms,
                "private funding ID changes consent"
            );
            tx.rollback().await?;
        } else {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                .bind(i64::from(JOB))
                .fetch_one(&mut *tx)
                .await?;
            ensure!(count < MAX_JOBS, "private funding capacity exhausted");
            payer
                .0
                .disk
                .insert(&mut tx, JOB, &tag, &[0; 32], &result.job)
                .await?;
            payer.0.disk.commit(tx).await?;
        }
        Ok(result)
    }
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
            "private funding capacity exceeded"
        );
        let mut jobs = Vec::new();
        for row in rows {
            let tag: Vec<u8> = row.try_get("tag")?;
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("private funding tag differs"))?;
            let raw: Vec<u8> = row.try_get("value")?;
            let job: Job = payer.0.disk.decode(JOB, &tag, &raw)?;
            let result = Self {
                payer: payer.clone(),
                job,
            };
            result.validate()?;
            ensure!(
                payer.0.disk.tag(JOB, &result.job.id)? == tag,
                "private funding tag differs"
            );
            jobs.push(result);
        }
        tx.rollback().await?;
        Ok(jobs)
    }
    pub fn id(&self) -> [u8; 32] {
        self.job.id
    }
    pub fn terms(&self) -> &Terms {
        &self.job.terms
    }
    pub async fn step<A: crate::Host>(&self, services: Services<'_, A>) -> Result<State> {
        let _gate = self.payer.0.purchases.lock().await;
        self.validate()?;
        let terms = &self.job.terms;
        self.payer
            .check_deposit_consent(self.job.id, terms.amount_ou, terms.window()?)
            .await?;
        ensure!(
            services.relayer.verifying_key().to_bytes() == terms.relayer_public,
            "private funding relayer differs"
        );
        if !services.index.sync(128).await?.complete {
            return Ok(State::Syncing);
        }
        let view = services.index.view().await?;
        let operation = Operation::Movement(self.job.id);
        let sequences = self
            .payer
            .native_sequences(&terms.relayer_public, operation)
            .await?;
        ensure!(
            sequences.len() <= 1,
            "funding has multiple native signatures"
        );
        if let Some(sequence) = sequences.first() {
            let attempt = self
                .payer
                .native_attempt(&terms.relayer_public, *sequence)
                .await?;
            if let Some(epoch) = self.payer.confirmed_native(&attempt).await? {
                ensure!(
                    self.payer.reconcile_native(&attempt, view.index()).await? == Some(epoch),
                    "private funding confirmation changed"
                );
                return Ok(State::Funded { epoch });
            }
            self.payer
                .broadcast(services.submission, &attempt, view.index())
                .await?;
            return Ok(State::Submitted {
                hash: attempt.hash()?,
            });
        }
        self.payer
            .prepare_deposit(
                self.job.id,
                terms.amount_ou,
                terms.window()?,
                view.index(),
                services.prover,
            )
            .await?;
        let attempt = self
            .payer
            .sign_native(operation, view.index(), services.relayer, terms.fees)
            .await?;
        self.payer
            .broadcast(services.submission, &attempt, view.index())
            .await?;
        Ok(State::Submitted {
            hash: attempt.hash()?,
        })
    }
}
