//! Encrypted request outbox. No network operation may allocate a new request
//! ID implicitly after an ambiguous response.
use super::Payer;
use anyhow::{ensure, Context, Result};
use octravpn_core::{
    payments::{Deployment, SignedPrivateRequest},
    Address, PublicKey,
};

const REQUEST: u8 = 3;
impl Payer {
    /// Caller chooses a random nonzero ID once. Reusing it with changed terms
    /// is refused; the exact signed request survives process/HTTP failure.
    pub async fn record_request(
        &self,
        request: SignedPrivateRequest,
    ) -> Result<SignedPrivateRequest> {
        request.verify()?;
        let source = &self.1;
        ensure!(
            request.request.target.chain_origin == source.origin
                && request.request.target.pool
                    == Deployment {
                        domain: hex::encode(source.domain.digest()),
                        program: octravpn_core::parse_native_address(source.circle())?,
                    }
                && request.request.target.directory
                    == octravpn_core::parse_native_address(&source.directory.config.program)?
                && Address::from_pubkey(&request.request.target.operator.0)
                    == source.directory.operator,
            "private request differs from payer's accepted source"
        );
        self.0.disk.check()?;
        let tag = self.request_tag(request.request.id, request.receipt_key)?;
        let mut tx = self.0.disk.begin().await?;
        if let Some(previous) = self
            .0
            .disk
            .load::<SignedPrivateRequest>(&mut tx, REQUEST, &tag)
            .await?
        {
            ensure!(
                previous.digest()? == request.digest()?,
                "private outbox ID reused with different terms"
            );
            tx.rollback().await?;
            return Ok(previous);
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(REQUEST))
            .fetch_one(&mut *tx)
            .await?;
        ensure!(count < 65_536, "private outbox capacity exhausted");
        self.0
            .disk
            .insert(&mut tx, REQUEST, &tag, &[0; 32], &request)
            .await?;
        self.0.disk.commit(tx).await?;
        Ok(request)
    }
    pub async fn saved_request(
        &self,
        id: [u8; 32],
        receipt_key: PublicKey,
    ) -> Result<SignedPrivateRequest> {
        self.recorded_request(id, receipt_key)
            .await?
            .context("private outbox request missing")
    }
    pub(super) async fn recorded_request(
        &self,
        id: [u8; 32],
        receipt_key: PublicKey,
    ) -> Result<Option<SignedPrivateRequest>> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let result: Option<SignedPrivateRequest> = self
            .0
            .disk
            .load(&mut tx, REQUEST, &self.request_tag(id, receipt_key)?)
            .await?;
        tx.rollback().await?;
        let Some(result) = result else {
            return Ok(None);
        };
        result.verify()?;
        ensure!(
            result.request.id == id && result.receipt_key == receipt_key,
            "private outbox identity differs"
        );
        Ok(Some(result))
    }
    fn request_tag(&self, id: [u8; 32], receipt_key: PublicKey) -> Result<[u8; 32]> {
        self.0
            .disk
            .tag(REQUEST, &[receipt_key.0.as_slice(), &id].concat())
    }
}
