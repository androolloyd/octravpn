//! Authenticated, bounded private purchase RPC. Request/result mappings live in
//! the encrypted book; opening and quote reservation commit with their reply.
use super::{native, Channel, Receipt, SavedProof, Wallet};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octravpn_core::{
    payments::{Deployment, PrivateAction, PrivateResult, PrivateTarget, SignedPrivateRequest},
    Address, KeyPair,
};
use octravpn_node::payments::{Config, PrivatePurchases, Service};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, Transaction};
use std::sync::Arc;

const REQUEST: u8 = 4;

/// Local operator allocation limits, not payer funds or chain balances.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub max_channels: u32,
    pub max_requests: u32,
    pub max_ceiling_ou: u64,
    pub max_invoice_lifetime_ms: u64,
}
impl Policy {
    pub(in crate::vpn::payments::shielded) fn validate(self) -> Result<()> {
        ensure!(
            (1..=4096).contains(&self.max_channels)
                && (1..=65_536).contains(&self.max_requests)
                && self.max_ceiling_ou > 0
                && i64::try_from(self.max_ceiling_ou).is_ok()
                && (1..=86_400_000).contains(&self.max_invoice_lifetime_ms),
            "private RPC policy differs"
        );
        Ok(())
    }
}
pub(super) struct Reservation {
    tag: [u8; 32],
    digest: [u8; 32],
    pub(super) max_channels: u32,
    max_requests: u32,
    window: std::ops::Range<u64>,
}
impl Reservation {
    pub(super) fn check_time(&self, now: u64) -> Result<()> {
        ensure!(
            self.window.contains(&now),
            "private request is outside canonical window"
        );
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    digest: [u8; 32],
    result: PrivateResult,
}

impl Wallet {
    pub fn private_target(&self, operator: octravpn_core::PublicKey) -> Result<PrivateTarget> {
        ensure!(
            Address::from_pubkey(&operator.0) == self.0.source.directory.operator,
            "private RPC operator differs"
        );
        Ok(PrivateTarget {
            chain_origin: self.0.source.origin,
            pool: Deployment {
                domain: hex::encode(self.0.source.domain.digest()),
                program: octravpn_core::parse_native_address(self.0.source.circle())?,
            },
            directory: octravpn_core::parse_native_address(
                &self.0.source.directory.config.program,
            )?,
            operator,
        })
    }
    /// Explicit opt-in: operators choose allocation ceilings before accepting
    /// self-authenticated clients. Public routes and raw remote HTTP stay absent.
    pub async fn bind_purchase_service(&self, config: Config, policy: Policy) -> Result<Service> {
        policy.validate()?;
        self.bind_service(config)
            .await?
            .with_private_purchases(Arc::new(Purchases {
                wallet: self.clone(),
                policy,
            }))
    }
    pub(super) async fn cached(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        request: &Reservation,
    ) -> Result<Option<PrivateResult>> {
        let Some(record) = self
            .0
            .disk
            .load::<Recorded>(tx, REQUEST, &request.tag)
            .await?
        else {
            return Ok(None);
        };
        ensure!(
            record.digest == request.digest,
            "private request ID reused with different terms"
        );
        Ok(Some(record.result))
    }
    pub(super) async fn record(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        request: &Reservation,
        result: PrivateResult,
    ) -> Result<()> {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(REQUEST))
            .fetch_one(&mut **tx)
            .await?;
        ensure!(
            count < i64::from(request.max_requests),
            "private RPC capacity exhausted"
        );
        self.0
            .disk
            .insert(
                tx,
                REQUEST,
                &request.tag,
                &[0; 32],
                &Recorded {
                    digest: request.digest,
                    result,
                },
            )
            .await
    }
}
impl Receipt<'_> {
    /// Explicit private wire serialization, never a claim of finality.
    pub fn evidence(&self) -> Result<String> {
        ensure!(
            self.call.deposit_ou == 0 && self.call.withdraw_ou == 0,
            "private receipt has native value flow"
        );
        Ok(encode(&serde_json::to_vec(&SavedProof::from_receipt(
            *self,
        ))?))
    }
}
pub(super) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
pub(super) fn decode(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len() <= 43_692, "private RPC payload too large");
    let bytes = STANDARD.decode(text)?;
    ensure!(
        bytes.len() <= 32_768 && STANDARD.encode(&bytes) == text,
        "private RPC encoding differs"
    );
    Ok(bytes)
}
struct Purchases {
    wallet: Wallet,
    policy: Policy,
}

#[async_trait]
impl PrivatePurchases for Purchases {
    async fn execute(&self, signed: SignedPrivateRequest, operator: &KeyPair) -> Result<Vec<u8>> {
        signed.verify()?;
        let wallet = &self.wallet;
        wallet.0.disk.check()?;
        ensure!(
            signed.request.target == wallet.private_target(operator.public)?,
            "private RPC target differs"
        );
        let lease = crate::SnapshotLease::capture(wallet.0.source.directory.shared.clone())?;
        lease.with_current(crate::vpn::payments::PLAN_MAX_AGE, || Ok(()))?;
        let now = wallet
            .0
            .source
            .directory
            .canonical_time(lease.committed())
            .await?;
        wallet.0.source.state(lease.committed().state())?;
        signed.request.check_time(now)?;
        lease.with_current(crate::vpn::payments::PLAN_MAX_AGE, || Ok(()))?;
        let request = Reservation {
            tag: wallet.0.disk.tag(
                REQUEST,
                &[signed.receipt_key.0.as_slice(), &signed.request.id].concat(),
            )?,
            digest: signed.digest()?,
            max_channels: self.policy.max_channels,
            max_requests: self.policy.max_requests,
            window: signed.request.valid_from_ms..signed.request.expires_ms,
        };
        let mut tx = wallet.0.disk.begin().await?;
        if let Some(result) = wallet.cached(&mut tx, &request).await? {
            tx.rollback().await?;
            return Ok(serde_json::to_vec(&result)?);
        }
        tx.rollback().await?;
        match signed.request.action {
            PrivateAction::Open { offer, ceiling_ou } => {
                ensure!(
                    ceiling_ou <= self.policy.max_ceiling_ou,
                    "private ceiling exceeds operator policy"
                );
                wallet
                    .create_channel_record(offer, signed.receipt_key.0, ceiling_ou, Some(&request))
                    .await?;
            }
            PrivateAction::Quote {
                channel,
                class,
                bytes,
                validity_ms,
            } => {
                ensure!(
                    validity_ms <= self.policy.max_invoice_lifetime_ms,
                    "private lifetime exceeds operator policy"
                );
                own(wallet, channel, &signed.receipt_key.0).await?;
                wallet
                    .issue_record(
                        channel,
                        class,
                        bytes,
                        validity_ms,
                        &SigningKey::from_bytes(&operator.secret_bytes()),
                        Some(&request),
                    )
                    .await?;
            }
            PrivateAction::Receipt {
                channel,
                quote,
                evidence,
            } => {
                own(wallet, channel, &signed.receipt_key.0).await?;
                let proof: SavedProof = serde_json::from_slice(&decode(&evidence)?)?;
                ensure!(proof.quote == quote, "private receipt quote differs");
                let mut tx = wallet.0.disk.begin().await?;
                let reserved: super::Quote = wallet
                    .0
                    .disk
                    .load(&mut tx, super::QUOTE, &wallet.quote_tag(&quote)?)
                    .await?
                    .context("private quote missing")?;
                ensure!(
                    reserved.channel == channel,
                    "private quote belongs to another channel"
                );
                // Check bounds before the expensive canonical confirmation.
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                        .bind(i64::from(REQUEST))
                        .fetch_one(&mut *tx)
                        .await?;
                ensure!(
                    count < i64::from(self.policy.max_requests),
                    "private RPC capacity exhausted"
                );
                tx.rollback().await?;
                let membership = proof.membership()?;
                let call = proof.call()?;
                let received = wallet
                    .receive(
                        quote,
                        Receipt {
                            epoch: proof.epoch,
                            commitment: proof.commitment,
                            membership: &membership,
                            call: &call,
                            relayer: native(&proof.relayer)?,
                        },
                    )
                    .await?;
                let result = PrivateResult::Receipt {
                    channel,
                    quote,
                    credit_id: received.credit_id,
                };
                let mut tx = wallet.0.disk.begin().await?;
                // Concurrent delivery or cancellation between credit and reply
                // is harmless: receive() deduplicates the same canonical note.
                if wallet.cached(&mut tx, &request).await?.is_none() {
                    wallet.record(&mut tx, &request, result).await?;
                }
                wallet.0.disk.commit(tx).await?;
            }
        }
        let mut tx = wallet.0.disk.begin().await?;
        let result = wallet
            .cached(&mut tx, &request)
            .await?
            .context("private RPC result missing")?;
        tx.rollback().await?;
        Ok(serde_json::to_vec(&result)?)
    }
}
async fn own(wallet: &Wallet, id: u64, receipt: &[u8; 32]) -> Result<()> {
    let channel: Channel = wallet.load_channel(id).await?;
    ensure!(
        &channel.receipt_key == receipt,
        "private channel owner differs"
    );
    Ok(())
}
