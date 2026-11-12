//! Authenticated, bounded private purchase RPC. Request/result mappings live in
//! the encrypted book; opening and quote reservation commit with their reply.
use super::{native, Channel, Receipt, SavedProof, Wallet};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octravpn_core::{
    payments::{Deployment, PrivateAction, PrivateResult, PrivateTarget, SignedPrivateRequest},
    Address, KeyPair, PublicKey,
};
use octravpn_node::payments::{Config, PrivatePurchases, Service};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, Transaction};
use std::sync::Arc;

const REQUEST: u8 = 4;

/// Local operator allocation limits, not payer funds or chain balances.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Off-chain pseudonymous receipt keys admitted by this operator. Empty
    /// or omitted lists refuse new allocations; signatures alone are not admission.
    #[serde(default)]
    pub allowed_receipt_keys: Vec<PublicKey>,
    /// Per-admitted-payer limits. Aggregate limits remain at most 4096/65536.
    pub max_channels: u32,
    pub max_requests: u32,
    pub max_ceiling_ou: u64,
    pub max_invoice_lifetime_ms: u64,
}
impl Policy {
    pub(in crate::vpn::payments::shielded) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4096).contains(&self.max_channels)
                && (1..=65_536).contains(&self.max_requests)
                && self.max_ceiling_ou > 0
                && i64::try_from(self.max_ceiling_ou).is_ok()
                && (1..=86_400_000).contains(&self.max_invoice_lifetime_ms),
            "private RPC policy differs"
        );
        let mut unique = std::collections::BTreeSet::new();
        for key in &self.allowed_receipt_keys {
            let public = ed25519_dalek::VerifyingKey::from_bytes(&key.0)?;
            ensure!(
                !public.is_weak() && unique.insert(key.0),
                "private admission key differs"
            );
        }
        let payers = self.allowed_receipt_keys.len().max(1) as u64;
        ensure!(
            u64::from(self.max_channels) * payers <= 4096
                && u64::from(self.max_requests) * payers <= 65_536,
            "private aggregate RPC capacity exceeds bound"
        );
        Ok(())
    }
    fn admit(&self, key: PublicKey) -> Result<()> {
        ensure!(
            self.allowed_receipt_keys.contains(&key),
            "private payer is not admitted"
        );
        Ok(())
    }
}
pub(super) struct Reservation {
    tag: [u8; 32],
    digest: [u8; 32],
    bucket: [u8; 32],
    now: u64,
    pub(super) receipt_key: [u8; 32],
    pub(super) max_channels: u32,
    pub(super) total_channels: u32,
    total_requests: u32,
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
    #[serde(default)]
    expires_ms: u64,
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
        record(&self.0.disk, tx, request, result).await
    }
}
async fn record(
    disk: &super::super::storage::Disk,
    tx: &mut Transaction<'_, Sqlite>,
    request: &Reservation,
    result: PrivateResult,
) -> Result<()> {
    request.check_time(request.now)?;
    // Only expired replay entries may be reclaimed. The request window is
    // checked against authenticated canonical time before reaching this book.
    // Bounded pages avoid materializing a payer's entire replay cache in RAM.
    let mut cursor = Vec::new();
    let mut live = 0_u32;
    loop {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT tag,value FROM wallet_records WHERE kind=? AND bucket=? AND tag>? ORDER BY tag LIMIT 64")
            .bind(i64::from(REQUEST)).bind(request.bucket.as_slice()).bind(&cursor)
            .fetch_all(&mut **tx).await?;
        if rows.is_empty() {
            break;
        }
        for (tag, raw) in rows {
            cursor.clone_from(&tag);
            let tag: [u8; 32] = tag
                .try_into()
                .map_err(|_| anyhow::anyhow!("private request tag differs"))?;
            let record: Recorded = disk.decode(REQUEST, &tag, &raw)?;
            if record.expires_ms != 0 && record.expires_ms <= request.now {
                sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=?")
                    .bind(i64::from(REQUEST))
                    .bind(tag.as_slice())
                    .execute(&mut **tx)
                    .await?;
            } else {
                live += 1;
            }
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
        .bind(i64::from(REQUEST))
        .fetch_one(&mut **tx)
        .await?;
    ensure!(
        live < request.max_requests && count < i64::from(request.total_requests),
        "private RPC capacity exhausted"
    );
    disk.insert(
        tx,
        REQUEST,
        &request.tag,
        &request.bucket,
        &Recorded {
            digest: request.digest,
            result,
            expires_ms: request.window.end,
        },
    )
    .await
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
        self.policy.admit(signed.receipt_key)?;
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
            bucket: wallet.0.disk.tag(REQUEST, &signed.receipt_key.0)?,
            now,
            receipt_key: signed.receipt_key.0,
            total_channels: self.policy.max_channels
                * self.policy.allowed_receipt_keys.len() as u32,
            total_requests: self.policy.max_requests
                * self.policy.allowed_receipt_keys.len() as u32,
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
                record(
                    &wallet.0.disk,
                    &mut tx,
                    &request,
                    PrivateResult::Receipt {
                        channel,
                        quote,
                        credit_id: [0; 32],
                    },
                )
                .await?;
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

#[cfg(test)]
mod security_tests {
    use super::*;
    use octravpn_core::sealed::Key;

    fn policy() -> Policy {
        Policy {
            allowed_receipt_keys: vec![
                KeyPair::from_secret_bytes(&[1; 32]).public,
                KeyPair::from_secret_bytes(&[2; 32]).public,
            ],
            max_channels: 1,
            max_requests: 1,
            max_ceiling_ou: 100,
            max_invoice_lifetime_ms: 1000,
        }
    }

    #[test]
    fn private_admission_is_explicit_and_aggregate_bounded() {
        let mut policy = policy();
        assert!(policy.validate().is_ok());
        assert!(policy.admit(policy.allowed_receipt_keys[0]).is_ok());
        assert!(policy
            .admit(KeyPair::from_secret_bytes(&[3; 32]).public)
            .is_err());
        let key = policy.allowed_receipt_keys[0];
        policy.allowed_receipt_keys.clear();
        assert!(policy.validate().is_ok());
        assert!(policy.admit(key).is_err());
        policy.allowed_receipt_keys = vec![key, key];
        assert!(policy.validate().is_err());
        policy = self::policy();
        policy.max_channels = 4096;
        assert!(policy.validate().is_err());
        policy = self::policy();
        policy.max_requests = 65_536;
        assert!(policy.validate().is_err());
        policy = self::policy();
        policy.allowed_receipt_keys = vec![PublicKey([0; 32])];
        assert!(policy.validate().is_err());
        let mut json = serde_json::to_value(self::policy()).unwrap();
        json.as_object_mut().unwrap().remove("allowed_receipt_keys");
        let missing: Policy = serde_json::from_value(json).unwrap();
        assert!(missing.admit(key).is_err());
    }

    fn request(
        disk: &super::super::super::storage::Disk,
        owner: u8,
        id: u8,
        now: u64,
    ) -> Reservation {
        Reservation {
            tag: disk.tag(REQUEST, &[owner, id]).unwrap(),
            digest: [id; 32],
            bucket: disk.tag(REQUEST, &[owner]).unwrap(),
            now,
            receipt_key: [owner; 32],
            max_channels: 1,
            total_channels: 2,
            max_requests: 1,
            total_requests: 2,
            window: now..now + 100,
        }
    }

    #[tokio::test]
    async fn private_request_quotas_are_isolated_persistent_and_expire_safely() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("book");
        let key = Key::from_bytes([3; 32]);
        let scope = [4; 32];
        let disk = super::super::super::storage::Disk::open(&path, key.clone(), scope, true)
            .await
            .unwrap();
        let result = || PrivateResult::Quote {
            channel: 0,
            invoice: "fixture".into(),
        };
        let a = request(&disk, 1, 1, 10);
        let b = request(&disk, 1, 2, 10);
        let c = request(&disk, 2, 3, 10);
        let mut tx = disk.begin().await.unwrap();
        record(&disk, &mut tx, &a, result()).await.unwrap();
        assert!(record(&disk, &mut tx, &b, result()).await.is_err());
        // The attacker's live entry cannot consume another admitted identity's slot.
        record(&disk, &mut tx, &c, result()).await.unwrap();
        disk.commit(tx).await.unwrap();
        disk.pool.close().await;
        drop(disk);
        let disk = super::super::super::storage::Disk::open(&path, key, scope, false)
            .await
            .unwrap();
        let mut tx = disk.begin().await.unwrap();
        assert!(record(&disk, &mut tx, &b, result()).await.is_err());
        let retained: Recorded = disk.load(&mut tx, REQUEST, &a.tag).await.unwrap().unwrap();
        assert_eq!(retained.digest, a.digest);
        assert_eq!(retained.expires_ms, 110);
        tx.rollback().await.unwrap();
        let expired = request(&disk, 1, 4, 110);
        let mut tx = disk.begin().await.unwrap();
        record(&disk, &mut tx, &expired, result()).await.unwrap();
        assert!(disk
            .load::<Recorded>(&mut tx, REQUEST, &a.tag)
            .await
            .unwrap()
            .is_none());
        assert!(disk
            .load::<Recorded>(&mut tx, REQUEST, &c.tag)
            .await
            .unwrap()
            .is_some());
        // Old signed requests fail their canonical window before cache/allocation.
        assert!(a.check_time(110).is_err());
        disk.commit(tx).await.unwrap();
        // Legacy ciphertext has no expiry: retain it rather than deleting replay protection.
        let old: Recorded = serde_json::from_value(serde_json::json!({
            "digest": vec![0_u8; 32], "result": result()
        }))
        .unwrap();
        assert_eq!(old.expires_ms, 0);
    }
    #[tokio::test]
    async fn private_request_pruning_pages_preserve_live_legacy_and_other_payers() {
        let directory = tempfile::tempdir().unwrap();
        let disk = super::super::super::storage::Disk::open(
            &directory.path().join("book"),
            Key::from_bytes([9; 32]),
            [10; 32],
            true,
        )
        .await
        .unwrap();
        let result = || PrivateResult::Quote {
            channel: 0,
            invoice: "fixture".into(),
        };
        let mut tx = disk.begin().await.unwrap();
        for id in 1..=65 {
            let old = request(&disk, 1, id, 10);
            disk.insert(
                &mut tx,
                REQUEST,
                &old.tag,
                &old.bucket,
                &Recorded {
                    digest: old.digest,
                    result: result(),
                    expires_ms: 110,
                },
            )
            .await
            .unwrap();
        }
        let legacy = request(&disk, 1, 66, 10);
        disk.insert(
            &mut tx,
            REQUEST,
            &legacy.tag,
            &legacy.bucket,
            &Recorded {
                digest: legacy.digest,
                result: result(),
                expires_ms: 0,
            },
        )
        .await
        .unwrap();
        let other = request(&disk, 2, 67, 10);
        disk.insert(
            &mut tx,
            REQUEST,
            &other.tag,
            &other.bucket,
            &Recorded {
                digest: other.digest,
                result: result(),
                expires_ms: 110,
            },
        )
        .await
        .unwrap();
        let mut fresh = request(&disk, 1, 68, 110);
        fresh.max_requests = 2;
        fresh.total_requests = 128;
        record(&disk, &mut tx, &fresh, result()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
            .bind(i64::from(REQUEST))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 3);
        assert!(disk
            .load::<Recorded>(&mut tx, REQUEST, &legacy.tag)
            .await
            .unwrap()
            .is_some());
        assert!(disk
            .load::<Recorded>(&mut tx, REQUEST, &other.tag)
            .await
            .unwrap()
            .is_some());
        disk.commit(tx).await.unwrap();
    }
}
