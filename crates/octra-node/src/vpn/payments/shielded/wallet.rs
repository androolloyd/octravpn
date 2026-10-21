//! Encrypted operator wallet and append-only, single-use purchase credits.
//! Issued claimant/spend keys derive from a durably reserved slot. SQLite never
//! receives plaintext invoices, identities, prices, keys or delivery counters.
pub(super) mod income;
mod recovery;
pub mod rpc;
mod transport;
use super::storage::Disk;
use super::{FundedPurchase, Inclusion, Limits, Pool};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_private_payments_experimental::{
    invoice::{Invoice, Settlement, SignedInvoice},
    native_stealth,
    pool::{self, call::Call, Membership, SpendKey},
};
use octravpn_core::{
    payments::{Deployment, PlanBinding, Tariff},
    sealed::Key,
    Address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const META: u8 = 0;
const CHANNEL: u8 = 1;
const QUOTE: u8 = 2;
const CREDIT: u8 = 3;
const ZERO: [u8; 32] = [0; 32];
const MAX_CREDITS: usize = 16_384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    version: u8,
    scope: [u8; 32],
    wallet_id: [u8; 32],
    next_slot: u64,
    next_channel: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    id: u64,
    receipt_key: [u8; 32],
    offer: u64,
    operator_generation: u64,
    tariff: Vec<u8>,
    budget_ou: u64,
    reserved_ou: u64,
    reserved_bytes: Vec<u64>,
    paid_ou: u64,
    totals: Vec<u64>,
    version: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Quote {
    channel: u64,
    slot: u64,
    invoice: Vec<u8>,
    credited: Option<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credit {
    channel: u64,
    slot: u64,
    invoice: Vec<u8>,
    credit_id: [u8; 32],
    entitled: bool,
    proof: SavedProof,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedProof {
    epoch: u64,
    commitment: [u8; 32],
    index: u32,
    siblings: Vec<[u8; 32]>,
    relayer: String,
    quote: [u8; 32],
    valid_from: u64,
    expires: u64,
    payout: String,
    boxes: [String; 2],
}

/// A receiver supplies inclusion material only. Terms and key slots come from
/// the wallet's own authenticated quote reservation, never a request's flags.
#[derive(Clone, Copy)]
pub struct Receipt<'a> {
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub membership: &'a Membership,
    pub call: &'a Call,
    pub relayer: [u8; 47],
}
pub struct ChannelInfo {
    pub binding: PlanBinding,
    pub receipt_key: [u8; 32],
    pub operator_generation: u64,
    pub tariff: Tariff,
    pub budget_ou: u64,
    pub paid_ou: u64,
    pub purchased: Vec<u64>,
    floor: FundingFloor,
}
#[derive(Clone, Copy, Default)]
struct FundingFloor {
    epoch: u64,
    count: u64,
    millis: u64,
}
impl FundingFloor {
    fn check(self, epoch: u64, count: u64, millis: u64) -> Result<()> {
        ensure!(
            epoch >= self.epoch && count >= self.count && millis >= self.millis,
            "private service publication predates confirmed funding"
        );
        Ok(())
    }
}
/// Duplicate delivery of a proof is idempotent. A second actual payment to the
/// same invoice is retained as an owned note, but does not buy its bytes twice.
pub struct Received {
    pub credit_id: [u8; 32],
    pub new_note: bool,
    pub new_capacity: bool,
}

struct Inner {
    source: Arc<Pool>,
    disk: Disk,
    key: Key,
    wallet_id: [u8; 32],
    verified: Mutex<BTreeMap<u64, (u64, FundingFloor)>>,
}
#[derive(Clone)]
pub struct Wallet(Arc<Inner>);

impl Wallet {
    pub async fn create(path: &Path, key: Key, source: Arc<Pool>) -> Result<Self> {
        Self::open(path, key, source, true).await
    }
    pub async fn resume(path: &Path, key: Key, source: Arc<Pool>) -> Result<Self> {
        Self::open(path, key, source, false).await
    }
    async fn open(path: &Path, key: Key, source: Arc<Pool>, create: bool) -> Result<Self> {
        let mut hash = Sha256::new();
        hash.update(b"Octranet private operator wallet v1\0");
        hash.update(source.origin);
        hash.update(source.address);
        hash.update(source.code_hash.as_bytes());
        hash.update(source.directory.config.program.as_bytes());
        hash.update(source.directory.operator.display().as_bytes());
        hash.update(source.directory.config.offer.to_be_bytes());
        let scope: [u8; 32] = hash.finalize().into();
        let key = key.derive(b"operator wallet", &scope)?;
        let disk = Disk::open(path, key.clone(), scope, create).await?;
        let mut tx = disk.begin().await?;
        let meta: Meta = if create {
            use rand::RngCore;
            let mut id = [0; 32];
            rand::rngs::OsRng.try_fill_bytes(&mut id)?;
            let meta = Meta {
                version: 1,
                scope,
                wallet_id: id,
                next_slot: 1,
                next_channel: 1,
            };
            disk.insert(&mut tx, META, &ZERO, &ZERO, &meta).await?;
            meta
        } else {
            disk.load(&mut tx, META, &ZERO)
                .await?
                .context("private wallet metadata is missing")?
        };
        ensure!(
            meta.version == 1
                && meta.scope == scope
                && meta.wallet_id != ZERO
                && meta.next_slot > 0
                && meta.next_channel > 0,
            "private wallet identity differs"
        );
        disk.commit(tx).await?;
        Ok(Self(Arc::new(Inner {
            source,
            disk,
            key,
            wallet_id: meta.wallet_id,
            verified: Mutex::new(BTreeMap::new()),
        })))
    }

    pub async fn create_channel(
        &self,
        offer: u64,
        receipt_key: [u8; 32],
        budget_ou: u64,
    ) -> Result<ChannelInfo> {
        self.create_channel_record(offer, receipt_key, budget_ou, None)
            .await
    }
    async fn create_channel_record(
        &self,
        offer: u64,
        receipt_key: [u8; 32],
        budget_ou: u64,
        request: Option<&rpc::Reservation>,
    ) -> Result<ChannelInfo> {
        self.0.disk.check()?;
        ensure!(
            budget_ou > 0 && i64::try_from(budget_ou).is_ok(),
            "private channel ceiling differs"
        );
        let public = ed25519_dalek::VerifyingKey::from_bytes(&receipt_key)?;
        ensure!(!public.is_weak(), "weak private channel receipt key");
        let offered = self.0.source.directory.offer(offer).await?;
        ensure!(
            offered.purchasable(),
            "private channel offer is unavailable"
        );
        if let Some(request) = request {
            request.check_time(offered.canonical_ms)?;
        }
        let mut tx = self.0.disk.begin().await?;
        if let Some(request) = request {
            if let Some(octravpn_core::payments::PrivateResult::Open { binding, .. }) =
                self.cached(&mut tx, request).await?
            {
                let channel: Channel = self
                    .0
                    .disk
                    .load(&mut tx, CHANNEL, &self.channel_tag(binding.plan)?)
                    .await?
                    .context("private channel missing")?;
                tx.rollback().await?;
                return self.info(&channel);
            }
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM wallet_records WHERE kind=?")
                .bind(i64::from(CHANNEL))
                .fetch_one(&mut *tx)
                .await?;
            ensure!(
                count < i64::from(request.max_channels),
                "private channel capacity exhausted"
            );
        }
        let mut meta: Meta = self
            .0
            .disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("private wallet metadata missing")?;
        let id = meta.next_channel;
        meta.next_channel = meta
            .next_channel
            .checked_add(1)
            .context("private channel IDs exhausted")?;
        let channel = Channel {
            id,
            receipt_key,
            offer,
            operator_generation: offered.operator_generation,
            tariff: offered.tariff.canonical_bytes()?,
            budget_ou,
            reserved_ou: 0,
            paid_ou: 0,
            reserved_bytes: vec![0; offered.tariff.classes().len()],
            totals: vec![0; offered.tariff.classes().len()],
            version: 0,
        };
        self.0
            .disk
            .insert(&mut tx, CHANNEL, &self.channel_tag(id)?, &ZERO, &channel)
            .await?;
        self.0.disk.replace(&mut tx, META, &ZERO, &meta).await?;
        if let Some(request) = request {
            let info = self.info(&channel)?;
            self.record(
                &mut tx,
                request,
                octravpn_core::payments::PrivateResult::Open {
                    binding: Box::new(info.binding),
                    operator_generation: info.operator_generation,
                    tariff: info.tariff,
                    ceiling_ou: info.budget_ou,
                },
            )
            .await?;
        }
        self.0.disk.commit(tx).await?;
        offered.with_current(|_| Ok(()))?;
        self.info(&channel)
    }

    /// Reserves a unique key slot and this invoice's byte/cost ceiling before
    /// returning its signatures. A cancelled/ambiguous call cannot reuse a
    /// publicly issued claimant. Quote ceilings do not lock any native OCT.
    pub async fn issue(
        &self,
        channel_id: u64,
        class: u8,
        bytes: u64,
        validity_ms: u64,
        operator: &SigningKey,
    ) -> Result<SignedInvoice> {
        self.issue_record(channel_id, class, bytes, validity_ms, operator, None)
            .await
    }
    async fn issue_record(
        &self,
        channel_id: u64,
        class: u8,
        bytes: u64,
        validity_ms: u64,
        operator: &SigningKey,
        request: Option<&rpc::Reservation>,
    ) -> Result<SignedInvoice> {
        self.0.disk.check()?;
        let initial = self.load_channel(channel_id).await?;
        let offered = self.0.source.directory.offer(initial.offer).await?;
        ensure!(
            offered.purchasable()
                && operator.verifying_key().to_bytes()
                    == offered.receipt_key.context("operator key missing")?.0,
            "private quote operator differs"
        );
        if let Some(request) = request {
            request.check_time(offered.canonical_ms)?;
        }
        ensure!(
            (1..=86_400_000).contains(&validity_ms),
            "private quote lifetime differs"
        );
        let rate = offered
            .tariff
            .classes()
            .get(usize::from(class))
            .context("private quote class missing")?
            .rate_ou_per_mib;
        let mut tx = self.0.disk.begin().await?;
        if let Some(request) = request {
            if let Some(octravpn_core::payments::PrivateResult::Quote { invoice, .. }) =
                self.cached(&mut tx, request).await?
            {
                tx.rollback().await?;
                return SignedInvoice::decode_private(&rpc::decode(&invoice)?);
            }
        }
        let mut channel: Channel = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &self.channel_tag(channel_id)?)
            .await?
            .context("private channel missing")?;
        ensure!(
            channel.operator_generation == offered.operator_generation
                && channel.tariff == offered.tariff.canonical_bytes()?,
            "private channel terms changed"
        );
        let mut meta: Meta = self
            .0
            .disk
            .load(&mut tx, META, &ZERO)
            .await?
            .context("private wallet metadata missing")?;
        let slot = meta.next_slot;
        meta.next_slot = slot.checked_add(1).context("private key slots exhausted")?;
        let (spend, claimant) = self.credentials(slot)?;
        let context = [self.0.wallet_id.as_slice(), &slot.to_be_bytes()].concat();
        let nonce = *self.0.key.derive_bytes(b"invoice nonce", &context)?;
        let expires = offered
            .canonical_ms
            .checked_add(validity_ms)
            .context("private quote clock overflow")?;
        let invoice = Invoice {
            chain_origin: self.0.source.origin,
            directory_circle: native(&self.0.source.directory.config.program)?,
            operator_key: operator.verifying_key().to_bytes(),
            bond_generation: offered.operator_generation,
            offer: channel.offer,
            tariff_hash: hex::decode(&offered.manifest_hash)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("tariff hash size differs"))?,
            receipt_key: channel.receipt_key,
            recipient_key: claimant.verifying_key().to_bytes(),
            settlement: Settlement::ShieldedPool {
                circle: self.0.source.address,
                note_owner: pool::encode_field(spend.owner(self.0.source.domain)),
            },
            nonce,
            traffic_class: class,
            bytes,
            rate_ou_per_mib: rate,
            valid_from_ms: offered.canonical_ms,
            expires_ms: if offered.offer_end_ms == 0 {
                expires
            } else {
                expires.min(offered.offer_end_ms)
            },
        };
        let amount = invoice.amount_ou()?;
        ensure!(
            amount > 0,
            "zero-price traffic uses a free grant, not a paid note"
        );
        channel.reserved_ou = channel
            .reserved_ou
            .checked_add(amount)
            .context("private quote ceiling overflow")?;
        ensure!(
            channel.reserved_ou <= channel.budget_ou,
            "private channel quote ceiling exhausted"
        );
        let reserved = channel
            .reserved_bytes
            .get_mut(usize::from(class))
            .context("private quote counter shape differs")?;
        *reserved = reserved
            .checked_add(bytes)
            .context("private quote byte ceiling exhausted")?;
        let signed = SignedInvoice::sign(invoice, operator, &claimant)?;
        let id = signed.id()?;
        let quote = Quote {
            channel: channel_id,
            slot,
            invoice: signed.encode_private()?.to_vec(),
            credited: None,
        };
        self.0
            .disk
            .insert(
                &mut tx,
                QUOTE,
                &self.quote_tag(&id)?,
                &self.channel_tag(channel_id)?,
                &quote,
            )
            .await?;
        self.0
            .disk
            .replace(&mut tx, CHANNEL, &self.channel_tag(channel_id)?, &channel)
            .await?;
        self.0.disk.replace(&mut tx, META, &ZERO, &meta).await?;
        if let Some(request) = request {
            self.record(
                &mut tx,
                request,
                octravpn_core::payments::PrivateResult::Quote {
                    channel: channel_id,
                    invoice: rpc::encode(&signed.encode_private()?),
                },
            )
            .await?;
        }
        self.0.disk.commit(tx).await?;
        offered.with_current(|_| Ok(()))?;
        Ok(signed)
    }

    pub async fn receive(&self, quote_id: [u8; 32], receipt: Receipt<'_>) -> Result<Received> {
        self.0.disk.check()?;
        ensure!(
            receipt.call.deposit_ou == 0 && receipt.call.withdraw_ou == 0,
            "private receipt has native value flow"
        );
        let mut tx = self.0.disk.begin().await?;
        let quote: Quote = self
            .0
            .disk
            .load(&mut tx, QUOTE, &self.quote_tag(&quote_id)?)
            .await?
            .context("private invoice was not reserved")?;
        let channel: Channel = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &self.channel_tag(quote.channel)?)
            .await?
            .context("private channel missing")?;
        tx.rollback().await?;
        let signed = SignedInvoice::decode_private(&quote.invoice)?;
        ensure!(signed.id()? == quote_id, "private invoice identity differs");
        let proof = SavedProof::from_receipt(receipt);
        let funded = self.verify(&channel, quote.slot, &signed, &proof).await?;
        let tag = self.0.disk.tag(CREDIT, &funded.credit_id)?;
        let mut tx = self.0.disk.begin().await?;
        if let Some(previous) = self.0.disk.load::<Credit>(&mut tx, CREDIT, &tag).await? {
            ensure!(
                previous.channel == quote.channel
                    && previous.invoice == quote.invoice
                    && previous.credit_id == funded.credit_id,
                "private credit already belongs elsewhere"
            );
            tx.rollback().await?;
            return Ok(Received {
                credit_id: funded.credit_id,
                new_note: false,
                new_capacity: false,
            });
        }
        let mut latest: Quote = self
            .0
            .disk
            .load(&mut tx, QUOTE, &self.quote_tag(&quote_id)?)
            .await?
            .context("private quote disappeared")?;
        let mut channel: Channel = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &self.channel_tag(quote.channel)?)
            .await?
            .context("private channel disappeared")?;
        let entitled = latest.credited.is_none();
        if entitled {
            let class = usize::from(funded.traffic_class);
            let total = channel
                .totals
                .get_mut(class)
                .context("private credit class differs")?;
            *total = total
                .checked_add(funded.bytes)
                .context("private purchased byte overflow")?;
            channel.paid_ou = channel
                .paid_ou
                .checked_add(funded.amount_ou)
                .context("private credit price overflow")?;
            ensure!(
                channel.paid_ou <= channel.reserved_ou && channel.reserved_ou <= channel.budget_ou,
                "private quote ceiling accounting differs"
            );
            latest.credited = Some(funded.credit_id);
            self.0
                .disk
                .replace(&mut tx, QUOTE, &self.quote_tag(&quote_id)?, &latest)
                .await?;
        }
        channel.version = channel
            .version
            .checked_add(1)
            .context("private credit version exhausted")?;
        let credit = Credit {
            channel: quote.channel,
            slot: quote.slot,
            invoice: quote.invoice,
            credit_id: funded.credit_id,
            entitled,
            proof,
        };
        self.0
            .disk
            .insert(
                &mut tx,
                CREDIT,
                &tag,
                &self.channel_tag(channel.id)?,
                &credit,
            )
            .await?;
        self.0
            .disk
            .replace(&mut tx, CHANNEL, &self.channel_tag(channel.id)?, &channel)
            .await?;
        self.0.disk.commit(tx).await?;
        self.0.verified.lock().await.remove(&channel.id);
        Ok(Received {
            credit_id: funded.credit_id,
            new_note: true,
            new_capacity: entitled,
        })
    }

    /// Ciphertext integrity is not funding authority. A reopened wallet checks
    /// canonical note proofs lazily per channel before returning byte floors.
    pub async fn channel(&self, id: u64) -> Result<ChannelInfo> {
        self.0.disk.check()?;
        let mut tx = self.0.disk.begin().await?;
        let channel: Channel = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &self.channel_tag(id)?)
            .await?
            .context("private channel missing")?;
        let cached = self.0.verified.lock().await.get(&id).copied();
        if let Some((_, floor)) = cached.filter(|(version, _)| *version == channel.version) {
            tx.rollback().await?;
            let mut info = self.info(&channel)?;
            info.floor = floor;
            return Ok(info);
        }
        let mut totals = vec![0_u64; channel.totals.len()];
        let mut paid = 0_u64;
        let mut seen = BTreeSet::new();
        let mut count = 0_u64;
        let mut floor = FundingFloor::default();
        let tag = self.channel_tag(id)?;
        ensure!(
            channel.version <= MAX_CREDITS as u64,
            "private channel credit limit exceeded"
        );
        let rows =
            sqlx::query("SELECT tag,value FROM wallet_records WHERE kind=? AND bucket=? LIMIT ?")
                .bind(i64::from(CREDIT))
                .bind(tag.as_slice())
                .bind(i64::try_from(MAX_CREDITS + 1)?)
                .fetch_all(&mut *tx)
                .await?;
        ensure!(
            rows.len() <= MAX_CREDITS,
            "private channel credit limit exceeded"
        );
        // Verification may read encrypted historical witnesses from this same
        // single-connection journal. Release the read transaction first.
        tx.rollback().await?;
        for row in rows {
            let key: Vec<u8> = row.try_get("tag")?;
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| anyhow::anyhow!("private credit tag differs"))?;
            let raw: Vec<u8> = row.try_get("value")?;
            let credit: Credit = self.0.disk.decode(CREDIT, &key, &raw)?;
            ensure!(credit.channel == id, "private credit channel differs");
            let signed = SignedInvoice::decode_private(&credit.invoice)?;
            let funded = self
                .verify(&channel, credit.slot, &signed, &credit.proof)
                .await?;
            ensure!(
                funded.credit_id == credit.credit_id
                    && self.0.disk.tag(CREDIT, &funded.credit_id)? == key,
                "private credit identity differs"
            );
            floor.epoch = floor.epoch.max(funded.epoch);
            floor.count = floor.count.max(u64::from(credit.proof.index) + 1);
            floor.millis = floor.millis.max(funded.purchased_ms);
            if credit.entitled {
                ensure!(seen.insert(funded.quote), "private invoice credited twice");
                let total = totals
                    .get_mut(usize::from(funded.traffic_class))
                    .context("private credit class missing")?;
                *total = total
                    .checked_add(funded.bytes)
                    .context("private credit byte overflow")?;
                paid = paid
                    .checked_add(funded.amount_ou)
                    .context("private credit total overflow")?;
            }
            count = count
                .checked_add(1)
                .context("private credit count overflow")?;
        }
        ensure!(
            count == channel.version && totals == channel.totals && paid == channel.paid_ou,
            "private channel credit history differs"
        );
        let mut tx = self.0.disk.begin().await?;
        let latest: Channel = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &tag)
            .await?
            .context("private channel disappeared")?;
        ensure!(
            latest == channel,
            "private channel changed during verification; retry"
        );
        tx.rollback().await?;
        self.0
            .verified
            .lock()
            .await
            .insert(id, (channel.version, floor));
        let mut info = self.info(&channel)?;
        info.floor = floor;
        Ok(info)
    }

    pub async fn open_meter(
        &self,
        id: u64,
        path: PathBuf,
        existing_only: bool,
    ) -> Result<Arc<octravpn_node::payment_meter::Meter>> {
        let info = self.channel(id).await?;
        octravpn_node::payment_meter::Meter::open_private(
            path,
            info.binding,
            info.tariff,
            info.budget_ou,
            info.purchased,
            self.meter_key()?,
            existing_only,
        )
        .await
    }
    fn meter_key(&self) -> Result<Key> {
        self.0.key.derive(b"wallet meters", &self.0.wallet_id)
    }
    pub async fn reconcile_meter(
        &self,
        id: u64,
        meter: &Arc<octravpn_node::payment_meter::Meter>,
    ) -> Result<()> {
        let info = self.channel(id).await?;
        ensure!(
            meter.binding() == &info.binding
                && meter.tariff() == &info.tariff
                && meter.budget_ou() == info.budget_ou,
            "private meter binding differs"
        );
        meter.reconcile(info.purchased).await
    }
    async fn load_channel(&self, id: u64) -> Result<Channel> {
        let mut tx = self.0.disk.begin().await?;
        let result = self
            .0
            .disk
            .load(&mut tx, CHANNEL, &self.channel_tag(id)?)
            .await?
            .context("private channel missing")?;
        tx.rollback().await?;
        Ok(result)
    }
    fn channel_tag(&self, id: u64) -> Result<[u8; 32]> {
        self.0.disk.tag(CHANNEL, &id.to_be_bytes())
    }
    fn quote_tag(&self, id: &[u8; 32]) -> Result<[u8; 32]> {
        self.0.disk.tag(QUOTE, id)
    }
    fn info(&self, channel: &Channel) -> Result<ChannelInfo> {
        let tariff = Tariff::from_bytes(&channel.tariff)?;
        ensure!(
            tariff.canonical_bytes()? == channel.tariff
                && channel.totals.len() == tariff.classes().len()
                && channel.reserved_bytes.len() == channel.totals.len()
                && channel
                    .totals
                    .iter()
                    .zip(&channel.reserved_bytes)
                    .all(|(paid, reserved)| paid <= reserved)
                && channel.paid_ou <= channel.reserved_ou
                && channel.reserved_ou <= channel.budget_ou
                && tariff.total_charge(&channel.totals)? <= channel.paid_ou,
            "private channel accounting differs"
        );
        Ok(ChannelInfo {
            binding: PlanBinding {
                deployment: Deployment {
                    domain: hex::encode(self.0.source.domain.digest()),
                    program: octravpn_core::parse_native_address(std::str::from_utf8(
                        &self.0.source.address,
                    )?)?,
                },
                payer: Address::from_pubkey(&channel.receipt_key),
                generation: 1,
                plan: channel.id,
                offer: channel.offer,
                manifest_hash: tariff.hash_hex()?,
            },
            receipt_key: channel.receipt_key,
            operator_generation: channel.operator_generation,
            tariff,
            budget_ou: channel.budget_ou,
            paid_ou: channel.paid_ou,
            purchased: channel.totals.clone(),
            floor: FundingFloor::default(),
        })
    }
    fn credentials(&self, slot: u64) -> Result<(SpendKey, SigningKey)> {
        let context = [self.0.wallet_id.as_slice(), &slot.to_be_bytes()].concat();
        let seed = self.0.key.derive_bytes(b"claimant", &context)?;
        let claimant = SigningKey::from_bytes(&seed);
        for attempt in 0_u32..256 {
            let material = self.0.key.derive_bytes(
                b"spend",
                &[context.as_slice(), &attempt.to_be_bytes()].concat(),
            )?;
            if let Ok(spend) = SpendKey::from_bytes(&material) {
                return Ok((spend, claimant));
            }
        }
        anyhow::bail!("private spend key derivation exhausted")
    }
    async fn verify(
        &self,
        channel: &Channel,
        slot: u64,
        signed: &SignedInvoice,
        proof: &SavedProof,
    ) -> Result<FundedPurchase> {
        let (spend, claimant) = self.credentials(slot)?;
        ensure!(
            signed.invoice.recipient_key == claimant.verifying_key().to_bytes()
                && signed.invoice.receipt_key == channel.receipt_key
                && signed.invoice.offer == channel.offer
                && signed.invoice.bond_generation == channel.operator_generation,
            "private reserved quote differs"
        );
        let membership = proof.membership()?;
        let call = proof.call()?;
        let seed = Zeroizing::new(claimant.to_bytes());
        let view = native_stealth::view_secret(&seed);
        let tariff = Tariff::from_bytes(&channel.tariff)?;
        let limits = Limits {
            receipt_key: channel.receipt_key,
            traffic_class: signed.invoice.traffic_class,
            max_bytes: signed.invoice.bytes,
            max_cost_ou: signed.invoice.amount_ou()?,
        };
        let input = Inclusion {
            epoch: proof.epoch,
            commitment: proof.commitment,
            membership: &membership,
            call: &call,
            relayer: native(&proof.relayer)?,
            invoice: signed,
            tariff: &tariff,
            limits: &limits,
            spend_key: &spend,
            view_secret: &view,
        };
        if proof.epoch <= self.0.source.directory.history.anchor().epoch.0 {
            let witness = self
                .recovery_proof(proof.epoch)
                .await?
                .context("portable evidence missing below retained history floor")?;
            self.0.source.confirm_recovered(input, &witness).await
        } else {
            self.0.source.confirm(input).await
        }
    }
}

impl SavedProof {
    fn from_receipt(receipt: Receipt<'_>) -> Self {
        Self {
            epoch: receipt.epoch,
            commitment: receipt.commitment,
            index: receipt.membership.index,
            siblings: receipt
                .membership
                .siblings
                .iter()
                .copied()
                .map(pool::encode_field)
                .collect(),
            relayer: String::from_utf8_lossy(&receipt.relayer).into_owned(),
            quote: receipt.call.quote,
            valid_from: receipt.call.valid_from_ms,
            expires: receipt.call.expires_ms,
            payout: String::from_utf8_lossy(&receipt.call.payout).into_owned(),
            boxes: receipt.call.boxes.clone(),
        }
    }
    fn membership(&self) -> Result<Membership> {
        ensure!(
            self.siblings.len() == pool::NOTE_DEPTH,
            "private note path depth differs"
        );
        let siblings = self
            .siblings
            .iter()
            .map(pool::decode_field)
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("private note path shape differs"))?;
        Ok(Membership {
            index: self.index,
            siblings,
        })
    }
    fn call(&self) -> Result<Call> {
        Ok(Call {
            quote: self.quote,
            valid_from_ms: self.valid_from,
            expires_ms: self.expires,
            payout: native(&self.payout)?,
            deposit_ou: 0,
            withdraw_ou: 0,
            boxes: self.boxes.clone(),
        })
    }
}
fn native(text: &str) -> Result<[u8; 47]> {
    octravpn_core::parse_native_address(text)?;
    Ok(text.as_bytes().try_into()?)
}
