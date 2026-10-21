//! Private, operator-signed finite purchase terms. Verification authenticates a
//! quote and consent; it does not authenticate money or authorize forwarding.
use anyhow::{ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"OctraVPN private invoice v2\0";
const CLAIMANT_DOMAIN: &[u8] = b"OctraVPN private claimant v2\0";
const MIB: u128 = 1_048_576;
const DAY_MS: u64 = 86_400_000;

/// An authenticated quote whose start has not reached the payer's canonical
/// clock. Waiting cannot extend its expiry or authorize a payment.
#[derive(Debug)]
pub struct NotYetValid;
impl std::fmt::Display for NotYetValid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private invoice awaits canonical time")
    }
}
impl std::error::Error for NotYetValid {}

/// Settlement identity is signed and independently accepted, so a native-claim
/// quote cannot be silently redirected into a pool or to another note owner.
#[derive(Clone, PartialEq, Eq)]
pub enum Settlement {
    NativeClaim,
    ShieldedPool {
        circle: [u8; 47],
        note_owner: [u8; 32],
    },
}

/// These records contain private payer/operator relationships. No Debug or
/// generic serialization is provided; the eventual transport must encrypt them.
#[derive(Clone)]
pub struct Invoice {
    pub chain_origin: [u8; 32],
    pub directory_circle: [u8; 47],
    pub operator_key: [u8; 32],
    pub bond_generation: u64,
    pub offer: u64,
    pub tariff_hash: [u8; 32],
    pub receipt_key: [u8; 32],
    /// One-time native claimant identity. Durable recipient reuse prevention
    /// belongs to the future operator wallet; a codec cannot enforce it.
    pub recipient_key: [u8; 32],
    pub settlement: Settlement,
    pub nonce: [u8; 32],
    pub traffic_class: u8,
    pub bytes: u64,
    pub rate_ou_per_mib: u64,
    pub valid_from_ms: u64,
    pub expires_ms: u64,
}

/// Caller-accepted limits and independently authenticated Circle offer facts.
/// Never construct this from the operator's response alone. canonical_ms is the
/// authenticated chain time, rather than the operator or local wall clock.
pub struct Consent {
    pub chain_origin: [u8; 32],
    pub directory_circle: [u8; 47],
    pub operator_key: [u8; 32],
    pub bond_generation: u64,
    pub offer: u64,
    pub tariff_hash: [u8; 32],
    pub receipt_key: [u8; 32],
    pub settlement: Settlement,
    pub traffic_class: u8,
    pub rate_ou_per_mib: u64,
    pub max_bytes: u64,
    pub max_cost_ou: u64,
    pub canonical_ms: u64,
    pub active_from_ms: u64,
    pub purchase_deadline_ms: Option<u64>,
}

pub struct SignedInvoice {
    pub invoice: Invoice,
    pub signature: [u8; 64],
    pub claimant_signature: [u8; 64],
}

fn public(raw: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(raw)?;
    ensure!(!key.is_weak(), "weak invoice identity");
    Ok(key)
}

impl Invoice {
    pub fn amount_ou(&self) -> Result<u64> {
        ensure!(
            self.bytes > 0
                && self.bytes <= i64::MAX as u64
                && self.rate_ou_per_mib <= i64::MAX as u64,
            "native invoice quantity out of range"
        );
        let amount = (u128::from(self.bytes) * u128::from(self.rate_ou_per_mib)).div_ceil(MIB);
        ensure!(
            amount <= i64::MAX as u128,
            "native invoice price out of range"
        );
        Ok(amount as u64)
    }

    pub fn recipient_address(&self) -> Result<[u8; 47]> {
        public(&self.recipient_key)?;
        let body = bs58::encode(Sha256::digest(self.recipient_key)).into_string();
        let address = format!(
            "oct{}{body}",
            "1".repeat(44_usize.saturating_sub(body.len()))
        );
        Ok(address.as_bytes().try_into()?)
    }

    pub fn recipient_view_public(&self) -> Result<[u8; 32]> {
        Ok(public(&self.recipient_key)?.to_montgomery().to_bytes())
    }

    fn preimage(&self) -> Result<Vec<u8>> {
        self.amount_ou()?;
        ensure!(
            self.chain_origin != [0; 32]
                && self.tariff_hash != [0; 32]
                && self.nonce != [0; 32]
                && self.bond_generation > 0,
            "incomplete private invoice"
        );
        ensure!(
            self.directory_circle.starts_with(b"oct")
                && self.directory_circle[3..].iter().all(|c| {
                    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)
                }),
            "invalid invoice directory Circle"
        );
        public(&self.operator_key)?;
        public(&self.receipt_key)?;
        public(&self.recipient_key)?;
        ensure!(
            self.operator_key != self.recipient_key && self.receipt_key != self.recipient_key,
            "private invoice requires a separate claimant identity"
        );
        ensure!(
            self.expires_ms > self.valid_from_ms && self.expires_ms - self.valid_from_ms <= DAY_MS,
            "invalid invoice validity window"
        );
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&self.chain_origin);
        bytes.extend_from_slice(&self.directory_circle);
        bytes.extend_from_slice(&self.operator_key);
        for number in [self.bond_generation, self.offer] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        bytes.extend_from_slice(&self.tariff_hash);
        bytes.extend_from_slice(&self.receipt_key);
        bytes.extend_from_slice(&self.recipient_key);
        bytes.extend_from_slice(&self.nonce);
        bytes.push(self.traffic_class);
        for number in [
            self.bytes,
            self.rate_ou_per_mib,
            self.valid_from_ms,
            self.expires_ms,
        ] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        match &self.settlement {
            Settlement::NativeClaim => bytes.push(0),
            Settlement::ShieldedPool { circle, note_owner } => {
                crate::pool::call::address(circle)?;
                use ark_ff::Zero;
                ensure!(
                    !crate::pool::decode_field(note_owner)?.is_zero(),
                    "invalid pool note owner"
                );
                bytes.push(1);
                bytes.extend_from_slice(circle);
                bytes.extend_from_slice(note_owner);
            }
        }
        Ok(bytes)
    }
}

impl SignedInvoice {
    /// Authenticates only the signed private terms, not consent or payment.
    pub fn id(&self) -> Result<[u8; 32]> {
        let preimage = self.invoice.preimage()?;
        self.check_signatures(&preimage)?;
        Ok(Sha256::digest(preimage).into())
    }

    /// Contains private relationships and amounts. Encrypt before persistence
    /// or transport; the returned plaintext buffer is wiped on drop.
    pub fn encode_private(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut bytes = self.invoice.preimage()?;
        self.check_signatures(&bytes)?;
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&self.claimant_signature);
        Ok(zeroize::Zeroizing::new(bytes))
    }

    pub fn decode_private(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 2048 && bytes.starts_with(DOMAIN),
            "invalid private invoice encoding"
        );
        let mut reader = InvoiceReader(&bytes[DOMAIN.len()..]);
        let invoice = Invoice {
            chain_origin: reader.take()?,
            directory_circle: reader.take()?,
            operator_key: reader.take()?,
            bond_generation: reader.number()?,
            offer: reader.number()?,
            tariff_hash: reader.take()?,
            receipt_key: reader.take()?,
            recipient_key: reader.take()?,
            nonce: reader.take()?,
            traffic_class: reader.take::<1>()?[0],
            bytes: reader.number()?,
            rate_ou_per_mib: reader.number()?,
            valid_from_ms: reader.number()?,
            expires_ms: reader.number()?,
            settlement: match reader.take::<1>()?[0] {
                0 => Settlement::NativeClaim,
                1 => Settlement::ShieldedPool {
                    circle: reader.take()?,
                    note_owner: reader.take()?,
                },
                _ => anyhow::bail!("invalid private invoice settlement encoding"),
            },
        };
        let signed = Self {
            invoice,
            signature: reader.take()?,
            claimant_signature: reader.take()?,
        };
        ensure!(reader.0.is_empty(), "trailing private invoice bytes");
        signed.id()?;
        Ok(signed)
    }

    fn check_signatures(&self, preimage: &[u8]) -> Result<()> {
        public(&self.invoice.operator_key)?
            .verify_strict(preimage, &Signature::from_bytes(&self.signature))?;
        public(&self.invoice.recipient_key)?.verify_strict(
            &claimant_preimage(preimage),
            &Signature::from_bytes(&self.claimant_signature),
        )?;
        Ok(())
    }
    pub fn sign(invoice: Invoice, operator: &SigningKey, claimant: &SigningKey) -> Result<Self> {
        ensure!(
            operator.verifying_key().to_bytes() == invoice.operator_key,
            "invoice signer differs"
        );
        ensure!(
            claimant.verifying_key().to_bytes() == invoice.recipient_key,
            "invoice claimant differs"
        );
        let preimage = invoice.preimage()?;
        let signature = operator.sign(&preimage).to_bytes();
        let claimant_signature = claimant.sign(&claimant_preimage(&preimage)).to_bytes();
        Ok(Self {
            invoice,
            signature,
            claimant_signature,
        })
    }

    /// Returns only the immutable quote ID. Actual canonical payment and a
    /// durable single-use output check are mandatory before minting capacity.
    pub fn verify(&self, consent: &Consent) -> Result<[u8; 32]> {
        let q = &self.invoice;
        let preimage = q.preimage()?;
        ensure!(
            q.chain_origin == consent.chain_origin
                && q.directory_circle == consent.directory_circle
                && q.operator_key == consent.operator_key
                && q.bond_generation == consent.bond_generation
                && q.offer == consent.offer
                && q.tariff_hash == consent.tariff_hash
                && q.receipt_key == consent.receipt_key
                && q.settlement == consent.settlement
                && q.traffic_class == consent.traffic_class
                && q.rate_ou_per_mib == consent.rate_ou_per_mib,
            "private invoice differs from accepted offer"
        );
        ensure!(
            q.bytes <= consent.max_bytes && q.amount_ou()? <= consent.max_cost_ou,
            "private invoice exceeds consent"
        );
        ensure!(
            q.valid_from_ms >= consent.active_from_ms && consent.canonical_ms < q.expires_ms,
            "private invoice is not currently purchasable"
        );
        if let Some(deadline) = consent.purchase_deadline_ms {
            ensure!(
                q.expires_ms <= deadline && consent.canonical_ms < deadline,
                "private invoice outlives the accepted rate notice"
            );
        }
        self.check_signatures(&preimage)?;
        if consent.canonical_ms < q.valid_from_ms {
            return Err(NotYetValid.into());
        }
        Ok(Sha256::digest(preimage).into())
    }
}

struct InvoiceReader<'a>(&'a [u8]);
impl InvoiceReader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        ensure!(self.0.len() >= N, "truncated private invoice");
        let (value, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(value.try_into()?)
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }
}

fn claimant_preimage(invoice: &[u8]) -> Vec<u8> {
    let mut bytes = CLAIMANT_DOMAIN.to_vec();
    bytes.extend_from_slice(&Sha256::digest(invoice));
    bytes
}

#[cfg(test)]
mod tests;
