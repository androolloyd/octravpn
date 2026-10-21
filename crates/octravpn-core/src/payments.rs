//! Application payment authorizations and immutable traffic tariffs.
//! These types do not establish canonical state, packet delivery or persistence.
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::{b64, parse_native_address, sig, Address, CoreError, KeyPair, PublicKey, Signature};

mod budget;
mod connection;
mod private_purchase;
mod service_receipt;
mod shielded_status;
mod tariff;
pub use budget::{Budget, Reservation};
pub use connection::{Connect, PlanBinding, SignedConnect, SignedStatus, Status};
pub use private_purchase::{
    PrivateAction, PrivateExchange, PrivateRequest, PrivateResult, PrivateTarget,
    SignedPrivateReply, SignedPrivateRequest,
};
pub use service_receipt::{ServiceReceipt, SignedServiceReceipt};
pub use shielded_status::{ShieldedStatus, SignedShieldedStatus};
pub use tariff::{Direction, IpPrefix, Protocol, Selector, Tariff, TrafficClass};

pub const BYTES_PER_MIB: u64 = 1_048_576;
pub const MAX_CLASSES: usize = 32;
pub const MAX_SELECTORS: usize = 256;
pub const MAX_TARIFF_BYTES: usize = 65_536;

/// No current service view or control transport. This grants no authority and
/// cannot extend a client's last authenticated canonical-clock deadline.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unavailable(String);
impl Unavailable {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Octranet payment data: {0}")]
    Invalid(&'static str),
    #[error("unknown traffic class {0}")]
    UnknownClass(u8),
    #[error("traffic charge or byte counter overflow")]
    Overflow,
    #[error("traffic budget exhausted: required {required}, budget {budget}")]
    BudgetExceeded { required: u64, budget: u64 },
    #[error(transparent)]
    Crypto(#[from] CoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Packet(#[from] crate::ip_tunnel::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

fn hash(value: &str) -> Result<()> {
    crate::v3_canonical::check_hash(value, || Error::Invalid("expected lowercase SHA256"))
}
fn native(value: &Address) -> Result<()> {
    if parse_native_address(value.display())? != *value {
        return Err(Error::Invalid("address raw/display mismatch"));
    }
    Ok(())
}
fn deserialize_hash<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    hash(&value).map_err(D::Error::custom)?;
    Ok(value)
}
fn deserialize_positive<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(D::Error::custom("expected nonzero uint64"));
    }
    Ok(value)
}
fn deserialize_class<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u8, D::Error> {
    let value = u8::deserialize(deserializer)?;
    if usize::from(value) >= MAX_CLASSES {
        return Err(D::Error::custom("traffic class exceeds bound"));
    }
    Ok(value)
}

mod native_address {
    use super::{native, Address, Deserializer, Serializer};
    use serde::{de::Error as _, Deserialize};
    pub(super) fn serialize<S: Serializer>(
        value: &Address,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        native(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(value.display())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Address, D::Error> {
        super::parse_native_address(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
mod public_key {
    use super::{b64, Deserializer, PublicKey, Serializer};
    use serde::{de::Error as _, Deserialize};
    pub(super) fn serialize<S: Serializer>(
        value: &PublicKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64::encode(value.0))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<PublicKey, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = b64::decode(&text).map_err(D::Error::custom)?;
        let raw =
            <[u8; 32]>::try_from(bytes).map_err(|_| D::Error::custom("expected 32-byte key"))?;
        if b64::encode(raw) != text {
            return Err(D::Error::custom("noncanonical public key encoding"));
        }
        Ok(PublicKey(raw))
    }
}
mod signature {
    use super::{b64, Deserializer, Serializer, Signature};
    use serde::{de::Error as _, Deserialize};
    pub(super) fn serialize<S: Serializer>(
        value: &Signature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64::encode(value.0))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Signature, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = b64::decode(&text).map_err(D::Error::custom)?;
        let raw = <[u8; 64]>::try_from(bytes)
            .map_err(|_| D::Error::custom("expected 64-byte signature"))?;
        if b64::encode(raw) != text {
            return Err(D::Error::custom("noncanonical signature encoding"));
        }
        Ok(Signature(raw))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    #[serde(deserialize_with = "deserialize_hash")]
    pub domain: String,
    #[serde(with = "native_address")]
    pub program: Address,
}
impl Deployment {
    pub fn validate(&self) -> Result<()> {
        hash(&self.domain)?;
        native(&self.program)
    }

    pub fn registration_message(&self, payer: &Address, generation: u64) -> Result<String> {
        self.validate()?;
        native(payer)?;
        if generation == 0 {
            return Err(Error::Invalid("zero account generation"));
        }
        Ok(format!(
            "Octranet register v1|{}|{}|{}|{generation}",
            self.domain, self.program, payer
        ))
    }
}

/// Payer authorization to buy a cumulative byte allowance for one traffic class.
/// The wire field name remains `usage`; this is not evidence of packet delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub deployment: Deployment,
    #[serde(with = "native_address")]
    pub payer: Address,
    #[serde(deserialize_with = "deserialize_positive")]
    pub generation: u64,
    pub plan: u64,
    pub offer: u64,
    #[serde(deserialize_with = "deserialize_hash")]
    pub manifest_hash: String,
    #[serde(deserialize_with = "deserialize_class")]
    pub traffic_class: u8,
    #[serde(deserialize_with = "deserialize_positive")]
    pub sequence: u64,
    pub total_bytes: u64,
}
impl Usage {
    pub fn binding(&self) -> PlanBinding {
        PlanBinding {
            deployment: self.deployment.clone(),
            payer: self.payer.clone(),
            generation: self.generation,
            plan: self.plan,
            offer: self.offer,
            manifest_hash: self.manifest_hash.clone(),
        }
    }

    pub fn from_binding(
        binding: PlanBinding,
        traffic_class: u8,
        sequence: u64,
        total_bytes: u64,
    ) -> Result<Self> {
        let usage = Self {
            deployment: binding.deployment,
            payer: binding.payer,
            generation: binding.generation,
            plan: binding.plan,
            offer: binding.offer,
            manifest_hash: binding.manifest_hash,
            traffic_class,
            sequence,
            total_bytes,
        };
        usage.validate()?;
        Ok(usage)
    }

    pub fn validate(&self) -> Result<()> {
        self.binding().validate()?;
        if self.sequence == 0 {
            return Err(Error::Invalid("zero receipt sequence"));
        }
        if usize::from(self.traffic_class) >= MAX_CLASSES {
            return Err(Error::UnknownClass(self.traffic_class));
        }
        Ok(())
    }

    /// Exact raw ASCII input to AML ed25519_ok; there is no prehash or JSON.
    pub fn signing_message(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "Octranet prepaid v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.deployment.domain,
            self.deployment.program,
            self.payer,
            self.generation,
            self.plan,
            self.offer,
            self.manifest_hash,
            self.traffic_class,
            self.sequence,
            self.total_bytes
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUsage {
    pub usage: Usage,
    #[serde(with = "public_key")]
    pub receipt_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}
impl SignedUsage {
    pub fn sign(usage: Usage, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(usage.signing_message()?.as_bytes());
        Ok(Self {
            usage,
            receipt_key: key.public,
            signature,
        })
    }

    pub fn verify(&self) -> Result<()> {
        verify_authorization(
            &self.receipt_key,
            self.usage.signing_message()?.as_bytes(),
            &self.signature,
        )
    }

    /// Ordinary application call arguments; caller still verifies current
    /// canonical account key, generation, plan, tariff and available budget.
    pub fn claim_params(&self) -> Result<serde_json::Value> {
        self.verify()?;
        Ok(serde_json::json!([
            self.usage.plan,
            self.usage.traffic_class,
            self.usage.sequence,
            self.usage.total_bytes,
            b64::encode(self.signature.0)
        ]))
    }
}

fn verify_authorization(key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    // Match the adopted native key guard plus normal Ed25519 verification.
    // verify_strict additionally rejects R encodings accepted by that VM.
    let mut y = key.0;
    y[31] &= 0x7f;
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if y.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less
        || CompressedEdwardsY(key.0)
            .decompress()
            .is_none_or(|point| point.is_small_order())
    {
        return Err(Error::Invalid("unsafe receipt public key"));
    }
    sig::verify(key, message, signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn usage() -> Usage {
        Usage {
            deployment: Deployment {
                domain: "a".repeat(64),
                program: Address::from_pubkey(&[1; 32]),
            },
            payer: Address::from_pubkey(&[2; 32]),
            generation: 1,
            plan: 0,
            offer: 3,
            manifest_hash: "b".repeat(64),
            traffic_class: 1,
            sequence: 7,
            total_bytes: 1_048_577,
        }
    }

    #[test]
    fn messages_match_application_ascii_without_prehash() {
        let u = usage();
        assert_eq!(
            u.signing_message().unwrap(),
            format!(
                "Octranet prepaid v1|{}|{}|{}|1|0|3|{}|1|7|1048577",
                "a".repeat(64),
                u.deployment.program,
                u.payer,
                "b".repeat(64)
            )
        );
        assert_eq!(
            u.deployment.registration_message(&u.payer, 2).unwrap(),
            format!(
                "Octranet register v1|{}|{}|{}|2",
                "a".repeat(64),
                u.deployment.program,
                u.payer
            )
        );
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let signed = SignedUsage::sign(u, &key).unwrap();
        signed.verify().unwrap();
        assert_eq!(
            signed.claim_params().unwrap(),
            json!([0, 1, 7, 1_048_577, b64::encode(signed.signature.0)])
        );
        let raw = serde_json::to_vec(&signed).unwrap();
        let restored: SignedUsage = serde_json::from_slice(&raw).unwrap();
        assert_eq!(restored, signed);
        restored.verify().unwrap();
    }

    #[test]
    fn every_signed_usage_field_is_authenticated() {
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let original = SignedUsage::sign(usage(), &key).unwrap();
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.usage.deployment.domain = "c".repeat(64);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.deployment.program = Address::from_pubkey(&[3; 32]);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.payer = Address::from_pubkey(&[3; 32]);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.generation += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.plan += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.offer += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.manifest_hash = "c".repeat(64);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.traffic_class += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.sequence += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.usage.total_bytes += 1;
        mutations.push(changed);
        let mut changed = original;
        changed.receipt_key = KeyPair::from_secret_bytes(&[8; 32]).public;
        mutations.push(changed);
        for changed in mutations {
            assert!(changed.verify().is_err());
        }
    }

    #[test]
    fn json_rejects_unknown_fields_malformed_ids_and_invalid_receipt_numbers() {
        let mut value = serde_json::to_value(usage()).unwrap();
        value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Usage>(value).is_err());
        for (field, invalid) in [
            ("payer", json!("not-an-address")),
            ("generation", json!(0)),
            ("sequence", json!(0)),
            ("traffic_class", json!(32)),
            ("manifest_hash", json!("A".repeat(64))),
        ] {
            let mut value = serde_json::to_value(usage()).unwrap();
            value[field] = invalid;
            assert!(serde_json::from_value::<Usage>(value).is_err(), "{field}");
        }
        let mut value = serde_json::to_value(usage()).unwrap();
        value["deployment"]["domain"] = json!("A".repeat(64));
        assert!(serde_json::from_value::<Usage>(value).is_err());
        let mut forged = usage();
        forged.payer = Address::from_parts([0; 32], forged.payer.display());
        assert!(forged.signing_message().is_err());
    }

    #[test]
    fn identity_public_key_never_authorizes_usage() {
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let mut signed = SignedUsage::sign(usage(), &key).unwrap();
        signed.receipt_key = PublicKey([0; 32]);
        assert!(signed.verify().is_err());
        let mut identity = [0; 32];
        identity[0] = 1;
        signed.receipt_key = PublicKey(identity);
        assert!(signed.verify().is_err());
    }
}
