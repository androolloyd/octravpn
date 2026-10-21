//! Explicit private control wire format. Use only inside authenticated TLS;
//! signatures authenticate requests and replies, never canonical funding.
use super::{
    native, native_address, public_key, signature, verify_authorization, Address, Deployment,
    Error, KeyPair, PublicKey, Result, Signature,
};
use crate::b64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Authenticated, confidential transport only. A successful exchange is never
/// proof of payment; the payer must independently reconcile canonical state.
#[async_trait::async_trait]
pub trait PrivateExchange: Send + Sync {
    async fn exchange(&self, request: &SignedPrivateRequest) -> anyhow::Result<SignedPrivateReply>;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTarget {
    pub chain_origin: [u8; 32],
    pub pool: Deployment,
    #[serde(with = "native_address")]
    pub directory: Address,
    #[serde(with = "public_key")]
    pub operator: PublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateAction {
    Open {
        offer: u64,
        ceiling_ou: u64,
    },
    Quote {
        channel: u64,
        class: u8,
        bytes: u64,
        validity_ms: u64,
    },
    /// Base64 of an explicit inclusion record. It is evidence only; the host
    /// reconstructs the note from canonical history before granting capacity.
    Receipt {
        channel: u64,
        quote: [u8; 32],
        evidence: String,
    },
}

/// Explicit TLS response data. None of these messages is a forwarding grant.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateResult {
    Open {
        binding: Box<super::PlanBinding>,
        operator_generation: u64,
        tariff: super::Tariff,
        ceiling_ou: u64,
    },
    Quote {
        channel: u64,
        invoice: String,
    },
    Receipt {
        channel: u64,
        quote: [u8; 32],
        credit_id: [u8; 32],
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRequest {
    pub target: PrivateTarget,
    pub id: [u8; 32],
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub action: PrivateAction,
}
impl PrivateRequest {
    fn validate(&self) -> Result<()> {
        self.target.pool.validate()?;
        native(&self.target.directory)?;
        if self.target.chain_origin == [0; 32]
            || self.id == [0; 32]
            || self.expires_ms <= self.valid_from_ms
            || self.expires_ms - self.valid_from_ms > 86_400_000
        {
            return Err(Error::Invalid("private request identity/window differs"));
        }
        match &self.action {
            PrivateAction::Open { ceiling_ou, .. }
                if *ceiling_ou == 0 || *ceiling_ou > i64::MAX as u64 =>
            {
                return Err(Error::Invalid("private ceiling differs"))
            }
            PrivateAction::Quote {
                channel,
                class,
                bytes,
                validity_ms,
            } if *channel == 0
                || usize::from(*class) >= super::MAX_CLASSES
                || *bytes == 0
                || !(1..=86_400_000).contains(validity_ms) =>
            {
                return Err(Error::Invalid("private quote request differs"))
            }
            PrivateAction::Receipt {
                channel, evidence, ..
            } => {
                if *channel == 0 {
                    return Err(Error::Invalid("zero private channel"));
                }
                decode(evidence, 32_768)?;
            }
            _ => {}
        }
        Ok(())
    }
    fn message(&self, key: &PublicKey) -> Result<Vec<u8>> {
        self.validate()?;
        let mut message = b"Octranet private purchase request v1\0".to_vec();
        message.extend_from_slice(&key.0);
        // Struct/enum field order is fixed by this version, not supplied JSON
        // spelling or map order. All deserialized unknown fields are rejected.
        message.extend_from_slice(&serde_json::to_vec(self)?);
        Ok(message)
    }
    pub fn check_time(&self, canonical_ms: u64) -> Result<()> {
        self.validate()?;
        if !(self.valid_from_ms..self.expires_ms).contains(&canonical_ms) {
            return Err(Error::Invalid(
                "private request is outside canonical window",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateRequest {
    pub request: PrivateRequest,
    #[serde(with = "public_key")]
    pub receipt_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}
impl SignedPrivateRequest {
    pub fn sign(request: PrivateRequest, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(&request.message(&key.public)?);
        Ok(Self {
            request,
            receipt_key: key.public,
            signature,
        })
    }
    pub fn verify(&self) -> Result<()> {
        verify_authorization(
            &self.receipt_key,
            &self.request.message(&self.receipt_key)?,
            &self.signature,
        )
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.verify()?;
        Ok(Sha256::digest(self.request.message(&self.receipt_key)?).into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateReply {
    pub request_hash: [u8; 32],
    pub payload: String,
    #[serde(with = "signature")]
    pub signature: Signature,
}
impl SignedPrivateReply {
    fn message(request_hash: &[u8; 32], payload: &str) -> Result<Vec<u8>> {
        // Tariffs may occupy the full 64 KiB native bound. Leave room for the
        // binding/terms rather than allocating an unretrievable channel.
        decode(payload, 73_728)?;
        let mut bytes = b"Octranet private purchase reply v1\0".to_vec();
        bytes.extend_from_slice(request_hash);
        bytes.extend_from_slice(payload.as_bytes());
        Ok(bytes)
    }
    pub fn sign(
        request: &SignedPrivateRequest,
        payload: &[u8],
        operator: &KeyPair,
    ) -> Result<Self> {
        if operator.public != request.request.target.operator {
            return Err(Error::Invalid("private reply operator differs"));
        }
        let request_hash = request.digest()?;
        let payload = b64::encode(payload);
        let signature = operator.sign(&Self::message(&request_hash, &payload)?);
        Ok(Self {
            request_hash,
            payload,
            signature,
        })
    }
    pub fn verify(&self, request: &SignedPrivateRequest) -> Result<Vec<u8>> {
        if self.request_hash != request.digest()? {
            return Err(Error::Invalid("private reply request differs"));
        }
        verify_authorization(
            &request.request.target.operator,
            &Self::message(&self.request_hash, &self.payload)?,
            &self.signature,
        )?;
        decode(&self.payload, 73_728)
    }
}
fn decode(text: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if text.len() > max_bytes.div_ceil(3) * 4 {
        return Err(Error::Invalid("private payload too large"));
    }
    let bytes =
        b64::decode(text).map_err(|_| Error::Invalid("private payload encoding differs"))?;
    if bytes.len() > max_bytes || b64::encode(&bytes) != text {
        return Err(Error::Invalid("private payload encoding differs"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> SignedPrivateRequest {
        let operator = KeyPair::from_secret_bytes(&[1; 32]);
        SignedPrivateRequest::sign(
            PrivateRequest {
                target: PrivateTarget {
                    chain_origin: [3; 32],
                    pool: Deployment {
                        domain: "ab".repeat(32),
                        program: Address::from_pubkey(&operator.public.0),
                    },
                    directory: Address::from_pubkey(&[7; 32]),
                    operator: operator.public,
                },
                id: [9; 32],
                valid_from_ms: 100,
                expires_ms: 200,
                action: PrivateAction::Open {
                    offer: 1,
                    ceiling_ou: 10,
                },
            },
            &KeyPair::from_secret_bytes(&[2; 32]),
        )
        .unwrap()
    }
    #[test]
    fn private_requests_and_responses_bind_identity_terms_and_window() {
        let original = request();
        original.verify().unwrap();
        let value = serde_json::to_value(&original).unwrap();
        let mutations = [
            ("/request/id/0", serde_json::json!(1)),
            ("/request/target/chain_origin/0", serde_json::json!(4)),
            (
                "/request/target/pool/domain",
                serde_json::json!("aa".repeat(32)),
            ),
            ("/request/valid_from_ms", serde_json::json!(99)),
            ("/request/expires_ms", serde_json::json!(201)),
            ("/request/action/ceiling_ou", serde_json::json!(11)),
            ("/request/action/offer", serde_json::json!(2)),
            ("/receipt_key", serde_json::json!(b64::encode([8; 32]))),
        ];
        for (path, replacement) in mutations {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            let changed: SignedPrivateRequest = serde_json::from_value(changed).unwrap();
            assert!(changed.verify().is_err(), "{path}");
        }
        assert!(original.request.check_time(99).is_err());
        original.request.check_time(100).unwrap();
        assert!(original.request.check_time(200).is_err());
        let reply =
            SignedPrivateReply::sign(&original, b"private", &KeyPair::from_secret_bytes(&[1; 32]))
                .unwrap();
        assert_eq!(reply.verify(&original).unwrap(), b"private");
        let mut other = request();
        other.request.id[0] = 10;
        let other =
            SignedPrivateRequest::sign(other.request, &KeyPair::from_secret_bytes(&[2; 32]))
                .unwrap();
        assert!(reply.verify(&other).is_err());
        let mut corrupt = reply;
        corrupt.payload = b64::encode(b"changed");
        assert!(corrupt.verify(&original).is_err());
        let full_tariff = vec![b'x'; super::super::MAX_TARIFF_BYTES + 1024];
        let reply = SignedPrivateReply::sign(
            &original,
            &full_tariff,
            &KeyPair::from_secret_bytes(&[1; 32]),
        )
        .unwrap();
        assert_eq!(reply.verify(&original).unwrap(), full_tariff);
        assert!(SignedPrivateReply::sign(
            &original,
            &vec![0; 73_729],
            &KeyPair::from_secret_bytes(&[1; 32])
        )
        .is_err());
        let mut extra = value;
        extra["request"]["action"]["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedPrivateRequest>(extra).is_err());
    }
}
