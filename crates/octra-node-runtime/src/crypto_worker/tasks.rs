use super::{
    image::{Cipher, Key},
    Error,
};
use octra_hfhe::{
    cipher::Cipher as ExpandedCipher,
    field::Fp,
    keys::PublicKey,
    proof::zero::{self, BoundProfile, ZeroProof},
    scalar::ScalarRule,
};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(crate) enum Request {
    Private(super::private::Request),
    #[cfg(feature = "test-helpers")]
    Fault(super::faults::Fault),
    #[cfg(feature = "test-helpers")]
    ProofFault {
        required: bool,
        fault: super::faults::Fault,
    },
    Circle(super::SensitiveJson),
    CircleParameters(super::SensitiveJson),
    CirclePrepare(crate::circle_hfhe::preflight::Parameters),
    CircleVerify(crate::circle_hfhe::preflight::Prepared),
    Key {
        #[serde(with = "bytes")]
        raw: Vec<u8>,
        registry: bool,
    },
    Cipher {
        #[serde(with = "bytes")]
        raw: Vec<u8>,
        strict: bool,
        cap: bool,
    },
    Calculate {
        key: Key,
        cipher: Cipher,
        other: Option<Cipher>,
        operation: Operation,
    },
    Verify {
        key: Key,
        cipher: Cipher,
        #[serde(with = "bytes")]
        proof: Vec<u8>,
        kind: u8,
        commitment: Option<[u8; 32]>,
        math: bool,
        asynchronous: bool,
    },
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Operation {
    Add,
    Sub,
    Mul {
        seed: [u8; 32],
        math: bool,
        draws: usize,
    },
    Scale {
        math: bool,
        amount: i64,
    },
    Divide(i64),
    AddInt {
        math: bool,
        amount: i64,
    },
    SubInt {
        math: bool,
        amount: i64,
    },
    Commit,
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Response {
    Private(super::private::Outcome),
    #[cfg(feature = "test-helpers")]
    Fault(u32),
    Circle(serde_json::Value),
    CircleParameters(
        crate::circle_hfhe::preflight::Step<crate::circle_hfhe::preflight::Parameters>,
    ),
    CirclePrepare(crate::circle_hfhe::preflight::Step<crate::circle_hfhe::preflight::Prepared>),
    Key(Key),
    Cipher(Cipher),
    Digest([u8; 32]),
    Verified(bool),
}
fn native(error: &octra_hfhe::Error) -> Error {
    if error.is_operational() {
        Error::Unavailable(error.to_string())
    } else {
        Error::Invalid
    }
}
#[derive(Default)]
pub(super) struct Local {
    saved: Option<(std::sync::Arc<[u8]>, std::sync::Arc<PublicKey>)>,
}
impl Local {
    fn key(&mut self, image: &Key) -> Result<std::sync::Arc<PublicKey>, Error> {
        if let Some((raw, key)) = &self.saved {
            if raw.as_ref() == image.bytes().as_ref() {
                return Ok(key.clone());
            }
        }
        // Exact isolated Fhe_calc.serve_session policy: one key, <=64MiB.
        // Retain neither old key nor cipher graphs after switching keys.
        self.saved = None;
        let key = std::sync::Arc::new(
            PublicKey::from_bytes(image.bytes()).map_err(|error| native(&error))?,
        );
        if key.image_size().is_ok_and(|size| size <= 67_108_864) {
            self.saved = Some((image.bytes().clone(), key.clone()));
        }
        Ok(key)
    }
    pub(super) fn execute(&mut self, request: Request) -> Result<Response, Error> {
        match request {
            Request::Private(request) => Ok(Response::Private(super::private::execute(request))),
            #[cfg(feature = "test-helpers")]
            Request::Fault(fault) => super::faults::execute(fault),
            #[cfg(feature = "test-helpers")]
            Request::ProofFault { fault, .. } => super::faults::execute(fault),
            Request::CircleParameters(value) => Ok(Response::CircleParameters(
                crate::circle_hfhe::preflight::parameters(&value),
            )),
            Request::CirclePrepare(parameters) => Ok(Response::CirclePrepare(
                crate::circle_hfhe::preflight::prepare(parameters),
            )),
            Request::CircleVerify(prepared) => Ok(Response::Circle(
                crate::circle_hfhe::preflight::verify(prepared),
            )),
            Request::Circle(value) => Ok(Response::Circle(crate::circle_hfhe::local(&value))),
            Request::Key { raw, registry } => {
                let key = if registry {
                    crate::private_crypto::load_pubkey(&raw).map_err(|e| match e {
                        crate::private_crypto::Error::Rejected(_) => Error::Invalid,
                        crate::private_crypto::Error::Unavailable(e) => native(&e),
                    })?
                } else {
                    PublicKey::from_bytes(&raw).map_err(|error| native(&error))?
                };
                Key::from_public_key(&key)
                    .map(Response::Key)
                    .map_err(|error| native(&error))
            }
            Request::Cipher { raw, strict, cap } => {
                ExpandedCipher::from_bytes_with_policy(&raw, strict, cap)
                    .and_then(|v| Cipher::from_value(&v))
                    .map(Response::Cipher)
                    .map_err(|error| native(&error))
            }
            Request::Calculate {
                key,
                cipher,
                other,
                operation,
            } => {
                let key = self.key(&key)?;
                let cipher = ExpandedCipher::from_bytes_with_policy(cipher.bytes(), false, false)
                    .map_err(|error| native(&error))?;
                let other = other
                    .map(|v| ExpandedCipher::from_bytes_with_policy(v.bytes(), false, false))
                    .transpose()
                    .map_err(|error| native(&error))?;
                let result = match operation {
                    Operation::Add => cipher.add(&key, other.as_ref().ok_or(Error::Invalid)?),
                    Operation::Sub => cipher.subtract(&key, other.as_ref().ok_or(Error::Invalid)?),
                    Operation::Mul { seed, math, draws } => cipher.multiply_seeded(
                        &key,
                        other.as_ref().ok_or(Error::Invalid)?,
                        &seed,
                        8,
                        math,
                        draws,
                    ),
                    Operation::Scale { math, amount } => Ok(if math {
                        cipher.mul_constant_i64(amount)
                    } else {
                        cipher.mul_constant_u64(amount as u64)
                    }),
                    Operation::Divide(amount) => {
                        cipher.divide_constant(Fp::from_words(amount as u64, 0))
                    }
                    Operation::AddInt { math, amount } => cipher.add_constant(
                        if math && amount < 0 {
                            Fp::from_words(amount.wrapping_sub(1) as u64, i64::MAX as u64)
                        } else {
                            Fp::from_words(amount as u64, 0)
                        },
                        math,
                    ),
                    Operation::SubInt { math, amount } => {
                        if math && amount < 0 {
                            cipher
                                .add_constant(Fp::from_words(amount.wrapping_neg() as u64, 0), true)
                        } else {
                            cipher.subtract_constant(Fp::from_words(amount as u64, 0), math)
                        }
                    }
                    Operation::Commit => return Ok(Response::Digest(cipher.commitment(&key))),
                }
                .map_err(|error| native(&error))?;
                Cipher::from_value(&result)
                    .map(Response::Cipher)
                    .map_err(|error| native(&error))
            }
            Request::Verify {
                key,
                cipher,
                proof,
                kind,
                commitment,
                math,
                asynchronous: _,
            } => {
                let result = || -> Result<bool, Error> {
                    let key = PublicKey::from_bytes(key.bytes()).map_err(|error| native(&error))?;
                    if !key.supports_alias_rejection() {
                        return Ok(false);
                    }
                    let cipher =
                        ExpandedCipher::from_bytes_with_policy(cipher.bytes(), kind != 0, true)
                            .map_err(|error| native(&error))?;
                    let proof = if kind == 1 {
                        ZeroProof::from_bound_range_bytes(&proof)
                    } else {
                        ZeroProof::from_raw_bytes(&proof)
                    }
                    .map_err(|error| native(&error))?;
                    let rule = if math {
                        ScalarRule::Wide
                    } else {
                        ScalarRule::Prior
                    };
                    match kind {
                        0 => zero::verify_zero(&key, &cipher, &proof, rule),
                        1 => zero::verify_embedded_range(&key, &cipher, &proof, true, rule),
                        2 => zero::verify_bound(
                            &key,
                            &cipher,
                            &proof,
                            &commitment.ok_or(Error::Invalid)?,
                            BoundProfile::Standard,
                            true,
                            rule,
                        ),
                        _ => return Err(Error::Invalid),
                    }
                    .map_err(|error| native(&error))
                };
                match result() {
                    Ok(valid) => Ok(Response::Verified(valid)),
                    Err(Error::Invalid) => Ok(Response::Verified(false)),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

pub(crate) mod bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let encoded = zeroize::Zeroizing::new(STANDARD.encode(v));
        s.serialize_str(&encoded)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = zeroize::Zeroizing::new(String::deserialize(d)?);
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
pub(crate) mod arc_bytes {
    use serde::{Deserializer, Serializer};
    use std::sync::Arc;
    pub(crate) fn serialize<S: Serializer>(v: &Arc<[u8]>, s: S) -> Result<S::Ok, S::Error> {
        super::bytes::serialize(v, s)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<[u8]>, D::Error> {
        super::bytes::deserialize(d).map(Into::into)
    }
}
