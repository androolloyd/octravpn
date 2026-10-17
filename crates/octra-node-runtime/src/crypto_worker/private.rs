//! Native PVAC verification and balance operations. Images carry public bytes;
//! expanded untrusted keys, ciphers and proof graphs stay inside this worker.
use crate::private_crypto as local;
use octra_hfhe::{proof::zero::BoundProfile, scalar::ScalarRule};
use serde::{Deserialize, Serialize};
pub(super) mod admission;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Key {
    #[serde(with = "super::tasks::bytes")]
    pub(crate) raw: Vec<u8>,
    pub(crate) alias: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Cipher {
    #[serde(with = "super::tasks::bytes")]
    pub(crate) raw: Vec<u8>,
    pub(crate) wrapped: bool,
    pub(crate) bound: bool,
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Request {
    EncodeKey(Key),
    EncodeCipher(Cipher),
    Cell {
        #[serde(with = "super::tasks::bytes")]
        public: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        expected: Vec<u8>,
        kind: u8,
        #[serde(with = "super::tasks::bytes")]
        proof: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        amount: Vec<u8>,
        strict: bool,
        math: bool,
    },
    Key {
        #[serde(with = "super::tasks::bytes")]
        raw: Vec<u8>,
        proof: bool,
    },
    Cipher {
        #[serde(with = "super::tasks::bytes")]
        raw: Vec<u8>,
        strict: bool,
        cap: bool,
    },
    Layers {
        #[serde(with = "super::tasks::bytes")]
        raw: Vec<u8>,
        cap: bool,
    },
    Guard {
        #[serde(with = "super::tasks::bytes")]
        raw: Vec<u8>,
        cap: bool,
        refresh: bool,
    },
    Balance {
        public: Key,
        #[serde(with = "super::tasks::bytes")]
        current: Vec<u8>,
        delta: Cipher,
        withdraw: bool,
        cap: bool,
        recoverable: bool,
    },
    Amount {
        public: Key,
        amount: String,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        proof: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        commitment: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        blinding: Vec<u8>,
        strict: bool,
        math: bool,
    },
    Commitment {
        public: Key,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        expected: Vec<u8>,
        cap: bool,
    },
    Claim {
        public: Key,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        proof: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        commitment: Vec<u8>,
        strict: bool,
        math: bool,
        profile: u8,
    },
    RangeBound {
        public: Key,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        proof: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        commitment: Vec<u8>,
        strict: bool,
        math: bool,
    },
    Range {
        public: Key,
        #[serde(with = "super::tasks::bytes")]
        cipher: Vec<u8>,
        #[serde(with = "super::tasks::bytes")]
        proof: Vec<u8>,
        strict: bool,
        math: bool,
    },
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Response {
    Key(Key),
    Cipher(Cipher),
    Bytes(#[serde(with = "super::tasks::bytes")] Vec<u8>),
    Bool(bool),
    Unit,
    Layers(usize),
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Failure {
    Rejected(#[serde(with = "super::tasks::bytes")] Vec<u8>),
    Unavailable(String),
}
impl From<local::Error> for Failure {
    fn from(error: local::Error) -> Self {
        match error {
            local::Error::Rejected(reason) => Self::Rejected(reason),
            local::Error::Unavailable(error) => Self::Unavailable(error.to_string()),
        }
    }
}
pub(crate) type Outcome = Result<Response, Failure>;
fn rule(math: bool) -> ScalarRule {
    if math {
        ScalarRule::Wide
    } else {
        ScalarRule::Prior
    }
}
fn key(image: &Key) -> Result<octra_hfhe::keys::PublicKey, local::Error> {
    local::load_pubkey(&image.raw)
}
fn execute_local(request: Request) -> Result<Response, local::Error> {
    match request {
        Request::EncodeKey(image) => key(&image)?
            .to_bytes()
            .map(Response::Bytes)
            .map_err(local::Error::Unavailable),
        Request::EncodeCipher(image) => {
            local::encode_cipher(&local::decode_cipher(&image.raw, false, false)?)
                .map(Response::Bytes)
        }
        Request::Cell {
            public,
            cipher,
            expected,
            kind,
            proof,
            amount,
            strict,
            math,
        } => {
            use crate::circle_cell_crypto::{self, Kind};
            let kind = match kind {
                0 => Kind::None,
                1 => Kind::Zero,
                2 => Kind::BoundZero,
                3 => Kind::Range,
                _ => return Err(local::Error::rejected("worker cell profile differs")),
            };
            circle_cell_crypto::verify(
                &public,
                &cipher,
                &expected,
                kind,
                &proof,
                &amount,
                strict,
                rule(math),
            )?;
            Ok(Response::Unit)
        }
        Request::Key { raw, proof } => {
            let key = if proof {
                local::proof_pubkey(&raw)
            } else {
                local::load_pubkey(&raw)
            }?;
            let alias = key.supports_alias_rejection();
            Ok(Response::Key(Key { raw, alias }))
        }
        Request::Cipher { raw, strict, cap } => {
            let cipher = local::decode_cipher(&raw, strict, cap)?;
            let wrapped = cipher.is_wrapped_scalar();
            let bound = cipher.has_key_bound_material();
            Ok(Response::Cipher(Cipher {
                raw,
                wrapped,
                bound,
            }))
        }
        Request::Layers { raw, cap } => local::base_layers(&raw, cap).map(Response::Layers),
        Request::Guard { raw, cap, refresh } => {
            if refresh {
                local::check_refresh_source(&raw, cap)
            } else {
                local::check_private_input(&raw, cap)
            }?;
            Ok(Response::Unit)
        }
        Request::Balance {
            public,
            current,
            delta,
            withdraw,
            cap,
            recoverable,
        } => {
            let public = key(&public)?;
            let delta = local::decode_cipher(&delta.raw, false, false)?;
            local::balance(
                &public,
                &current,
                &delta,
                withdraw,
                cap,
                if recoverable {
                    local::ResultPolicy::Recoverable
                } else {
                    local::ResultPolicy::Legacy
                },
            )
            .map(Response::Bytes)
        }
        Request::Amount {
            public,
            amount,
            cipher,
            proof,
            commitment,
            blinding,
            strict,
            math,
        } => {
            let public = key(&public)?;
            let amount = amount
                .parse()
                .map_err(|_| local::Error::rejected("worker amount encoding differs"))?;
            local::verify_amount(
                &public,
                &amount,
                &local::AmountProof {
                    cipher: &cipher,
                    proof: &proof,
                    commitment: &commitment,
                    blinding: &blinding,
                },
                strict,
                rule(math),
            )?;
            Ok(Response::Unit)
        }
        Request::Commitment {
            public,
            cipher,
            expected,
            cap,
        } => local::verify_commitment(&key(&public)?, &cipher, &expected, cap).map(Response::Bool),
        Request::Claim {
            public,
            cipher,
            proof,
            commitment,
            strict,
            math,
            profile,
        } => {
            let profile = match profile {
                0 => BoundProfile::Standard,
                1 => BoundProfile::KeySwitchRefresh,
                2 => BoundProfile::HistoricalMigration,
                _ => return Err(local::Error::rejected("worker claim profile differs")),
            };
            local::verify_claim_profile(
                &key(&public)?,
                &cipher,
                &proof,
                &commitment,
                strict,
                rule(math),
                profile,
            )?;
            Ok(Response::Unit)
        }
        Request::RangeBound {
            public,
            cipher,
            proof,
            commitment,
            strict,
            math,
        } => {
            local::verify_range_bound(
                &key(&public)?,
                &cipher,
                &proof,
                &commitment,
                strict,
                rule(math),
            )?;
            Ok(Response::Unit)
        }
        Request::Range {
            public,
            cipher,
            proof,
            strict,
            math,
        } => local::verify_range(&key(&public)?, &cipher, &proof, strict, rule(math))
            .map(Response::Bool),
    }
}
pub(crate) fn execute(request: Request) -> Outcome {
    execute_local(request).map_err(Into::into)
}
