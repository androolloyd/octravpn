//! Image facade used by actual private transition preparation and execution.
//! A configured host Scope requires the owned process; a worker or standalone
//! component caller without a Scope executes the same local primitive adapter.
//! Failed/cancelled scoped calls never fall back to work in the node process.
pub(crate) use super::transition_hash;
pub use super::{AmountProof, ResultPolicy};
use crate::crypto_worker::{
    self,
    private::{self, Failure, Request, Response},
};
use num_bigint::BigInt;
use octra_hfhe::{proof::zero::BoundProfile, scalar::ScalarRule};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("private input rejected: {0:?}")]
    Rejected(Vec<u8>),
    #[error("private cryptography unavailable: {0}")]
    Unavailable(String),
}
impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        match error {
            Failure::Rejected(reason) => Self::Rejected(reason),
            Failure::Unavailable(reason) => Self::Unavailable(reason),
        }
    }
}
fn call(request: Request) -> Result<Response, Error> {
    if !crypto_worker::has_scope() {
        return private::execute(request).map_err(Into::into);
    }
    match crypto_worker::call(crypto_worker::Request::Private(request)) {
        Ok(crypto_worker::Response::Private(response)) => response.map_err(Into::into),
        Err(crypto_worker::Error::Unavailable(reason)) => Err(Error::Unavailable(reason)),
        _ => Err(Error::Unavailable(
            "private worker response kind differs".into(),
        )),
    }
}
fn math(rule: ScalarRule) -> bool {
    rule == ScalarRule::Wide
}
fn unit(result: &Response) -> Result<(), Error> {
    match result {
        Response::Unit => Ok(()),
        _ => Err(Error::Unavailable(
            "private worker response kind differs".into(),
        )),
    }
}
fn boolean(result: &Response) -> Result<bool, Error> {
    match result {
        Response::Bool(value) => Ok(*value),
        _ => Err(Error::Unavailable(
            "private worker response kind differs".into(),
        )),
    }
}
pub struct PublicKey(private::Key);
impl PublicKey {
    pub fn supports_alias_rejection(&self) -> bool {
        self.0.alias
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        bytes(call(Request::EncodeKey(self.0.clone()))?)
    }
}
pub struct Cipher(private::Cipher);
impl Cipher {
    pub fn is_wrapped_scalar(&self) -> bool {
        self.0.wrapped
    }
    pub fn has_key_bound_material(&self) -> bool {
        self.0.bound
    }
}
fn bytes(result: Response) -> Result<Vec<u8>, Error> {
    match result {
        Response::Bytes(value) => Ok(value),
        _ => Err(Error::Unavailable(
            "private worker response kind differs".into(),
        )),
    }
}
pub fn encode_cipher(cipher: &Cipher) -> Result<Vec<u8>, Error> {
    bytes(call(Request::EncodeCipher(cipher.0.clone()))?)
}
#[allow(clippy::too_many_arguments)] // Exact unchanged native PVAC cell request.
pub(crate) fn verify_cell(
    public: &[u8],
    cipher: &[u8],
    expected: &[u8],
    kind: crate::circle_cell_crypto::Kind,
    proof: &[u8],
    amount: &[u8],
    strict: bool,
    rule: ScalarRule,
) -> Result<(), Error> {
    use crate::circle_cell_crypto::Kind;
    let kind = match kind {
        Kind::None => 0,
        Kind::Zero => 1,
        Kind::BoundZero => 2,
        Kind::Range => 3,
    };
    unit(&call(Request::Cell {
        public: public.to_vec(),
        cipher: cipher.to_vec(),
        expected: expected.to_vec(),
        kind,
        proof: proof.to_vec(),
        amount: amount.to_vec(),
        strict,
        math: math(rule),
    })?)
}
fn key(raw: &[u8], proof: bool) -> Result<PublicKey, Error> {
    match call(Request::Key {
        raw: raw.to_vec(),
        proof,
    })? {
        Response::Key(key) => Ok(PublicKey(key)),
        _ => Err(Error::Unavailable(
            "private worker key response differs".into(),
        )),
    }
}
pub fn load_pubkey(raw: &[u8]) -> Result<PublicKey, Error> {
    key(raw, false)
}
pub fn proof_pubkey(raw: &[u8]) -> Result<PublicKey, Error> {
    key(raw, true)
}
pub fn decode_cipher(raw: &[u8], strict: bool, cap: bool) -> Result<Cipher, Error> {
    match call(Request::Cipher {
        raw: raw.to_vec(),
        strict,
        cap,
    })? {
        Response::Cipher(cipher) => Ok(Cipher(cipher)),
        _ => Err(Error::Unavailable(
            "private worker cipher response differs".into(),
        )),
    }
}
pub fn base_layers(raw: &[u8], cap: bool) -> Result<usize, Error> {
    match call(Request::Layers {
        raw: raw.to_vec(),
        cap,
    })? {
        Response::Layers(layers) => Ok(layers),
        _ => Err(Error::Unavailable(
            "private worker layers response differs".into(),
        )),
    }
}
pub fn check_private_input(raw: &[u8], cap: bool) -> Result<(), Error> {
    unit(&call(Request::Guard {
        raw: raw.to_vec(),
        cap,
        refresh: false,
    })?)
}
pub fn check_refresh_source(raw: &[u8], cap: bool) -> Result<(), Error> {
    unit(&call(Request::Guard {
        raw: raw.to_vec(),
        cap,
        refresh: true,
    })?)
}
pub fn balance(
    public: &PublicKey,
    current: &[u8],
    delta: &Cipher,
    withdraw: bool,
    cap: bool,
    policy: ResultPolicy,
) -> Result<Vec<u8>, Error> {
    match call(Request::Balance {
        public: public.0.clone(),
        current: current.to_vec(),
        delta: delta.0.clone(),
        withdraw,
        cap,
        recoverable: policy == ResultPolicy::Recoverable,
    })? {
        Response::Bytes(bytes) => Ok(bytes),
        _ => Err(Error::Unavailable(
            "private worker balance response differs".into(),
        )),
    }
}
pub fn verify_amount(
    public: &PublicKey,
    amount: &BigInt,
    payload: &AmountProof<'_>,
    strict: bool,
    rule: ScalarRule,
) -> Result<(), Error> {
    unit(&call(Request::Amount {
        public: public.0.clone(),
        amount: amount.to_string(),
        cipher: payload.cipher.to_vec(),
        proof: payload.proof.to_vec(),
        commitment: payload.commitment.to_vec(),
        blinding: payload.blinding.to_vec(),
        strict,
        math: math(rule),
    })?)
}
pub fn verify_commitment(
    public: &PublicKey,
    cipher: &[u8],
    expected: &[u8],
    cap: bool,
) -> Result<bool, Error> {
    boolean(&call(Request::Commitment {
        public: public.0.clone(),
        cipher: cipher.to_vec(),
        expected: expected.to_vec(),
        cap,
    })?)
}
pub fn verify_claim(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    rule: ScalarRule,
) -> Result<(), Error> {
    verify_claim_profile(
        public,
        cipher,
        proof,
        commitment,
        strict,
        rule,
        BoundProfile::Standard,
    )
}
pub(crate) fn verify_claim_profile(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    rule: ScalarRule,
    profile: BoundProfile,
) -> Result<(), Error> {
    let profile = match profile {
        BoundProfile::Standard => 0,
        BoundProfile::KeySwitchRefresh => 1,
        BoundProfile::HistoricalMigration => 2,
        BoundProfile::Range => {
            return Err(Error::Unavailable("private claim profile differs".into()))
        }
    };
    unit(&call(Request::Claim {
        public: public.0.clone(),
        cipher: cipher.to_vec(),
        proof: proof.to_vec(),
        commitment: commitment.to_vec(),
        strict,
        math: math(rule),
        profile,
    })?)
}
pub(crate) fn verify_range_bound(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    commitment: &[u8],
    strict: bool,
    rule: ScalarRule,
) -> Result<(), Error> {
    unit(&call(Request::RangeBound {
        public: public.0.clone(),
        cipher: cipher.to_vec(),
        proof: proof.to_vec(),
        commitment: commitment.to_vec(),
        strict,
        math: math(rule),
    })?)
}
pub fn verify_range(
    public: &PublicKey,
    cipher: &[u8],
    proof: &[u8],
    strict: bool,
    rule: ScalarRule,
) -> Result<bool, Error> {
    boolean(&call(Request::Range {
        public: public.0.clone(),
        cipher: cipher.to_vec(),
        proof: proof.to_vec(),
        strict,
        math: math(rule),
    })?)
}
