//! Safe ownership over the adopted native PVAC library. No OCaml or IPC on
//! these calls. Verification policy and isolation belong to the node host.
#[allow(unsafe_code)] // C ABI calls and owning handles are confined to this module.
mod native;
pub use native::{Cipher, PublicKey, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Unavailable(String),
}

/// Active math uses signed field scalars; historical math uses unsigned casts.
#[derive(Clone, Copy, Debug)]
pub enum Math {
    Prior,
    Active,
}

pub use native::{keygen, pedersen_commit};
