//! `OctraVPN` shared types, RPC client, and crypto primitives.
//!
//! This crate is split into modules so the node daemon and client CLI can
//! depend on a single coherent surface. Everything that goes onto the wire
//! between client/node/chain lives here so types only get defined once.

pub mod address;
pub mod backend;
pub mod bounded;
pub mod commit;
pub mod control;
pub mod coverage;
pub mod earnings;
pub mod onion;
pub mod receipt;
pub mod rpc;
pub mod session;
pub mod sig;
pub mod stealth;
pub mod tx;
pub mod util;
pub mod wallet_enc;

pub use backend::{OctraBackend, PlaceholderBackend, RpcBackend};

pub use address::{Address, ADDRESS_LEN};
pub use earnings::{LedgerPoint, POINT_LEN};
pub use receipt::{Receipt, ReceiptError, SignedReceipt};
pub use session::{
    EndpointRecord, OpenSessionParams, RouteOpening, SessionId, SessionState, ValidatorRecord,
};
pub use sig::{KeyPair, PublicKey, Signature};

/// Library-wide error type. Crates downstream return their own errors;
/// this is just for shared utilities that don't already use `anyhow`.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

pub type CoreResult<T> = std::result::Result<T, CoreError>;
