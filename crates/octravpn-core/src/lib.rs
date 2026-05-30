//! `OctraVPN` shared types, RPC client, and crypto primitives.
//!
//! This crate is split into modules so the node daemon and client CLI can
//! depend on a single coherent surface. Everything that goes onto the wire
//! between client/node/chain lives here so types only get defined once.

// Thin Octra primitives (address codec, ed25519 sig, branch-coverage
// hooks, tx signing, util helpers, passphrase-protected wallet envelope)
// now live in the `octra-core` crate inside `octra-foundry/`. We
// re-export them here so existing call sites keep working unchanged.
pub use octra_core::{address, circle, coverage, sig, tx, util, wallet_enc, CoreError, CoreResult};

pub mod aead;
pub mod b64;
pub mod backend;
pub mod bearer;
pub mod bounded;
pub mod commit;
pub mod control;
pub mod earnings;
pub mod onion;
pub mod receipt;
pub mod receipt_journal;
pub mod rpc;
pub mod session;
pub mod spki_verifier;
pub mod stealth;
pub mod v3_calls;
pub mod v3_canonical;
pub mod v3_members;
pub mod v3_policy;
pub mod v3_state_root;
pub mod validator_oracle;

pub use backend::{OctraBackend, PlaceholderBackend, RpcBackend};

pub use address::{Address, ADDRESS_LEN};
pub use earnings::{LedgerPoint, POINT_LEN};
pub use receipt::{Receipt, ReceiptError, SignedReceipt};
pub use session::{
    EndpointRecord, OpenSessionParams, RouteOpening, SessionId, SessionState, ValidatorRecord,
};
pub use sig::{KeyPair, PublicKey, Signature};
