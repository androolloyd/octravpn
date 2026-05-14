//! Octra Circle simulator for OctraVPN v2.
//!
//! See [`docs/v2-circles-design.md`](../../docs/v2-circles-design.md)
//! for the architecture. This crate is the Rust component that
//! simulates everything the v2 design says lives "inside the
//! Circle":
//!
//!   * **Identity** — operator's WireGuard keypair, region tag,
//!     publicly-advertised exit endpoint.
//!   * **Access contract** — which tailnet members may open sessions
//!     against which exit class (shared / internal), and at what
//!     price. Class is gated on member tags; tailnet owners author
//!     the rule set via [`AclRule`].
//!   * **Encrypted byte counter** per active session. v1 of this
//!     crate uses *mock* HFHE ciphertexts (opaque hex blobs that
//!     length-increment on each `meter_packet` call). Real PVAC
//!     wiring is deferred — proof generation isn't in the public
//!     `pvac_hfhe_cpp` PoC. See `docs/v2-octra-questions.md`.
//!   * **Proxy surface** — the methods main-net `program/main-v2.aml`
//!     expects: `settle_claim(session_id, bytes_used)` and the bond /
//!     dispute hooks. The Circle dispatches these via the
//!     [`MockChain`] trait so tests can run against an in-memory stub
//!     and integration runs against the real (mock) RPC.
//!
//! The CircleSim does NOT own:
//!   * Main-net escrow (tailnet treasuries, session deposits, refund
//!     math) — that's the v2 AML's job.
//!   * Client-side state — the client's `octravpn` CLI talks to the
//!     CircleSim via the (TODO) HTTP control plane.

pub mod acl;
pub mod chain;
pub mod meter;
pub mod sim;

pub use acl::{AclRule, ExitClass, MemberTag};
pub use chain::{ChainError, MockChain};
pub use meter::{ByteMeter, EncryptedCounter};
pub use sim::{CircleConfig, CircleSim, OpenSessionRequest, SessionRecord};
