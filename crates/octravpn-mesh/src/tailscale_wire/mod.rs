//! Tailscale wire-protocol compatibility layer.
//!
//! Implements just enough of the Tailscale coordination protocol for
//! a stock `tailscale up` client to make progress against an OctraVPN
//! node. See `docs/tailscale-interop-blocker.md` for the four-PR plan
//! (`/key` → `/ts2021` → `/register` → `/map`) this module is built
//! against, and `docs/tailscale-interop-finding.md` for the diagnosis
//! that motivated it.
//!
//! ## What ships in this commit
//!
//! - **PR 1: `GET /key`** ([`key_handler`]) — returns the node's
//!   long-term Noise X25519 public key as a Tailscale-shape
//!   `OverTLSPublicKeyResponse` JSON. Key is generated once and
//!   persisted under the configured directory across boots.
//! - **PR 2: Noise IK helpers** ([`noise`]) — minimal initiator +
//!   responder wrappers around `snow` for the
//!   `Noise_IK_25519_ChaChaPoly_BLAKE2s` pattern that TS2021 uses.
//!   Used by an in-process round-trip test today; full `/ts2021`
//!   upgrade-and-frame on top of an HTTP/2 hijacked socket is *not*
//!   yet wired (see decision log + blocker doc).
//! - **PR 3 scaffold: `POST /machine/{node_key}/register`**
//!   ([`register`]) — decodes a JSON `RegisterRequest`, redeems the
//!   presented authkey against `PreauthMinter`, allocates a tailnet
//!   IP. The handler is plaintext-JSON today (not yet wrapped in the
//!   Noise frame layer); it's testable end-to-end in isolation but
//!   stock `tailscale up` will not exercise it until PR 2's framing
//!   lands fully.
//! - **PR 4 scaffold: `POST /machine/{node_key}/map`** ([`map`]) — a
//!   minimum-viable long-poll handler returning a two-peer
//!   `MapResponse`. Same plaintext-JSON caveat as register.
//!
//! ## Decision log (read this before changing anything)
//!
//! - **Why a single `tailscale_wire` module vs splitting between
//!   `noise/`, `wire/`, `http/`:** the four files (`noise`,
//!   `key_handler`, `register`, `map`) all share the
//!   `WireState` / `MachineRegistry` types and re-export through
//!   `router()`. One module keeps the imports flat.
//! - **Why `snow` 0.9 and not 0.10:** the blocker doc pins 0.9 and the
//!   workspace MSRV is currently 1.85, which snow 0.10 also satisfies,
//!   but the spec is explicit — bumping to 0.10 is a separate change.
//! - **Why we *don't* implement DERP:** the docker harness peers share
//!   a bridge network and can NAT-traverse directly; DERP would
//!   require a separate relay subprocess and is out of scope per the
//!   blocker doc's "stretch acceptance" note.
//! - **Why JSON not the binary `controlbase` framing for register/map:**
//!   honest gap. The real wire is JSON wrapped in
//!   `Noise_IK_25519_ChaChaPoly_BLAKE2s` frames on top of HTTP/2 inside
//!   the hijacked `/ts2021` connection. Implementing that
//!   end-to-end is the bulk of the remaining work
//!   (`tailscale/control/controlbase` + `golang.org/x/net/http2` —
//!   neither has a clean Rust analogue today). PR 3+4's plaintext
//!   handlers are *testable in isolation* and ready to slot behind the
//!   frame layer once it lands.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::Notify;

use crate::{ip_alloc::TailnetIpAllocator, headscale_bridge::PreauthMinter};

pub mod controlbase;
pub mod key_handler;
pub mod map;
pub mod noise;
pub mod register;
pub mod wire;

pub use noise::ServerNoiseKey;
pub use wire::{MachineRecord, MapRequest, MapResponse, RegisterRequest, RegisterResponse};

/// Error type for the Tailscale-wire handlers.
///
/// Variants map cleanly to Tailscale's documented error envelope: the
/// outer JSON `{"error": "..."}` plus an HTTP status (4xx on
/// authentication / parse errors, 5xx on internal). Concrete HTTP
/// mapping lives in each handler module — this type stays
/// transport-agnostic so the same error can surface from a CLI
/// fixture path.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("authkey rejected: {0}")]
    AuthKeyRejected(String),
    #[error("invalid request body: {0}")]
    InvalidBody(String),
    #[error("noise handshake: {0}")]
    Noise(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Shared state for every handler under [`router`].
///
/// Cheap to clone: every field is an `Arc`. Construct once at node
/// startup and hand to both the wire router and any place that needs
/// to inspect peers (e.g. an admin UI).
#[derive(Clone)]
pub struct WireState {
    /// The node's long-term Noise X25519 keypair. Same key across
    /// reboots; persisted under `state_dir`. Public key is what
    /// `GET /key` returns.
    pub server_noise_key: Arc<ServerNoiseKey>,
    /// Preauth minter so `register` can validate presented authkeys.
    pub preauth: PreauthMinter,
    /// IP allocator for the (single) tailnet the wire surface serves.
    pub ip_allocator: Arc<TailnetIpAllocator>,
    /// node_key (hex) → machine record. Map long-poll reads this to
    /// build the peer list; register writes to it on success.
    pub machines: Arc<MachineRegistry>,
}

/// In-memory machine registry. Each successful `register` inserts here;
/// `map` reads here.
///
/// Decision: a plain `parking_lot::RwLock<HashMap>` rather than a
/// `BoundedMap`. The interop harness only ever runs 2 peers; the
/// production surface will outgrow this and should swap in a
/// persistent store, but that's tracked in the blocker doc, not here.
#[derive(Default)]
pub struct MachineRegistry {
    inner: RwLock<HashMap<String, MachineRecord>>,
    /// Wakes pending `/map` long-polls when a new machine registers.
    /// One `Notify` is sufficient because the interop test only has
    /// two peers — peer A's long-poll wakes when B registers, and vice
    /// versa.
    pub(crate) notify: Arc<Notify>,
}

impl MachineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a machine record. Wakes every pending
    /// `/map` long-poll.
    pub fn upsert(&self, node_key_hex: String, rec: MachineRecord) {
        let mut g = self.inner.write();
        g.insert(node_key_hex, rec);
        drop(g);
        self.notify.notify_waiters();
    }

    /// Snapshot all known machines. Used by `/map` to build the peer
    /// list.
    pub fn all(&self) -> Vec<(String, MachineRecord)> {
        let g = self.inner.read();
        g.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Look up a single machine by its hex-encoded node key.
    pub fn get(&self, node_key_hex: &str) -> Option<MachineRecord> {
        self.inner.read().get(node_key_hex).cloned()
    }

    /// Number of registered machines.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// True if no machines are registered.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Build the Tailscale-wire router.
///
/// Mount under the same axum app as the rest of the node's control
/// plane. The four routes here are intentionally unauthenticated at
/// the HTTP layer — authorization happens via the presented authkey
/// (for `register`) or via possession of a registered node-key (for
/// `map`).
pub fn router(state: WireState) -> Router {
    Router::new()
        .route("/key", get(key_handler::handle_key))
        .route("/ts2021", post(noise::handle_ts2021_post))
        .route(
            "/machine/:node_key/register",
            post(register::handle_register),
        )
        .route("/machine/:node_key/map", post(map::handle_map))
        .with_state(state)
}
