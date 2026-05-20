//! Minimal obfs4-style DPI-evasion wrapper for OctraVPN's UDP transport.
//!
//! # What this is (and isn't)
//!
//! This crate is *modelled on* obfs4 / lyrebird — the Tor Project's
//! pluggable transport — but is **not** wire-compatible with
//! obfs4proxy. We borrow three load-bearing ideas:
//!
//!   1. **NTOR-style handshake.** Client and server each contribute an
//!      ephemeral X25519 keypair. The server publishes a long-term
//!      X25519 identity pubkey + a 20-byte `node_id` to authorised
//!      clients out of band. The handshake derives a per-direction
//!      ChaCha20-Poly1305 key. Clients who do not know `node_id`
//!      cannot compute the MAC and are dropped silently — this is the
//!      *probe-resistance* property: a state-level DPI scanner that
//!      replays handshake bytes against random ports learns nothing.
//!   2. **Random-length frame envelopes.** Each logical datagram is
//!      sealed with a uniformly random padding suffix so that fixed
//!      input (WG handshake init = 148 bytes, transport packet =
//!      payload + 32 bytes) leaves the wire as length-distribution-
//!      randomised ciphertext. There is no detectable WireGuard length
//!      signature.
//!   3. **IAT (inter-arrival timing) chaff.** Optional jitter inserted
//!      between successive `send_to` calls so a flow-timing classifier
//!      cannot fingerprint WG's tight handshake-then-burst pattern. See
//!      [`iat::IatMode`].
//!
//! # What we deliberately drop
//!
//! - **No client identity / bridge auth flow.** obfs4 has a complete
//!   client-keypair scheme; we only need the bridge-knows-secret half
//!   because OctraVPN authenticates on a separate layer (the
//!   chain-bound receipt + WG static-key allowlist).
//! - **No state replay table.** obfs4 keeps a per-bridge replay cache
//!   for the handshake mac. We rely on ephemeral X25519 making each
//!   handshake unique; a replayed handshake derives a key the server
//!   cannot decrypt subsequent frames under, so the session dies
//!   without ever producing useful output.
//! - **No HMAC-DRBG-driven padding.** obfs4 uses a deterministic PRNG
//!   so client and server agree on padding lengths. We use system
//!   randomness because our framing is self-delimiting (each frame
//!   carries its own length prefix), so we don't need agreement.
//!
//! # Wire format
//!
//! See [`frame`] for the byte layout. Briefly:
//!
//! ```text
//!   [u16 BE: total_ciphertext_len][ciphertext..][16 byte tag]
//!     where ciphertext = ChaCha20-Poly1305(
//!         key,
//!         nonce  = 4-byte direction-tag || u64 BE counter,
//!         aad    = empty,
//!         payload = [u16 BE: real_len][real_payload][random_pad..]
//!     )
//! ```
//!
//! # Plug-point
//!
//! [`Obfs4Transport`] implements [`octravpn_tun::Transport`]. Wiring
//! through `octravpn-node` lives in `crates/octravpn-node/src/hub.rs`
//! and is opt-in via `node.toml`'s `[tun.transport]` block.
//!
//! # Threat model (one paragraph)
//!
//! AmneziaWG already obfuscates the WG static-handshake constant
//! ("WireGuard v1 zx2c4 Jason@zx2c4.com") — but a flow-shape DPI engine
//! still sees fixed 148-byte handshake-init datagrams, a 92-byte
//! response, then 32+payload transport packets. obfs4's NTOR-style
//! handshake plus length-randomised frames removes both the fixed-size
//! signature and the static handshake bytes; *and* the MAC-gated
//! NTOR means a national-scale active prober that throws random bytes
//! at the port gets no response at all, which is what AmneziaWG cannot
//! provide (AmneziaWG will still respond to a syntactically-valid WG
//! handshake under the alternate magic).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bridge;
pub mod frame;
pub mod handshake;
pub mod iat;
pub mod transport;

pub use bridge::{BridgeCredentials, BridgeIdentity, NODE_ID_LEN};
pub use frame::FrameError;
pub use handshake::HandshakeError;
pub use iat::IatMode;
pub use transport::Obfs4Transport;
