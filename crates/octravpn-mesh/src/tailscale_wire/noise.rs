//! TS2021 Noise IK handshake helpers.
//!
//! Tailscale's TS2021 protocol uses the `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! pattern with a Tailscale-specific prologue string mixed in via
//! `MixHash`. The full wire-level upgrade also involves:
//!
//!   1. An HTTP `Upgrade: tailscale-control-protocol` request to
//!      `/ts2021`.
//!   2. A custom 3-byte header framing
//!      (`[msgType:u8][len:u16be]`, or 5-byte for `Initiation` carrying
//!      a `protocolVersion:u16be`) wrapping each Noise message.
//!   3. HTTP/2 spoken over the hijacked socket once the handshake
//!      completes.
//!
//! This module implements **layer (1) only**: an in-process initiator /
//! responder pair on top of `snow`, with the Tailscale prologue
//! correctly bound in. The framing layer (2) and the HTTP/2 hijack (3)
//! are *not* wired here — see the decision log in `mod.rs` for why,
//! and `docs/tailscale-interop-blocker.md` for the gap. With just (1)
//! we can prove the Noise math, write a round-trip test, and persist
//! the server's long-term static key. Adding (2) is mechanical;
//! adding (3) requires a Rust HTTP/2 server that can take a hijacked
//! `tokio::io::AsyncRead+AsyncWrite` connection (no crate exposes
//! this cleanly today — `h2` requires its own Connection type).
//!
//! ## Decision log
//!
//! - **Pattern is `Noise_IK_25519_ChaChaPoly_BLAKE2s` exactly.** Sourced
//!   from
//!   `tailscale/control/controlbase/handshake.go:protocolName`. snow's
//!   `Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()…)` maps
//!   1:1.
//! - **Prologue is `"Tailscale Control Protocol v<N>"` where N is the
//!   decimal capability version.** From
//!   `tailscale/control/controlbase/handshake.go:protocolVersionPrologue`.
//!   We pin N to 39 (`NoiseCapabilityVersion`) because that's what
//!   headscale upstream targets; future clients may advance it but the
//!   Noise key is the same.
//! - **Static key persistence:** `<state_dir>/noise_static.key`,
//!   32 raw bytes (no PEM, no JSON envelope). The file is created
//!   `0600` on Unix; on Windows we rely on the default ACL inherited
//!   from the parent dir. We chose raw bytes rather than a JSON
//!   envelope because there's exactly one consumer (this module) and
//!   the simpler format is harder to corrupt.

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use parking_lot::Mutex;
use snow::{params::NoiseParams, Builder};

use super::{WireError, WireState};

/// The Tailscale capability version we advertise in the Noise
/// prologue. Pinned at 39 to match juanfont/headscale upstream
/// (`hscontrol/handlers.go:NoiseCapabilityVersion`). Stock
/// `tailscale up` advertises a higher capability version on `GET /key?v=…`
/// (138 as of 2026-05), but the prologue version is a property of *our*
/// implementation, not the client's.
pub const NOISE_CAPABILITY_VERSION: u16 = 39;

/// Noise pattern string. `Noise_IK_25519_ChaChaPoly_BLAKE2s` is the
/// exact instantiation TS2021 uses. Sourced from
/// `tailscale/control/controlbase/handshake.go`.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Default file name for the persisted long-term static key under the
/// caller-supplied `state_dir`.
pub const NOISE_STATIC_KEY_FILENAME: &str = "noise_static.key";

/// Server's long-term Noise X25519 keypair.
///
/// Construct once via [`ServerNoiseKey::load_or_generate`]; share by
/// `Arc`. Cheap to clone.
pub struct ServerNoiseKey {
    /// 32-byte X25519 private scalar. Held under a mutex only because
    /// `snow`'s Builder borrows it by `&[u8]`; the mutex is held only
    /// during builder construction, which is fast.
    private: Mutex<Vec<u8>>,
    /// 32-byte X25519 public point. Cached so `/key` doesn't have to
    /// re-derive on every request.
    public: [u8; 32],
}

impl ServerNoiseKey {
    /// Load the server's long-term static key from
    /// `<state_dir>/noise_static.key`, generating + persisting a fresh
    /// one if the file is absent.
    ///
    /// `state_dir` is created if it doesn't exist. On Unix the key file
    /// is written with mode `0600`.
    pub fn load_or_generate(state_dir: impl AsRef<Path>) -> Result<Self, WireError> {
        let dir: PathBuf = state_dir.as_ref().into();
        fs::create_dir_all(&dir)?;
        let path = dir.join(NOISE_STATIC_KEY_FILENAME);

        let private = match fs::File::open(&path) {
            Ok(mut f) => {
                let mut buf = Vec::with_capacity(32);
                f.read_to_end(&mut buf)?;
                if buf.len() != 32 {
                    return Err(WireError::Internal(format!(
                        "noise static key at {} has length {}; expected 32",
                        path.display(),
                        buf.len()
                    )));
                }
                buf
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let kp = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?)
                    .generate_keypair()
                    .map_err(noise_err)?;
                // Persist atomically: write to .tmp then rename. Avoids
                // a partial file on a crash mid-write.
                let tmp = path.with_extension("key.tmp");
                {
                    let mut f = fs::File::create(&tmp)?;
                    f.write_all(&kp.private)?;
                    f.sync_all()?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perm = fs::metadata(&tmp)?.permissions();
                    perm.set_mode(0o600);
                    fs::set_permissions(&tmp, perm)?;
                }
                fs::rename(&tmp, &path)?;
                kp.private
            }
            Err(e) => return Err(e.into()),
        };

        // Derive the public key from the private. snow doesn't
        // expose a public-from-private helper directly, so we use a
        // throwaway IK round-trip: we run our own private key as the
        // *responder* (which doesn't need a remote static), then
        // observe the responder's static via the initiator's
        // `get_remote_static` after the first message.
        let public: [u8; 32] = derive_x25519_public(&private)?;

        Ok(Self {
            private: Mutex::new(private),
            public,
        })
    }

    /// 32-byte X25519 public key. Cheap to copy.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// Hex-encoded public key (lowercase, no prefix). The `/key`
    /// handler prepends `mkey:` to match Tailscale's machine-key
    /// envelope format.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    /// Build an IK initiator targeting `remote_static` (the peer's
    /// 32-byte X25519 public). Useful for tests and (eventually) for
    /// the wire-frame layer.
    pub fn build_initiator(&self, remote_static: &[u8; 32]) -> Result<snow::HandshakeState, WireError> {
        let priv_g = self.private.lock();
        let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;
        Builder::new(params)
            .local_private_key(&priv_g)
            .remote_public_key(remote_static)
            .prologue(&prologue_bytes(NOISE_CAPABILITY_VERSION))
            .build_initiator()
            .map_err(noise_err)
    }

    /// Build an IK responder. Used by `/ts2021` once the frame layer
    /// is wired.
    pub fn build_responder(&self) -> Result<snow::HandshakeState, WireError> {
        let priv_g = self.private.lock();
        let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;
        Builder::new(params)
            .local_private_key(&priv_g)
            .prologue(&prologue_bytes(NOISE_CAPABILITY_VERSION))
            .build_responder()
            .map_err(noise_err)
    }
}

/// Tailscale's prologue format: ASCII string
/// `"Tailscale Control Protocol v<N>"` with N the decimal capability
/// version.
fn prologue_bytes(cap_ver: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{cap_ver}").into_bytes()
}

/// Derive an X25519 public key from a 32-byte private scalar.
///
/// `snow` doesn't expose a direct private-to-public helper, but the
/// IK initiator's first handshake message (`-> e, es, s, ss`) carries
/// the initiator's static public — encrypted under `es`, but the
/// responder decrypts it as part of `read_message` and the recovered
/// value is exposed via `get_remote_static`. We use that as a
/// public-derivation oracle:
///
///   1. Generate a throwaway keypair for the responder side.
///   2. Build an initiator that locally uses *our* private key and
///      targets the throwaway responder.
///   3. Run one handshake message.
///   4. Read the recovered static from the responder side.
///
/// More verbose than `x25519-dalek::PublicKey::from(&priv)`, but the
/// blocker doc forbids any new dep besides `snow`. Cost is one
/// curve-mult + one ChaPoly decrypt at startup — trivial.
fn derive_x25519_public(private: &[u8]) -> Result<[u8; 32], WireError> {
    use snow::Builder;
    let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;

    // Throwaway responder keypair; the only thing we need is for it
    // to be a valid X25519 public so the initiator can run `es`.
    let throwaway_resp = Builder::new(params.clone())
        .generate_keypair()
        .map_err(noise_err)?;

    let mut init = Builder::new(params.clone())
        .local_private_key(private)
        .remote_public_key(&throwaway_resp.public)
        .build_initiator()
        .map_err(noise_err)?;

    let mut resp = Builder::new(params)
        .local_private_key(&throwaway_resp.private)
        .build_responder()
        .map_err(noise_err)?;

    let mut msg = [0u8; 1024];
    let n = init.write_message(&[], &mut msg).map_err(noise_err)?;
    let mut payload = [0u8; 1024];
    resp.read_message(&msg[..n], &mut payload).map_err(noise_err)?;
    let recovered = resp.get_remote_static().ok_or_else(|| {
        WireError::Noise(
            "responder could not recover initiator static after read_message".into(),
        )
    })?;
    if recovered.len() != 32 {
        return Err(WireError::Noise(format!(
            "recovered static has length {}; expected 32",
            recovered.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(recovered);
    Ok(out)
}

fn noise_err<E: std::fmt::Display>(e: E) -> WireError {
    WireError::Noise(e.to_string())
}

/// Stub `/ts2021` handler. Returns 501 Not Implemented today.
///
/// A real implementation would:
///   1. Verify `Upgrade: tailscale-control-protocol` header.
///   2. Hijack the TCP connection.
///   3. Read the 5-byte initiation header
///      (`type=1, len, protocolVersion:u16be`), then `len` bytes of
///      Noise IK initiation message.
///   4. Run snow as IK responder, write the 3-byte response header +
///      Noise response.
///   5. Hand the hijacked socket to an HTTP/2 server with `read_record`
///      / `write_record` framing applied.
///
/// Step 5 is the wall: tokio's `h2` crate doesn't take a pre-hijacked
/// connection cleanly. Tracked in the blocker doc.
pub async fn handle_ts2021_stub(State(_s): State<WireState>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "ts2021 upgrade not yet wired; see docs/tailscale-interop-blocker.md",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn server_key_persists_across_loads() {
        let dir = tempdir().unwrap();
        let a = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        let pub_a = a.public_bytes();
        drop(a);
        let b = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        assert_eq!(pub_a, b.public_bytes(), "static key must persist across loads");
    }

    #[test]
    fn server_key_public_hex_is_64_chars() {
        let dir = tempdir().unwrap();
        let k = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        let h = k.public_hex();
        assert_eq!(h.len(), 64, "32-byte key → 64 hex chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The decisive Noise test: a snow IK round-trip between an
    /// initiator that knows the responder's static (the server's
    /// `ServerNoiseKey`) and a responder using that same key produces
    /// matching transport ciphers.
    #[test]
    fn ik_round_trip() {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());

        // Initiator (client) needs to know the server's static public.
        let server_pub = server.public_bytes();
        let mut init = server.build_initiator(&server_pub).unwrap();
        let mut resp = server.build_responder().unwrap();

        // -> e, es, s, ss
        let mut buf1 = [0u8; 1024];
        let n1 = init.write_message(b"", &mut buf1).unwrap();
        let mut payload = [0u8; 1024];
        let n_in = resp.read_message(&buf1[..n1], &mut payload).unwrap();
        assert_eq!(n_in, 0);

        // <- e, ee, se
        let mut buf2 = [0u8; 1024];
        let n2 = resp.write_message(b"", &mut buf2).unwrap();
        let n_in2 = init.read_message(&buf2[..n2], &mut payload).unwrap();
        assert_eq!(n_in2, 0);

        // Both sides must now be in transport mode and agree.
        let mut init_t = init.into_transport_mode().unwrap();
        let mut resp_t = resp.into_transport_mode().unwrap();

        // Initiator → responder.
        let plaintext = b"hello tailscale";
        let mut ct = [0u8; 1024];
        let nc = init_t.write_message(plaintext, &mut ct).unwrap();
        let mut pt = [0u8; 1024];
        let nd = resp_t.read_message(&ct[..nc], &mut pt).unwrap();
        assert_eq!(&pt[..nd], plaintext);

        // Responder → initiator.
        let plaintext2 = b"hello octra";
        let nc2 = resp_t.write_message(plaintext2, &mut ct).unwrap();
        let nd2 = init_t.read_message(&ct[..nc2], &mut pt).unwrap();
        assert_eq!(&pt[..nd2], plaintext2);
    }

    #[test]
    fn prologue_format_matches_tailscale() {
        // Sanity-check the prologue against the upstream format
        // sourced in the module doc.
        let p = prologue_bytes(39);
        assert_eq!(p, b"Tailscale Control Protocol v39".to_vec());
    }
}
