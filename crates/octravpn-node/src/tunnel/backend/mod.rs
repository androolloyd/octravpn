//! WireGuard peer-admin backend abstraction (Perf-10).
//!
//! ## Why
//!
//! Boringtun (userspace) tops out around ~1.23 Gbps/core/hop. Kernel
//! WireGuard runs ~25 Gbps/core on Linux because the AEAD + Noise
//! transform happens in the kernel, SMP-fans-out across cores, and
//! avoids the user↔kernel datagram copy on every packet.
//!
//! Both wire formats are identical (Noise IKpsk2 + ChaCha20-Poly1305).
//! So a node that needs WG peer-administration only — *no* onion
//! peel/forward — can swap the kernel module in transparently to peers.
//! Nodes that need onion forwarding still ride the userspace boringtun
//! `Server` in the parent module; they cannot use the kernel backend
//! because the kernel does not surface decrypted inner packets back to
//! the userspace daemon in a peelable form.
//!
//! ## Surface
//!
//! Everything operators need is on the [`WgBackend`] trait:
//!
//! - [`WgBackend::add_peer`] — install / overwrite a peer's allowed_ips
//!   + optional endpoint + keepalive
//! - [`WgBackend::remove_peer`] — tear it down
//! - [`WgBackend::update_endpoint`] — narrow endpoint refresh without
//!   touching allowed-ips (handy for roaming clients whose UDP src
//!   address moves)
//! - [`WgBackend::peer_stats`] — per-peer rx/tx counters + last
//!   handshake instant
//! - [`WgBackend::interface_stats`] — sum of the above plus
//!   peer count
//!
//! ## Selection
//!
//! [`select_backend`] does the capability detection at boot. The
//! operator config (`[tunnel.backend] = "auto" | "kernel" | "boringtun"`)
//! drives it:
//!
//! * `auto` (default) — uses the userspace boringtun backend
//!   unconditionally, because the existing onion-peeling data-plane
//!   `Server` in `tunnel/mod.rs` runs in-process and binds the listen
//!   port itself. The kernel backend cannot peel onions (the kernel
//!   surfaces only opaque IP datagrams) and would race the boringtun
//!   `Server` for the UDP port. We log a one-line "kernel WG available
//!   but not selected" hint when the probe succeeds, so operators
//!   discover the perf-knob.
//! * `kernel` — explicitly opt in. Boot fails if the host lacks the
//!   kernel WG module or `CAP_NET_ADMIN`. Selects this when the
//!   operator has migrated their onion-routing role off this node (or
//!   never needed it) and wants raw 25 Gbps/core throughput.
//! * `boringtun` — force userspace. Same as `auto` today; use this to
//!   pin the choice across future default flips.
//!
//! The chosen backend is logged at boot via `tracing::info!`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tracing::info;

pub(crate) mod boringtun;
#[cfg(target_os = "linux")]
pub(crate) mod kernel;
pub(crate) mod mock;

/// Per-peer bandwidth + handshake counters surfaced by every backend.
///
/// `last_handshake_at = None` means the peer has never completed a
/// handshake since the backend was constructed. Kernel WG returns 0 in
/// that case; we normalise to `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PeerStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_at: Option<SystemTime>,
}

/// Whole-interface aggregate. `peer_count` is informational; the
/// authoritative answer is `interface_stats().peer_count == n_peers`
/// after `n_peers` successful `add_peer` calls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub peer_count: usize,
}

/// 32-byte WireGuard X25519 public key.
///
/// Wrapping it in a newtype keeps the trait signatures from depending
/// on `x25519_dalek` types (the kernel backend never touches
/// `x25519_dalek` — the kernel handles the crypto). All comparisons /
/// hashing happen on the raw 32 bytes; this matches how `wg` identifies
/// peers on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// Format as base64 (the encoding `wg set` expects on stdin).
    pub(crate) fn to_base64(self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

/// 32-byte WireGuard preshared key. Wrapped to keep the trait surface
/// independent of any specific crypto type. The kernel backend writes
/// the base64 form into `wg set <iface> peer <pk> preshared-key
/// <stdin>`; boringtun forwards the bytes to `Tunn::new`'s
/// `preshared_key` slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PresharedKey(pub [u8; 32]);

impl PresharedKey {
    pub(crate) fn to_base64(self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

/// A CIDR for the WG peer's `allowed-ips` field. We don't take a hard
/// dependency on `ipnet` because the only operation we need is "render
/// as `<addr>/<prefix>`" for the kernel-backend shellout and a
/// `contains()` check for the boringtun backend (the boringtun
/// `Server` matches by source addr, so allowed-ips is informational
/// there until tunnel.rs is refactored to route on it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IpNet {
    pub addr: std::net::IpAddr,
    pub prefix: u8,
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Operator-facing config block: `[tunnel.backend] = "auto" | "kernel"
/// | "boringtun"`. Defaults to `Auto`.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BackendKind {
    /// Probe for kernel WG (Linux + `CAP_NET_ADMIN` + module present);
    /// fall back to boringtun on failure.
    #[default]
    Auto,
    /// Force the kernel backend. Boot fails if the probe is negative.
    Kernel,
    /// Force the userspace boringtun backend. Use this to dodge
    /// kernel-side bugs without recompiling.
    Boringtun,
}

/// Peer-administration surface. Every method is `&self`; impls are
/// `Send + Sync` so the backend can be wrapped in `Arc<dyn WgBackend>`
/// and handed across tasks (the control plane installs peers from the
/// session-admission handler).
#[async_trait]
pub(crate) trait WgBackend: Send + Sync {
    /// Install (or overwrite) a peer entry. Idempotent: calling
    /// `add_peer` twice with the same `public_key` replaces the prior
    /// entry rather than failing.
    async fn add_peer(
        &self,
        public_key: PublicKey,
        preshared_key: Option<PresharedKey>,
        allowed_ips: Vec<IpNet>,
        endpoint: Option<SocketAddr>,
        keepalive_secs: Option<u16>,
    ) -> Result<()>;

    /// Drop a peer. No-op (returns Ok) if the peer was never added.
    async fn remove_peer(&self, public_key: &PublicKey) -> Result<()>;

    /// Refresh a peer's UDP endpoint without touching anything else.
    /// Returns an error if the peer is unknown.
    async fn update_endpoint(&self, public_key: &PublicKey, endpoint: SocketAddr) -> Result<()>;

    /// Per-peer counters. `Err` only if the peer is unknown.
    async fn peer_stats(&self, public_key: &PublicKey) -> Result<PeerStats>;

    /// Whole-interface aggregate. Always succeeds (returns zeros on a
    /// freshly-constructed backend with no peers).
    async fn interface_stats(&self) -> Result<InterfaceStats>;

    /// Human-readable backend name (for `tracing` + tests). Returns
    /// `"kernel"` / `"boringtun"` / `"mock"`.
    fn name(&self) -> &'static str;
}

/// Outcome of [`select_backend`]: which backend was picked and *why*.
/// Stored on the hub so `/health` can advertise it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BackendSelection {
    pub kind: BackendKind,
    pub reason: BackendSelectReason,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum BackendSelectReason {
    /// Operator pinned a specific backend via config.
    Forced,
    /// `auto` mode + kernel probe succeeded.
    AutoKernelOk,
    /// `auto` mode + kernel probe failed; fell back to boringtun.
    AutoKernelMissing,
    /// `auto` mode on non-Linux; boringtun unconditionally.
    AutoNonLinux,
}

/// Probe whether the kernel WG path is usable on this host.
///
/// Heuristic (cheap → expensive):
///   1. If `/sys/module/wireguard` exists, the module is loaded.
///   2. Else try `ip link add wg-octra-probe type wireguard` and
///      `ip link delete wg-octra-probe`. Either step failing → no
///      capability.
///
/// Returns `false` on any non-Linux host without doing any work.
#[cfg(target_os = "linux")]
pub(crate) fn kernel_wg_available() -> bool {
    if std::path::Path::new("/sys/module/wireguard").exists() {
        return true;
    }
    // Probe by creating + deleting a throwaway interface. Naming it
    // `wg-octra-probe` (16-char limit on Linux iface names) keeps it
    // distinct from any real `wg-octra-N` interface we own.
    let probe_name = "wg-octra-probe";
    let add = std::process::Command::new("ip")
        .args(["link", "add", probe_name, "type", "wireguard"])
        .output();
    match add {
        Ok(o) if o.status.success() => {
            let _ = std::process::Command::new("ip")
                .args(["link", "delete", probe_name])
                .output();
            true
        }
        _ => false,
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn kernel_wg_available() -> bool {
    false
}

/// Resolve the operator's [`BackendKind`] selection against the host's
/// capabilities. Returns the constructed backend plus the
/// [`BackendSelection`] decision record. Errors only if the operator
/// pinned `kernel` on a host that fails the capability probe.
///
/// The constructed `Arc<dyn WgBackend>` shares the interface name
/// (`iface_name`, e.g. `"wg-octra-0"`) so callers querying
/// `/proc/net/wireguard` or `wg show <iface>` get a consistent answer.
pub(crate) async fn select_backend(
    requested: BackendKind,
    iface_name: &str,
    listen_port: u16,
    static_secret_b64: &str,
) -> Result<(Arc<dyn WgBackend>, BackendSelection)> {
    match requested {
        BackendKind::Kernel => {
            if !cfg!(target_os = "linux") {
                anyhow::bail!(
                    "config requests kernel WG backend but this host is not Linux \
                     (tunnel.backend = \"kernel\")"
                );
            }
            if !kernel_wg_available() {
                anyhow::bail!(
                    "config requests kernel WG backend but probe failed \
                     (missing wireguard kernel module or CAP_NET_ADMIN)"
                );
            }
            let be = build_kernel(iface_name, listen_port, static_secret_b64).await?;
            info!(backend = "kernel", reason = "forced", "WG backend selected");
            Ok((
                be,
                BackendSelection {
                    kind: BackendKind::Kernel,
                    reason: BackendSelectReason::Forced,
                },
            ))
        }
        BackendKind::Boringtun => {
            let be = build_boringtun().await?;
            info!(
                backend = "boringtun",
                reason = "forced",
                "WG backend selected"
            );
            Ok((
                be,
                BackendSelection {
                    kind: BackendKind::Boringtun,
                    reason: BackendSelectReason::Forced,
                },
            ))
        }
        BackendKind::Auto => {
            // Auto always picks boringtun: the onion-peel data-plane
            // `Server` binds the WG listen port in-process and the
            // kernel backend would race for it. Operators who don't
            // need the onion role can explicitly set `backend =
            // "kernel"`. We *do* probe the kernel and log a hint
            // when it's available, so operators discover the perf
            // knob without reading the docs first.
            let _ = (iface_name, listen_port, static_secret_b64);
            let reason = if cfg!(target_os = "linux") {
                if kernel_wg_available() {
                    info!(
                        "kernel WG module is available on this host but \
                         `[tunnel.backend] = \"auto\"` keeps the userspace \
                         boringtun path because it carries the onion-peel \
                         data plane. Set `backend = \"kernel\"` if this node \
                         is not used for onion forwarding (Perf-10)."
                    );
                }
                BackendSelectReason::AutoKernelMissing
            } else {
                BackendSelectReason::AutoNonLinux
            };
            let be = build_boringtun().await?;
            info!(backend = "boringtun", "WG backend selected (auto)");
            Ok((
                be,
                BackendSelection {
                    kind: BackendKind::Boringtun,
                    reason,
                },
            ))
        }
    }
}

async fn build_boringtun() -> Result<Arc<dyn WgBackend>> {
    Ok(Arc::new(boringtun::BoringtunBackend::new()))
}

#[cfg(target_os = "linux")]
async fn build_kernel(
    iface_name: &str,
    listen_port: u16,
    static_secret_b64: &str,
) -> Result<Arc<dyn WgBackend>> {
    Ok(Arc::new(
        kernel::KernelBackend::up(iface_name, listen_port, static_secret_b64).await?,
    ))
}

#[cfg(not(target_os = "linux"))]
async fn build_kernel(
    _iface_name: &str,
    _listen_port: u16,
    _static_secret_b64: &str,
) -> Result<Arc<dyn WgBackend>> {
    anyhow::bail!("kernel WG backend is not available on this platform")
}

/// Convenience: derive a unique-enough interface name for this node.
/// `wg-octra-<port>` is short enough to fit Linux's 15-char IFNAMSIZ
/// minus the terminator (15 chars max). The `port` keeps two daemons
/// on the same host from clashing.
pub(crate) fn default_iface_name(listen_port: u16) -> String {
    // "wg-octra-65535" = 14 chars, safe.
    format!("wg-octra-{listen_port}")
}

/// Convert a `Duration` of "since last handshake" into a `SystemTime`
/// using `SystemTime::now()` as the reference.
fn ago_to_system_time(ago: Duration) -> Option<SystemTime> {
    SystemTime::now().checked_sub(ago)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipnet_renders_cidr_form() {
        let n = IpNet {
            addr: "10.0.0.1".parse().unwrap(),
            prefix: 32,
        };
        assert_eq!(n.to_string(), "10.0.0.1/32");
    }

    #[test]
    fn pubkey_round_trips_base64() {
        let raw = [9u8; 32];
        let pk = PublicKey(raw);
        let b64 = pk.to_base64();
        use base64::Engine as _;
        let dec = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn default_iface_name_is_short() {
        // IFNAMSIZ on Linux is 16 (15 chars + NUL). Anything we hand
        // to `ip link add` must fit.
        assert!(default_iface_name(51820).len() <= 15);
        assert!(default_iface_name(65535).len() <= 15);
    }

    #[test]
    fn backend_kind_parses_from_toml() {
        // Sanity: the lowercased serde rename matches the docs.
        #[derive(serde::Deserialize)]
        struct Wrap {
            kind: BackendKind,
        }
        let cases = [
            ("auto", BackendKind::Auto),
            ("kernel", BackendKind::Kernel),
            ("boringtun", BackendKind::Boringtun),
        ];
        for (s, want) in cases {
            let w: Wrap = toml::from_str(&format!("kind = \"{s}\"")).unwrap();
            assert_eq!(w.kind, want, "tag {s}");
        }
    }

    #[test]
    fn ago_to_system_time_roundtrip() {
        let st = ago_to_system_time(Duration::from_secs(5)).unwrap();
        let now = SystemTime::now();
        let dur = now.duration_since(st).unwrap();
        // Allow plenty of slack — we just want "yes it's ~5s ago".
        assert!(dur >= Duration::from_secs(4) && dur <= Duration::from_secs(7));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn kernel_wg_unavailable_on_non_linux() {
        assert!(!kernel_wg_available(), "non-Linux must report no kernel WG");
    }

    #[tokio::test]
    async fn auto_picks_boringtun() {
        // Per the post-redesign decision (kernel backend is opt-in
        // because the onion-peel data plane owns the listen port),
        // `auto` always returns boringtun.
        let res = select_backend(BackendKind::Auto, "wg-test-0", 51820, "abc").await;
        let (be, sel) = match res {
            Ok(v) => v,
            Err(e) => panic!("auto must succeed: {e}"),
        };
        assert_eq!(be.name(), "boringtun");
        assert_eq!(sel.kind, BackendKind::Boringtun);
    }

    #[tokio::test]
    async fn forced_kernel_on_non_linux_errors() {
        if cfg!(target_os = "linux") {
            return;
        }
        let res = select_backend(BackendKind::Kernel, "wg-test-0", 51820, "abc").await;
        let msg = match res {
            Ok(_) => panic!("kernel must error on non-Linux"),
            Err(e) => e.to_string(),
        };
        assert!(msg.contains("not Linux"), "got: {msg}");
    }
}
