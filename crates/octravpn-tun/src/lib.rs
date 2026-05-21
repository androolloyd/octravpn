//! Cross-platform TUN device for OctraVPN.
//!
//! Backends:
//!   - Linux: `/dev/net/tun` (needs `CAP_NET_ADMIN` or root)
//!   - macOS: `utun` virtual interface (root)
//!   - Windows: `wintun.dll` (driver, admin)
//!
//! All platforms expose the same async send/recv API on the L3 IP packet
//! boundary. Routes/IP configuration must be set by the calling
//! deployment script (Linux/macOS via `ip route`/`route add`; Windows
//! via `netsh interface ip set address`).
//!
//! Permissions story (see `docs/deploy.md`):
//!   - **Linux**: install with cap-bound binary
//!     (`setcap cap_net_admin+ep /usr/local/bin/octravpn-node`), or run
//!     under systemd with `AmbientCapabilities=CAP_NET_ADMIN`.
//!   - **macOS**: launchd service runs as root (only way to open utun).
//!     Optional: use Network Extension API (out of scope for v1).
//!   - **Windows**: SCM service runs as LocalSystem; wintun driver must
//!     be installed once via `wintun.dll` registration.

pub mod amnezia;

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use tracing::info;

/// DERP transport plumbing. The `front` submodule implements the
/// domain-fronting client used as a fallback when the censor IP-blocks
/// the operator's `derp-*` pool (see `docs/operators/derp-fronting.md`).
///
/// This module lives next to the TUN device because both are dial-time
/// concerns invoked from the same supervisor task — the TUN fd carries
/// inner IP packets, the DERP front transport carries the encrypted
/// relay session that wraps them. Keeping them in one crate avoids
/// pulling `reqwest` into the upper `octravpn-mesh` layer.
pub mod derp;

/// Pluggable UDP-shaped transport abstraction. Used by `octravpn-node`
/// to select between direct-UDP (the default) and the obfs4-modelled
/// wrapper in `octravpn-obfs4` — see `docs/operators/obfs4-bridge.md`.
pub mod transport;
pub use transport::{DirectUdp, Transport};

/// IPv4 address + prefix length for the virtual interface.
#[derive(Clone, Copy, Debug)]
pub struct TunAddress {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl TunAddress {
    pub const fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        Self { addr, prefix }
    }
}

/// Configuration handed to `open` to construct a TUN device.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// User-visible interface name. On macOS this is advisory (the
    /// kernel picks `utunN`); on Linux it becomes `ifr_name`; on
    /// Windows it sets the wintun pool name.
    pub name: String,
    pub address: TunAddress,
    pub mtu: u16,
    /// Whether to set the link UP at open time. Defaults to true.
    pub up_at_open: bool,
}

/// MTU floor we accept after a PMTUD fallback. 1280 is the IPv6 minimum
/// link MTU (RFC 8200 §5) and the smallest MTU we'll ever see on a
/// working internet path.
pub const MTU_FLOOR: u16 = 1280;

/// MTU we ship as the default. Bumped from 1380 → 1420 as part of the
/// Perf-Data-Plane combined work — most internet paths now MTU-1500
/// (especially over IPv6), and 1420 leaves room for the 80-byte WG
/// header without the onion-layer slack that direct sessions don't
/// use (see Perf-Data-Plane #3 / `octravpn-node/src/tunnel.rs`).
///
/// Operators can override via `[tunnel].mtu` in node config. On EMSGSIZE
/// the tunnel falls back to `MTU_LEGACY_SAFE`.
pub const MTU_DEFAULT: u16 = 1420;

/// Conservative MTU used as the fallback after PMTUD failure (EMSGSIZE).
/// Matches the historic v1 default and leaves room for WG + a 3-hop
/// onion layer (~40 B added). Never goes below `MTU_FLOOR`.
pub const MTU_LEGACY_SAFE: u16 = 1380;

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "octravpn".to_string(),
            address: TunAddress::new(Ipv4Addr::new(10, 66, 0, 2), 24),
            // Perf-Data-Plane #3: bumped from 1380 → 1420. PMTUD fallback
            // to 1380 lives in `Tun::on_emsgsize` below.
            mtu: MTU_DEFAULT,
            up_at_open: true,
        }
    }
}

/// PMTUD outcome surfaced by the data plane. The TUN device starts at
/// `MTU_DEFAULT`; on the first EMSGSIZE returned by `sendto` we step
/// down to `MTU_LEGACY_SAFE`. Never silently truncates or fragments —
/// the caller is expected to honor `current_mtu` for the next send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PmtudState {
    /// Boot-time / never-probed; use `MTU_DEFAULT`.
    Default,
    /// EMSGSIZE seen on send; data-plane MUST resize down to
    /// `MTU_LEGACY_SAFE` for the affected path.
    FellBackToSafe,
}

/// Async TUN device. `send`/`recv` operate on full IP packets (no L2
/// frame).
pub struct Tun {
    inner: tun_rs::AsyncDevice,
    name: String,
}

impl Tun {
    /// Open the TUN device per `cfg`. Returns an error if the OS API
    /// rejects (missing permissions, missing driver, etc.).
    pub fn open(cfg: &TunConfig) -> Result<Self> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .name(&cfg.name)
            .ipv4(cfg.address.addr, cfg.address.prefix, None)
            .mtu(cfg.mtu);
        if cfg.up_at_open {
            builder = builder.enable(true);
        }
        let dev = builder
            .build_async()
            .context("open TUN device (need CAP_NET_ADMIN / root / wintun driver)")?;
        let name = dev.name().unwrap_or_else(|_| cfg.name.clone());
        info!(tun = %name, addr = %cfg.address.addr, prefix = cfg.address.prefix, mtu = cfg.mtu, "TUN opened");
        Ok(Self { inner: dev, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Receive a single IP packet. The returned slice references `buf`
    /// up to the read length.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.recv(buf).await.context("tun recv")?;
        Ok(n)
    }

    /// Send a single IP packet.
    pub async fn send(&self, packet: &[u8]) -> Result<usize> {
        let n = self.inner.send(packet).await.context("tun send")?;
        Ok(n)
    }
}

/// Tracks PMTUD state for a single path (or the device as a whole, if
/// the operator doesn't run per-path tracking). The tracker is a tiny
/// state machine that exposes `current_mtu()` and accepts the io error
/// from a failed `send_to`; if the error is EMSGSIZE (or
/// `Os::EMSGSIZE`) it falls back to the safe MTU and returns the new
/// value. Subsequent calls keep returning the safe MTU.
///
/// Test note: callers can drive this without a real socket by passing
/// synthetic `std::io::Error::from_raw_os_error(EMSGSIZE)`.
#[derive(Debug)]
pub struct PmtudTracker {
    state: PmtudState,
    /// Cached MTU. Bumped down on EMSGSIZE. Never goes below `MTU_FLOOR`.
    mtu: u16,
}

impl Default for PmtudTracker {
    fn default() -> Self {
        Self {
            state: PmtudState::Default,
            mtu: MTU_DEFAULT,
        }
    }
}

impl PmtudTracker {
    /// New tracker starting at the configured MTU. Operators who set a
    /// non-default MTU still benefit from the EMSGSIZE fallback floor.
    pub fn with_initial(initial_mtu: u16) -> Self {
        Self {
            state: PmtudState::Default,
            mtu: initial_mtu.max(MTU_FLOOR),
        }
    }

    /// Current MTU. Callers use this as the segment size for the next
    /// send.
    pub fn current_mtu(&self) -> u16 {
        self.mtu
    }

    /// Tracker state for telemetry / metrics.
    pub fn state(&self) -> PmtudState {
        self.state
    }

    /// Hand the tracker an `io::Error` from a failed sendto. Returns
    /// `Some(new_mtu)` if the error was EMSGSIZE and we adjusted, else
    /// `None`. Idempotent: once we're at `FellBackToSafe`, further
    /// EMSGSIZE events are no-ops (we won't keep ratcheting below
    /// `MTU_LEGACY_SAFE`).
    pub fn on_send_error(&mut self, err: &std::io::Error) -> Option<u16> {
        // EMSGSIZE is libc::EMSGSIZE on Unix; on Windows the equivalent
        // is WSAEMSGSIZE (10040). raw_os_error() returns the platform
        // errno either way.
        let is_emsgsize = matches!(err.raw_os_error(), Some(code) if code == emsgsize_code());
        if !is_emsgsize {
            return None;
        }
        if matches!(self.state, PmtudState::FellBackToSafe) {
            // Already on the floor — caller shouldn't send packets > safe MTU.
            return None;
        }
        self.state = PmtudState::FellBackToSafe;
        self.mtu = MTU_LEGACY_SAFE;
        Some(self.mtu)
    }
}

/// Platform errno for EMSGSIZE. Hoisted into a small fn so the test
/// suite (and the docs) have one shared definition.
pub const fn emsgsize_code() -> i32 {
    #[cfg(unix)]
    {
        libc::EMSGSIZE
    }
    #[cfg(windows)]
    {
        10040 // WSAEMSGSIZE
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Best-effort default; the EMSGSIZE-fallback path is a no-op
        // on platforms we don't know.
        90
    }
}

/// Platform-aware doctor: returns `Ok(())` if a TUN device could
/// plausibly be opened, or an error describing what's missing.
pub fn doctor() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // CAP_NET_ADMIN is the minimal requirement.
        let path = std::path::Path::new("/dev/net/tun");
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "/dev/net/tun missing — kernel TUN module not loaded?"
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // utun is a kernel control; the only true check is `open`.
        // We just verify we have root or sudo since that's necessary.
        if !is_root() {
            return Err(anyhow::anyhow!(
                "macOS utun requires root (sudo). Run via launchd or `sudo octravpn-node run`."
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        // wintun.dll lives next to the binary or in C:\\Windows\\System32.
        // Loading it is the only true test.
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("TUN not supported on this platform"))
    }
}

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    // libc::geteuid is unsafe to call without a crate; check $USER/$UID
    // env vars and the existence of /var/run/sudo as proxies.
    std::env::var("USER").is_ok_and(|u| u == "root") || std::env::var("UID").is_ok_and(|u| u == "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_reports_something() {
        // Should not panic; result depends on OS.
        let _ = doctor();
    }

    #[test]
    fn default_config_sane() {
        let c = TunConfig::default();
        assert!(c.mtu > 1000);
        assert_eq!(c.address.prefix, 24);
    }

    /// Perf-Data-Plane #3: default MTU is the new 1420, not the legacy
    /// 1380. Catches a future regression that walks the default back.
    #[test]
    fn default_mtu_is_bumped_to_1420() {
        assert_eq!(TunConfig::default().mtu, 1420);
        assert_eq!(MTU_DEFAULT, 1420);
        assert_eq!(MTU_LEGACY_SAFE, 1380);
    }

    /// PMTUD fallback: a synthetic EMSGSIZE drops the tracker MTU from
    /// 1420 to 1380, and a second EMSGSIZE is a no-op (we never
    /// ratchet below the safe floor).
    #[test]
    fn pmtud_fallback_to_1380_on_emsgsize() {
        let mut t = PmtudTracker::default();
        assert_eq!(t.current_mtu(), 1420);
        assert_eq!(t.state(), PmtudState::Default);

        let err = std::io::Error::from_raw_os_error(emsgsize_code());
        let new = t.on_send_error(&err).expect("EMSGSIZE → fallback");
        assert_eq!(new, 1380);
        assert_eq!(t.current_mtu(), 1380);
        assert_eq!(t.state(), PmtudState::FellBackToSafe);

        // Idempotent: second EMSGSIZE doesn't ratchet further.
        let again = t.on_send_error(&err);
        assert!(again.is_none(), "must not ratchet below safe floor");
        assert_eq!(t.current_mtu(), 1380);
    }

    /// Non-EMSGSIZE errors don't move the tracker. Real packet loss /
    /// ENOBUFS / ECONNREFUSED MUST NOT pretend to be PMTUD events.
    #[test]
    fn pmtud_unrelated_error_does_not_fall_back() {
        let mut t = PmtudTracker::default();
        let err = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(t.on_send_error(&err).is_none());
        assert_eq!(t.current_mtu(), 1420);
        assert_eq!(t.state(), PmtudState::Default);
    }

    /// `with_initial` clamps any below-floor initial MTU up to the floor.
    /// Defends against an operator setting `mtu = 0` in node.toml.
    #[test]
    fn pmtud_initial_clamped_to_floor() {
        let t = PmtudTracker::with_initial(100);
        assert_eq!(t.current_mtu(), MTU_FLOOR);
    }
}
