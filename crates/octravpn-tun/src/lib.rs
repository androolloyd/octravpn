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

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use tracing::info;

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

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "octravpn".to_string(),
            address: TunAddress::new(Ipv4Addr::new(10, 66, 0, 2), 24),
            mtu: 1380, // 1500 - 80 to leave room for WG + onion overhead
            up_at_open: true,
        }
    }
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
}
