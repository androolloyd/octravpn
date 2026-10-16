//! Raw IPv4 from an OS TUN; route installation belongs to host provisioning.
use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use octravpn_core::{ip_tunnel, session::SessionId};
use octravpn_tun::{Tun, TunAddress, TunConfig};
use tracing::{debug, info};

use super::Tunnel;

pub(crate) struct Ip {
    device: Tun,
    assigned: Ipv4Addr,
}

impl Ip {
    pub(crate) fn preflight(name: &str) -> Result<()> {
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!(
                "TUN name must contain 1..15 ASCII letters, digits, dots, underscores or hyphens"
            );
        }
        octravpn_tun::doctor().context("client TUN preflight")
    }

    pub(crate) fn open(name: &str, session: &SessionId, wireguard_key: &[u8; 32]) -> Result<Self> {
        let assigned = ip_tunnel::address(session, wireguard_key);
        let device = Tun::open(&TunConfig {
            name: name.to_owned(),
            address: TunAddress::new(assigned, 32),
            mtu: ip_tunnel::MTU as u16,
            up_at_open: true,
        })
        .context("open funded-session TUN; retain the printed session id for escrow recovery")?;
        info!(interface = %device.name(), address = %assigned, mtu = ip_tunnel::MTU,
            "client TUN prepared; use explicit host routes for selected public IPv4 destinations");
        Ok(Self { device, assigned })
    }

    pub(super) async fn drive(self, tunnel: &mut Tunnel) -> Result<()> {
        let mut packet = vec![0; ip_tunnel::MTU + 1];
        info!(interface = %self.device.name(), address = %self.assigned,
            "authenticated IPv4 tunnel ready; press ctrl-c to disconnect");
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => return signal.context("wait for disconnect signal"),
                length = self.device.recv(&mut packet) => {
                    let length = length?;
                    if length == 0 { bail!("client TUN closed"); }
                    if let Err(error) = ip_tunnel::validate_outbound(&packet[..length], self.assigned) {
                        debug!(%error, "discarding IPv4 outside the authenticated client route");
                        continue;
                    }
                    tunnel.send(&ip_tunnel::encode(&packet[..length])?).await?;
                },
                payload = tunnel.recv() => {
                    let payload = payload?;
                    let packet = ip_tunnel::decode(&payload).context("decode operator IPv4 frame")?;
                    ip_tunnel::validate_inbound(packet, self.assigned)
                        .context("validate operator IPv4 return route")?;
                    let length = self.device.send(packet).await?;
                    if length != packet.len() { bail!("short client TUN packet write"); }
                },
            }
        }
    }
}
