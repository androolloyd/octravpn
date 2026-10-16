//! Loopback UDP forwarding for the existing single-flow exit wire format.
use std::net::{SocketAddr, SocketAddrV4};

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{ip_tunnel, tunnel_frame};
use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::Tunnel;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Forward {
    pub bind: SocketAddrV4,
    pub target: SocketAddrV4,
}

pub(crate) struct PreparedForward {
    socket: UdpSocket,
    target: SocketAddrV4,
}

impl Forward {
    /// Bind before committing escrow so invalid configuration, permissions or
    /// an occupied local port cannot strand a newly opened funded session.
    pub(crate) async fn prepare(self) -> Result<PreparedForward> {
        if !self.bind.ip().is_loopback() {
            bail!("client UDP forwarding must bind a loopback address");
        }
        if self.target.port() == 0 || !ip_tunnel::public_ipv4(*self.target.ip()) {
            bail!("client UDP forwarding target must be a public IPv4 address and nonzero port");
        }
        let socket = UdpSocket::bind(self.bind)
            .await
            .context("bind local UDP forward")?;
        Ok(PreparedForward {
            socket,
            target: self.target,
        })
    }
}

impl PreparedForward {
    pub(super) async fn drive(self, tunnel: &mut Tunnel) -> Result<()> {
        let mut packet = vec![0; 65_536];
        let mut local_peer: Option<SocketAddr> = None;
        info!(bind = %self.socket.local_addr()?, target = %self.target,
            "authenticated UDP forward ready; press ctrl-c to disconnect");
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => return signal.context("wait for disconnect signal"),
                received = self.socket.recv_from(&mut packet) => {
                    let (length, sender) = received.context("receive local forwarded datagram")?;
                    // The original exit wire has no application flow ID. Pin
                    // one local source for this session instead of mixing
                    // replies from different applications or UDP sockets.
                    if !sender.ip().is_loopback() || local_peer.is_some_and(|peer| peer != sender) {
                        debug!(%sender, "discarding datagram outside pinned local forward");
                        continue;
                    }
                    let mut payload = Vec::with_capacity(6 + length);
                    payload.extend_from_slice(&self.target.ip().octets());
                    payload.extend_from_slice(&self.target.port().to_be_bytes());
                    payload.extend_from_slice(&packet[..length]);
                    // Fresh one-hop onion overhead is bounded by the shared
                    // frame encoder. Do not truncate oversized UDP messages.
                    if length > tunnel_frame::MAX_PAYLOAD.saturating_sub(512) {
                        debug!(length, "discarding oversized forwarded datagram");
                        continue;
                    }
                    tunnel.send(&payload).await?;
                    local_peer.get_or_insert(sender);
                },
                received = tunnel.recv() => {
                    let payload = received?;
                    if payload.len() < 6
                        || payload[..4] != self.target.ip().octets()
                        || payload[4..6] != self.target.port().to_be_bytes()
                    {
                        bail!("operator returned data for an unrequested UDP target");
                    }
                    let peer = local_peer.ok_or_else(|| anyhow!("operator returned unsolicited UDP data"))?;
                    let length = self.socket.send_to(&payload[6..], peer).await.context("return forwarded datagram")?;
                    if length != payload.len() - 6 { bail!("short forwarded UDP send"); }
                },
            }
        }
    }
}
