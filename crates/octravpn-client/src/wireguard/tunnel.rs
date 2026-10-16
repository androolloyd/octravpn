//! One authenticated session over a single connected WireGuard endpoint.
use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use octravpn_core::{
    onion::{build_fresh_onion, HopBuildInput},
    session::SessionId,
    sig::KeyPair,
    tunnel_frame,
};
use octravpn_tun::amnezia::{AmneziaShield, WireTransport};
use tokio::{net::UdpSocket, time};
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

const DATAGRAM: usize = 65_535;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Traffic {
    /// Bytes offered inside authenticated session frames, excluding IP/WG.
    pub submitted: u64,
    /// Bytes received in validated frames for this exact session.
    pub received: u64,
}

impl Traffic {
    pub(crate) fn total(self) -> Result<u64> {
        self.submitted
            .checked_add(self.received)
            .ok_or_else(|| anyhow!("session byte counter exhausted"))
    }
}

pub(crate) struct Tunnel {
    socket: UdpSocket,
    peer: SocketAddr,
    noise: Tunn,
    secret: StaticSecret,
    recovery: Option<super::recovery::Control>,
    driver: super::recovery::Driver,
    generation: u64,
    shield: AmneziaShield,
    session: SessionId,
    hop: HopBuildInput,
    timer: time::Interval,
    traffic: Traffic,
    byte_limit: Option<u64>,
    work: Vec<u8>,
    network: Vec<u8>,
}

impl Tunnel {
    /// The operator key and endpoint must come from the same authenticated
    /// advertisement. The UDP socket never accepts a different sender.
    pub(crate) async fn connect(
        session: SessionId,
        identity: &KeyPair,
        endpoint: &str,
        server_key: [u8; 32],
        byte_limit: Option<u64>,
        transport: WireTransport,
    ) -> Result<Self> {
        validate_peer_key(server_key)?;
        let shield = AmneziaShield::new(
            transport
                .config()
                .map_err(|error| anyhow!("invalid operator transport: {error}"))?,
        )
        .map_err(|error| anyhow!("invalid operator transport: {error}"))?;
        let endpoint = validate_endpoint(endpoint)?;
        let peer = time::timeout(Duration::from_secs(10), tokio::net::lookup_host(endpoint))
            .await
            .context("resolve operator WireGuard endpoint timed out")??
            .find(|peer| {
                peer.port() != 0 && !peer.ip().is_unspecified() && !peer.ip().is_multicast()
            })
            .ok_or_else(|| anyhow!("operator WireGuard endpoint has no usable address"))?;
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .context("bind client WireGuard socket")?;
        socket
            .connect(peer)
            .await
            .context("connect client WireGuard socket")?;
        let mut timer = time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let secret = super::secret(identity);
        let (recovery, driver) = super::recovery::channel();
        let mut tunnel = Self {
            socket,
            peer,
            noise: Tunn::new(
                secret.clone(),
                PublicKey::from(server_key),
                None,
                Some(25),
                0,
                None,
            ),
            secret,
            recovery: Some(recovery),
            driver,
            generation: 0,
            shield,
            session,
            hop: HopBuildInput {
                static_pubkey: server_key,
                endpoint: endpoint.to_owned(),
            },
            timer,
            traffic: Traffic::default(),
            byte_limit,
            work: vec![0; DATAGRAM],
            network: vec![0; DATAGRAM],
        };
        let result = tunnel
            .noise
            .format_handshake_initiation(&mut tunnel.work, false);
        if let TunnResult::WriteToNetwork(packet) = result {
            send(&tunnel.socket, &mut tunnel.shield, tunnel.peer, packet).await?;
        } else {
            bail!("unable to initiate operator WireGuard handshake");
        }
        time::timeout(HANDSHAKE_TIMEOUT, async {
            while tunnel.noise.time_since_last_handshake().is_none() {
                // No application data is sent before the peer is authenticated.
                let _ = tunnel.step().await?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("operator WireGuard handshake timed out")??;
        tunnel.driver.initial_authenticated();
        Ok(tunnel)
    }

    pub(crate) fn recovery(&mut self) -> Result<super::recovery::Control> {
        self.recovery
            .take()
            .context("WireGuard recovery controller already taken")
    }

    pub(crate) fn traffic(&self) -> Traffic {
        self.traffic
    }

    fn reserve(&self, bytes: u64) -> Result<()> {
        let next = self
            .traffic
            .total()?
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("session byte counter exhausted"))?;
        if self.byte_limit.is_some_and(|limit| next > limit) {
            bail!("session traffic credit ceiling reached");
        }
        Ok(())
    }

    pub(crate) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        if !self.driver.ready() {
            debug!("discarding local packet while the existing session recovers");
            return Ok(());
        }
        // Fresh per-layer ECDH keys make the legacy zero-nonce onion encoding
        // safe across packets. No stable ephemeral or pinned-key sender exists.
        let onion = build_fresh_onion(std::slice::from_ref(&self.hop), payload)?;
        let frame = tunnel_frame::encode(&self.session, &onion)?;
        let bytes = 32_u64
            .checked_add(onion.len() as u64)
            .ok_or_else(|| anyhow!("session packet size exhausted"))?;
        self.reserve(bytes)?;
        match self.noise.encapsulate(&frame, &mut self.work) {
            TunnResult::WriteToNetwork(packet) => {
                match send(&self.socket, &mut self.shield, self.peer, packet).await {
                    Ok(()) => (),
                    Err(error) if transient(&error) => {
                        self.driver.unavailable();
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            TunnResult::Done | TunnResult::Err(WireGuardError::ConnectionExpired) => {
                self.driver.unavailable();
                return Ok(());
            }
            TunnResult::Err(error) => bail!("operator WireGuard encapsulation failed: {error:?}"),
            _ => bail!("operator WireGuard encapsulation returned tunnel data"),
        }
        self.traffic.submitted = self
            .traffic
            .submitted
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("session byte counter exhausted"))?;
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(payload) = self.step().await? {
                return Ok(payload);
            }
        }
    }

    async fn step(&mut self) -> Result<Option<Vec<u8>>> {
        enum Wake {
            Packet(std::io::Result<usize>),
            Timer,
            Reset(Result<u64>),
        }
        let wake = tokio::select! {
            received = self.socket.recv(&mut self.network) => {
                Wake::Packet(received)
            },
            _ = self.timer.tick() => Wake::Timer,
            generation=self.driver.requested()=>Wake::Reset(generation),
        };
        let result = match wake {
            Wake::Reset(generation) => {
                self.generation = generation?;
                self.noise = Tunn::new(
                    self.secret.clone(),
                    PublicKey::from(self.hop.static_pubkey),
                    None,
                    Some(25),
                    0,
                    None,
                );
                self.noise
                    .format_handshake_initiation(&mut self.work, false)
            }
            Wake::Packet(received) => {
                let length = match received {
                    Ok(length) => length,
                    Err(error) if transient_io(&error) => {
                        self.driver.unavailable();
                        return Ok(None);
                    }
                    Err(error) => return Err(error).context("receive operator WireGuard packet"),
                };
                let Some(length) = self.shield.wrap_recv(&mut self.network, |_| Some(length))
                else {
                    return Ok(None);
                };
                self.noise.decapsulate(
                    Some(self.peer.ip()),
                    &self.network[..length],
                    &mut self.work,
                )
            }
            Wake::Timer => self.noise.update_timers(&mut self.work),
        };
        if self.noise.time_since_last_handshake().is_some() {
            self.driver.authenticated(self.generation);
        }
        match result {
            TunnResult::WriteToNetwork(packet) => {
                if self.driver.ready() || !data_packet(packet) {
                    if let Err(error) =
                        send(&self.socket, &mut self.shield, self.peer, packet).await
                    {
                        if transient(&error) {
                            self.driver.unavailable();
                            return Ok(None);
                        }
                        return Err(error);
                    }
                }
                // Boringtun queues packets while rekeying. Drain only its
                // bounded internal queue, never application-generated traffic.
                loop {
                    match self.noise.decapsulate(None, &[], &mut self.work) {
                        TunnResult::WriteToNetwork(packet) => {
                            if self.driver.ready() || !data_packet(packet) {
                                if let Err(error) =
                                    send(&self.socket, &mut self.shield, self.peer, packet).await
                                {
                                    if transient(&error) {
                                        self.driver.unavailable();
                                        return Ok(None);
                                    }
                                    return Err(error);
                                }
                            }
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(error) => {
                            bail!("operator WireGuard queue failed: {error:?}")
                        }
                        _ => bail!("operator WireGuard queue returned tunnel data"),
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) => {
                let Ok(frame) = tunnel_frame::decode(packet) else {
                    return Ok(None);
                };
                if frame.get(..32) != Some(self.session.as_bytes().as_slice()) {
                    return Ok(None);
                }
                let bytes = frame.len() as u64;
                let payload = frame[32..].to_vec();
                self.reserve(bytes)?;
                self.traffic.received = self
                    .traffic
                    .received
                    .checked_add(bytes)
                    .ok_or_else(|| anyhow!("session byte counter exhausted"))?;
                return Ok(self.driver.ready().then_some(payload));
            }
            TunnResult::WriteToTunnelV6(_, _) | TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                self.driver.unavailable();
            }
            TunnResult::Err(error) => {
                // Forged/replayed datagrams never reach the application. Rekey
                // timers remain active, so a corrupt packet cannot kill a peer.
                debug!(?error, "discarding invalid operator WireGuard packet");
            }
        }
        Ok(None)
    }
}

fn data_packet(packet: &[u8]) -> bool {
    packet.get(..4) == Some(&[4, 0, 0, 0])
}
fn transient_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::Interrupted
    )
}
fn transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(transient_io)
    })
}

pub(super) fn validate_peer_key(key: [u8; 32]) -> Result<()> {
    // Low-order X25519 inputs contribute no secret to the shared key, even
    // when they are nonzero. This fixed probe checks only that public input.
    let probe = StaticSecret::from([42; 32]).diffie_hellman(&PublicKey::from(key));
    if !probe.was_contributory() {
        bail!("operator WireGuard key is noncontributory");
    }
    Ok(())
}

pub(super) fn validate_endpoint(endpoint: &str) -> Result<&str> {
    let raw = endpoint
        .trim()
        .strip_prefix("wg://")
        .unwrap_or(endpoint.trim());
    if raw.contains('/') || raw.contains('@') || raw.contains('?') || raw.contains('#') {
        bail!("operator WireGuard endpoint must be host:port");
    }
    let parsed = reqwest::Url::parse(&format!("udp://{raw}"))?;
    if parsed.host_str().is_none() || parsed.port().is_none_or(|port| port == 0) {
        bail!("operator WireGuard endpoint requires an explicit nonzero port");
    }
    Ok(raw)
}

async fn send(
    socket: &UdpSocket,
    shield: &mut AmneziaShield,
    peer: SocketAddr,
    packet: &[u8],
) -> Result<()> {
    if !shield.config().is_identity() {
        let mut packets = Vec::new();
        shield.wrap_send(peer, packet, |bytes| packets.push(bytes.to_vec()));
        for bytes in packets {
            send_datagram(socket, &bytes).await?;
        }
        return Ok(());
    }
    send_datagram(socket, packet).await
}
async fn send_datagram(socket: &UdpSocket, packet: &[u8]) -> Result<()> {
    let length = socket
        .send(packet)
        .await
        .context("send client WireGuard packet")?;
    if length != packet.len() {
        bail!("short client WireGuard UDP send");
    }
    Ok(())
}
