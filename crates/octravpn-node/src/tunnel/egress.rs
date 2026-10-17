//! Connected UDP flows. Neither remote replies nor packet traffic renew a grant.
use super::{
    debug, public_egress_ip, AllowedClient, AmneziaShield, Arc, Binding, Direction, Mutex,
    OnionRouter, Peer, Result, Server, SocketAddr, TunnResult, UdpSocket,
};
use anyhow::{ensure, Context};
use octravpn_core::session::SessionId;
use std::{collections::HashMap, time::Duration};
use tokio::{sync::mpsc, task::AbortHandle, time::Instant};

const MAX_FLOWS: usize = 512;
const SESSION_FLOWS: usize = 16;
const QUEUED_DATAGRAMS: usize = 4;
const IDLE: Duration = Duration::from_secs(30);

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    session: SessionId,
    client: [u8; 32],
    peer: SocketAddr,
    target: Option<SocketAddr>,
}

struct Datagram {
    bytes: Vec<u8>,
    billable: u64,
}
struct Flow {
    binding: Binding,
    send: mpsc::Sender<Datagram>,
    task: AbortHandle,
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub(super) struct Flows(Mutex<HashMap<Key, Flow>>);
impl Flows {
    fn send(&self, path: ReturnPath, datagram: Datagram) {
        let mut flows = self.0.lock();
        flows.retain(|_, flow| !flow.send.is_closed());
        if flows
            .get(&path.key)
            .is_some_and(|flow| !flow.binding.same(&path.binding))
        {
            flows.remove(&path.key);
        }
        if let Some(flow) = flows.get(&path.key) {
            let _ = flow.send.try_send(datagram);
            return;
        }
        if flows.len() >= MAX_FLOWS
            || flows
                .keys()
                .filter(|key| key.session == path.key.session)
                .count()
                >= SESSION_FLOWS
        {
            return;
        }
        let (send, receive) = mpsc::channel(QUEUED_DATAGRAMS);
        let _ = send.try_send(datagram);
        let binding = path.binding.clone();
        let key = path.key.clone();
        // The worker holds shared transport handles, never the Server or its
        // table. Dropping the table aborts every worker and releases its socket.
        let task = tokio::spawn(async move {
            if let Err(error) = run(path, receive).await {
                debug!(%error, "UDP egress flow closed");
            }
        })
        .abort_handle();
        flows.insert(
            key,
            Flow {
                binding,
                send,
                task,
            },
        );
    }
}

#[derive(Clone)]
pub(super) struct ReturnPath {
    key: Key,
    binding: Binding,
    socket: Arc<UdpSocket>,
    shield: Arc<Mutex<AmneziaShield>>,
    peers: Arc<octravpn_core::bounded::BoundedMap<SocketAddr, Arc<Peer>>>,
    allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
    router: Arc<OnionRouter>,
    payments: Option<Arc<crate::payments::Registry>>,
    local: SocketAddr,
}
impl ReturnPath {
    pub(super) fn paid(&self) -> Option<&Arc<crate::payments::Connection>> {
        self.binding.paid()
    }
    pub(super) fn allowed(&self) -> bool {
        self.matches_current(true)
    }
    pub(super) fn retained(&self) -> bool {
        self.matches_current(false)
    }
    fn matches_current(&self, require_live: bool) -> bool {
        super::binding::lookup(&self.allowlist, self.payments.as_deref(), &self.key.client)
            .is_some_and(|binding| {
                (if require_live {
                    binding.live()
                } else {
                    binding.retain_peer()
                }) && binding.same(&self.binding)
                    && *binding.session() == self.key.session
            })
            && self
                .peers
                .get(&self.key.peer)
                .is_some_and(|peer| peer.client_pubkey == self.key.client)
    }

    pub(super) fn identity(&self) -> (&SessionId, &[u8; 32]) {
        (&self.key.session, &self.key.client)
    }

    pub(super) fn record(&self, direction: Direction, bytes: u64) {
        self.router
            .record_bytes(&self.key.session, direction, bytes);
    }

    async fn reply(&self, payload: &[u8]) -> Result<()> {
        if !self.allowed() {
            return Ok(());
        }
        let Some(SocketAddr::V4(target)) = self.key.target else {
            return Ok(());
        };
        let mut body = Vec::with_capacity(6 + payload.len());
        body.extend_from_slice(&target.ip().octets());
        body.extend_from_slice(&target.port().to_be_bytes());
        body.extend_from_slice(payload);
        self.reply_body(&body).await
    }

    pub(super) async fn reply_body(&self, body: &[u8]) -> Result<()> {
        if !self.allowed() {
            return Ok(());
        }
        let frame = octravpn_core::tunnel_frame::encode(&self.key.session, body)?;
        let Some(peer) = self.peers.get(&self.key.peer) else {
            return Ok(());
        };
        let ticket = if let Some(connection) = self.paid() {
            let raw = octravpn_core::ip_tunnel::decode(body)?;
            Some(
                connection
                    .meter
                    .reserve(raw, octravpn_core::payments::Direction::Inbound)
                    .await?,
            )
        } else {
            None
        };
        let shard = peer.shard_for(self.key.peer, self.local);
        let mut work = vec![0; 65_535];
        let (result, no_session) = {
            let mut noise = peer.tuns[shard].lock();
            encapsulate(&mut noise, &frame, &mut work, self.paid().is_some())
        };
        if let Some(connection) = self.paid() {
            let ticket = ticket.context("paid packet reservation missing")?;
            if no_session {
                // No raw payload entered the library. A normal rekey can drop
                // this packet, but cannot consume permanent uncertain credit.
                ticket.cancel().await?;
                if let TunnResult::WriteToNetwork(bytes) = result {
                    connection.current(&mut || {
                        self.socket.try_send_to(bytes, self.key.peer)?;
                        Ok(())
                    })?;
                }
                return Ok(());
            }
            if let TunnResult::WriteToNetwork(bytes) = result {
                ensure!(
                    bytes.get(..4) == Some([4, 0, 0, 0].as_slice()),
                    "paid transport packet expected"
                );
                return connection
                    .handoff(ticket, bytes.len(), || {
                        self.socket.try_send_to(bytes, self.key.peer)
                    })
                    .await;
            }
            ticket.cancel().await?;
            anyhow::bail!("paid transport could not encapsulate packet");
        }
        if let TunnResult::WriteToNetwork(bytes) = result {
            // Encapsulation can initiate a rekey and queue the payload. Count
            // return traffic only for an actual transport datagram sent here;
            // queued rekey delivery can underbill, never inflate a receipt.
            let transport = bytes.get(..4) == Some([4, 0, 0, 0].as_slice());
            if self.allowed() {
                send(&self.socket, &self.shield, bytes, self.key.peer).await?;
                if transport {
                    self.router.record_bytes(
                        &self.key.session,
                        Direction::Out,
                        (32 + body.len()) as u64,
                    );
                }
            }
        }
        Ok(())
    }
}

fn encapsulate<'a>(
    noise: &mut super::Tunn,
    frame: &[u8],
    work: &'a mut [u8],
    paid: bool,
) -> (TunnResult<'a>, bool) {
    if paid && noise.time_since_last_handshake().is_none() {
        // In pinned boringtun this accessor is Some iff the current session
        // exists. The caller holds the same mutex through this decision.
        (noise.format_handshake_initiation(work, false), true)
    } else {
        (noise.encapsulate(frame, work), false)
    }
}

async fn run(path: ReturnPath, mut receive: mpsc::Receiver<Datagram>) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // A connected socket accepts replies only from this authenticated request's
    // selected public endpoint. It is separate from the WG listener and cannot
    // turn arbitrary internet datagrams into handshake or session input.
    socket
        .connect(
            path.key
                .target
                .ok_or_else(|| anyhow::anyhow!("UDP target missing"))?,
        )
        .await?;
    let mut until = Instant::now() + IDLE;
    let mut buffer = vec![0; 65_535];
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(until) => return Ok(()),
            incoming = receive.recv() => {
                let Some(datagram) = incoming else { return Ok(()); };
                if !path.allowed() { continue; }
                if matches!(tokio::time::timeout(Duration::from_secs(1), socket.send(&datagram.bytes)).await,
                    Ok(Ok(length)) if length == datagram.bytes.len()) {
                    path.router.record_bytes(&path.key.session, Direction::In, datagram.billable);
                    until = Instant::now() + IDLE;
                }
            },
            reply = socket.recv(&mut buffer) => {
                let length = reply?;
                if length <= octravpn_core::tunnel_frame::MAX_PAYLOAD.saturating_sub(6) && path.allowed() {
                    path.reply(&buffer[..length]).await?;
                }
            },
        }
    }
}

pub(super) async fn send(
    socket: &UdpSocket,
    shield: &Mutex<AmneziaShield>,
    bytes: &[u8],
    target: SocketAddr,
) -> std::io::Result<usize> {
    if shield.lock().config().is_identity() {
        return socket.send_to(bytes, target).await;
    }
    let mut packets = Vec::new();
    shield
        .lock()
        .wrap_send(target, bytes, |packet| packets.push(packet.to_vec()));
    let mut length = 0;
    for packet in packets {
        length = socket.send_to(&packet, target).await?;
    }
    Ok(length)
}

impl Server {
    pub(super) async fn egress(
        &self,
        session: &SessionId,
        peer: SocketAddr,
        binding: &Binding,
        payload: &[u8],
        billable: u64,
    ) {
        if !binding.live() {
            return;
        }
        if payload.starts_with(octravpn_core::ip_tunnel::PREFIX) {
            if let Some(tunnel) = &self.ip_tunnel {
                let path = self.return_path(session, peer, binding, None);
                if let Err(error) = tunnel.forward(path, payload, billable).await {
                    debug!(%error, "IP egress refused");
                }
            }
            return;
        }
        // Payment plans meter raw IP only; the legacy UDP wrapper cannot bypass
        // packet classification or select an unpriced egress path.
        if binding.paid().is_some() || payload.len() < 6 {
            return;
        }
        let ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let port = u16::from_be_bytes([payload[4], payload[5]]);
        if port == 0 || !public_egress_ip(ip) {
            return;
        }
        self.egress.send(
            self.return_path(
                session,
                peer,
                binding,
                Some(SocketAddr::new(ip.into(), port)),
            ),
            Datagram {
                bytes: payload[6..].to_vec(),
                billable,
            },
        );
    }

    pub(super) fn return_path(
        &self,
        session: &SessionId,
        peer: SocketAddr,
        binding: &Binding,
        target: Option<SocketAddr>,
    ) -> ReturnPath {
        ReturnPath {
            key: Key {
                session: session.clone(),
                client: binding.key(),
                peer,
                target,
            },
            binding: binding.clone(),
            socket: self.outbound_sock().clone(),
            shield: self.shield.clone(),
            peers: self.peers.clone(),
            allowlist: self.allowlist.clone(),
            payments: self.payments.clone(),
            router: self.router.clone(),
            local: self.local_addr,
        }
    }

    pub(super) async fn run_maintenance(self: Arc<Self>) {
        let mut period = tokio::time::interval(Duration::from_secs(1));
        let mut work = vec![0; 65_535];
        loop {
            period.tick().await;
            self.peers.sweep();
            if let Some(tunnel) = &self.ip_tunnel {
                tunnel.sweep();
            }
            for (source, peer) in self.peers.snapshot() {
                let binding = self.binding(&peer.client_pubkey);
                if binding
                    .as_ref()
                    .is_none_or(|binding| !binding.retain_peer())
                {
                    self.peers.remove(&source);
                    continue;
                }
                if !binding.is_some_and(|binding| binding.live()) {
                    continue;
                }
                let shard = peer.shard_for(source, self.local_addr);
                let result = peer.tuns[shard].lock().update_timers(&mut work);
                if let TunnResult::WriteToNetwork(bytes) = result {
                    if self
                        .binding(&peer.client_pubkey)
                        .is_some_and(|binding| binding.live())
                    {
                        let _ = self.shielded_send_to(bytes, source).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};
    #[test]
    fn paid_rekey_never_enters_the_opaque_payload_queue() {
        let a = StaticSecret::from([91; 32]);
        let b = StaticSecret::from([92; 32]);
        let mut sender =
            super::super::Tunn::new(a.clone(), PublicKey::from(&b), None, None, 0, None);
        let mut receiver = super::super::Tunn::new(b, PublicKey::from(&a), None, None, 0, None);
        let mut work = [0; 4096];
        let (first, unsent) = encapsulate(&mut sender, b"paid bytes", &mut work, true);
        assert!(unsent);
        let TunnResult::WriteToNetwork(init) = first else {
            panic!("handshake expected")
        };
        let init = init.to_vec();
        let TunnResult::WriteToNetwork(reply) = receiver.decapsulate(None, &init, &mut work) else {
            panic!("handshake response expected")
        };
        let reply = reply.to_vec();
        let _ = sender.decapsulate(None, &reply, &mut work);
        assert!(sender.time_since_last_handshake().is_some());
        assert!(
            matches!(sender.decapsulate(None, &[], &mut work), TunnResult::Done),
            "no paid payload may emerge from a later queue drain"
        );
        let (data, unsent) = encapsulate(&mut sender, b"paid bytes", &mut work, true);
        assert!(!unsent);
        let TunnResult::WriteToNetwork(data) = data else {
            panic!("transport expected")
        };
        assert_eq!(&data[..4], &[4, 0, 0, 0]);
    }
}
