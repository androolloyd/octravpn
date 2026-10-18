//! Opt-in kernel IP forwarding. Route/NAT policy belongs to host provisioning.
use super::{egress::ReturnPath, Direction, Server};
use anyhow::{ensure, Context, Result};
use octravpn_core::ip_tunnel as packet;
use octravpn_tun::{Tun, TunAddress, TunConfig};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
mod owners;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Dedicated interface, configured separately for internet forwarding/NAT.
    pub name: String,
    /// Durable ownership must survive restarts as long as kernel NAT can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_book: Option<PathBuf>,
}
impl Config {
    pub(crate) fn with_directory(mut self, directory: &Path) -> Self {
        if self.address_book.is_none() {
            self.address_book = Some(directory.join(format!("ip-owners-{}.bin", self.name)));
        }
        self
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 15
                && self
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
            "invalid VPN TUN interface name"
        );
        ensure!(
            self.address_book
                .as_ref()
                .is_none_or(|path| !path.as_os_str().is_empty()),
            "invalid VPN address-book path"
        );
        Ok(())
    }
}

pub(super) struct Tunnel {
    device: Tun,
    routes: Mutex<BTreeMap<Ipv4Addr, ReturnPath>>,
    owners: Arc<owners::Book>,
}

fn retain_routes(routes: &mut BTreeMap<Ipv4Addr, ReturnPath>) {
    // Suspension forbids handoff but preserves a route's transport identity.
    routes.retain(|_, path| path.retained());
}

impl Tunnel {
    pub(super) fn sweep(&self) {
        // Keep temporarily suspended publications; release terminal/replaced
        // transport capabilities so historical routes cannot pin every meter.
        retain_routes(&mut self.routes.lock());
    }
    async fn open(config: Config, server: [u8; 32]) -> Result<Self> {
        config.validate()?;
        let path = config
            .address_book
            .clone()
            .context("VPN IP transport requires a durable address-book path")?;
        let owners =
            tokio::task::spawn_blocking(move || owners::Book::open(&path, &server)).await??;
        let device = tokio::task::spawn_blocking(move || {
            Tun::open(&TunConfig {
                name: config.name,
                address: TunAddress::new(packet::GATEWAY, 15),
                mtu: packet::MTU as u16,
                up_at_open: true,
            })
        })
        .await??;
        Ok(Self {
            device,
            routes: Mutex::new(BTreeMap::new()),
            owners: Arc::new(owners),
        })
    }

    pub(super) async fn forward(
        &self,
        path: ReturnPath,
        payload: &[u8],
        billable: u64,
    ) -> Result<()> {
        let (session, key) = path.identity();
        let assigned = packet::address(session, key);
        let bytes = packet::decode(payload)?;
        packet::validate_outbound(bytes, assigned)?;
        self.forward_packet(path, bytes, billable, None).await
    }
    pub(super) async fn forward_stock(&self, path: ReturnPath, raw: &[u8]) -> Result<()> {
        let registration = path.stock().context("stock registration missing")?;
        let parsed = packet::parse(raw)?;
        ensure!(parsed.source == registration.ipv4, "stock source differs");
        let destination = if let Some(portal) = path.portal() {
            let exit = portal.exit().context("stock exit stopped")?;
            ensure!(
                crate::stock::packet::portal(&parsed, &exit.config),
                "outside fixed stock portal"
            );
            packet::GATEWAY
        } else if path
            .paid()
            .and_then(|c| c.stock_exit())
            .is_some_and(|exit| crate::stock::packet::circle(&parsed, &exit.config))
        {
            packet::GATEWAY
        } else {
            ensure!(
                packet::public_ipv4(parsed.destination),
                "stock private egress refused"
            );
            parsed.destination
        };
        let assigned = packet::address(path.identity().0, path.identity().1);
        let port = (parsed.destination == crate::stock::CIRCLE_GATEWAY).then_some(8443);
        let bytes = crate::stock::packet::rewrite(raw, assigned, destination, None, port)?;
        self.forward_packet(path, &bytes, raw.len() as u64, Some(raw))
            .await
    }
    async fn forward_packet(
        &self,
        path: ReturnPath,
        bytes: &[u8],
        billable: u64,
        original: Option<&[u8]>,
    ) -> Result<()> {
        let (session, key) = path.identity();
        let assigned = packet::address(session, key);
        ensure!(path.allowed(), "VPN IP grant expired");
        {
            let mut routes = self.routes.lock();
            if !routes.contains_key(&assigned) && routes.len() >= super::PEERS_CAP {
                retain_routes(&mut routes);
                ensure!(
                    routes.len() < super::PEERS_CAP,
                    "VPN IP route capacity exhausted"
                );
            }
        }
        self.owners.claim(assigned, session, key).await?;
        {
            let mut routes = self.routes.lock();
            if let Some(previous) = routes.get(&assigned) {
                // The durable book already pins ownership across process life.
                ensure!(
                    previous.identity() == path.identity(),
                    "VPN IP address collision"
                );
            } else {
                if routes.len() >= super::PEERS_CAP {
                    retain_routes(&mut routes);
                }
                ensure!(
                    routes.len() < super::PEERS_CAP,
                    "VPN IP route capacity exhausted"
                );
            }
            routes.insert(assigned, path.clone());
        }
        ensure!(path.allowed(), "VPN IP grant revoked");
        if let Some(connection) = path.paid() {
            let ticket = connection
                .meter
                .reserve(
                    original.unwrap_or(bytes),
                    octravpn_core::payments::Direction::Outbound,
                )
                .await?;
            return connection
                .handoff(ticket, bytes.len(), || {
                    path.handoff(|| self.device.try_send(bytes))
                })
                .await;
        }
        if let Some(portal) = path.portal() {
            return portal.current(&mut || {
                ensure!(
                    path.handoff(|| self.device.try_send(bytes))? == bytes.len(),
                    "partial stock portal write"
                );
                Ok(())
            });
        }
        let written = tokio::time::timeout(Duration::from_secs(1), self.device.send(bytes))
            .await
            .context("VPN TUN send timeout")??;
        ensure!(written == bytes.len(), "partial VPN TUN write");
        path.record(Direction::In, billable);
        Ok(())
    }

    pub(super) async fn run(self: Arc<Self>) {
        let mut buffer = vec![0; packet::MTU + 1];
        loop {
            let length = match self.device.recv(&mut buffer).await {
                Ok(length) => length,
                Err(error) => {
                    tracing::warn!(%error, "VPN TUN stopped");
                    return;
                }
            };
            let Ok(parsed) = packet::parse(&buffer[..length]) else {
                continue;
            };
            let path = self.routes.lock().get(&parsed.destination).cloned();
            let Some(path) = path else {
                continue;
            };
            let assigned = packet::address(path.identity().0, path.identity().1);
            if !path.allowed() || parsed.destination != assigned {
                continue;
            }
            let mut returned = None;
            if let Some(registration) = path.stock() {
                let source = if let Some(portal) = path.portal() {
                    let Some(exit) = portal.exit() else {
                        continue;
                    };
                    if !crate::stock::packet::portal_return(&parsed, exit.config.portal_port) {
                        continue;
                    }
                    exit.config.operator_ipv4
                } else if path
                    .paid()
                    .and_then(|c| c.stock_exit())
                    .is_some_and(|exit| exit.config.circle_gateway)
                    && crate::stock::packet::circle_return(&parsed)
                {
                    crate::stock::CIRCLE_GATEWAY
                } else {
                    if !packet::public_ipv4(parsed.source) {
                        continue;
                    }
                    parsed.source
                };
                let source_port = (source == crate::stock::CIRCLE_GATEWAY).then_some(443);
                let Ok(bytes) = crate::stock::packet::rewrite(
                    parsed.bytes,
                    source,
                    registration.ipv4,
                    source_port,
                    None,
                ) else {
                    continue;
                };
                returned = Some(bytes);
            } else if packet::validate_inbound(parsed.bytes, assigned).is_err() {
                continue;
            }
            let Ok(payload) = packet::encode(returned.as_deref().unwrap_or(parsed.bytes)) else {
                continue;
            };
            if let Err(error) = path.reply_body(&payload).await {
                tracing::debug!(%error, "VPN IP return refused");
            }
        }
    }
}

impl Server {
    pub(crate) async fn with_ip_tunnel(mut self, config: Option<Config>) -> Result<Self> {
        if let Some(config) = config {
            let key = x25519_dalek::PublicKey::from(&self.static_secret).to_bytes();
            self.ip_tunnel = Some(Arc::new(Tunnel::open(config, key).await?));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        onion::OnionRouter,
        tunnel::{AllowedClient, Binding, Peer, ADMISSION_LEASE},
    };
    use octravpn_core::{
        bounded::BoundedMap,
        control::{
            announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        },
        session::SessionId,
        KeyPair,
    };
    use std::time::Instant;
    use x25519_dalek::StaticSecret;

    /// Real route matching and retention, without a kernel interface. This
    /// component fixture does not establish canonical or WireGuard admission.
    #[tokio::test]
    async fn pruning_preserves_suspended_route_and_resumes_without_new_outbound_packet() {
        let key = KeyPair::from_secret_bytes(&[81; 32]);
        let opener = KeyPair::from_secret_bytes(&[82; 32]);
        let session = SessionId::from_u64(83);
        let client_wg_pubkey = [84; 32];
        let open_tx_hash = "ab".repeat(32);
        let request = AnnounceSessionRequest {
            client_sig: key.sign(&announce_signing_payload(
                &session,
                &key.public,
                &client_wg_pubkey,
                &open_tx_hash,
            )),
            opener_sig: opener.sign(&announce_opener_binding_payload(
                &session,
                &key.public,
                &client_wg_pubkey,
                &open_tx_hash,
            )),
            session_id: session.clone(),
            client_pubkey: key.public,
            client_wg_pubkey,
            open_tx_hash,
            opener_pubkey: opener.public,
        };
        let mut allowed = AllowedClient::new(request);
        allowed.paused = true;
        let allowlist = Arc::new(BoundedMap::new(1, ADMISSION_LEASE));
        assert!(allowlist.insert(client_wg_pubkey, allowed.clone()));
        let server = Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            StaticSecret::from([85; 32]),
            Arc::new(OnionRouter::new()),
            allowlist.clone(),
        )
        .await
        .unwrap();
        let peer = "127.0.0.1:51820".parse().unwrap();
        // Retention inspects peer identity, not its noise state. No handshake
        // or forwarding is claimed by this metadata-only peer fixture.
        assert!(server.peers.insert(
            peer,
            Arc::new(Peer {
                client_pubkey: client_wg_pubkey,
                tuns: Vec::new(),
                shard_count: 1
            })
        ));
        let path = server.return_path(&session, peer, &Binding::Legacy(allowed), None);
        assert!(!path.allowed());
        assert!(path.retained());
        let assigned = packet::address(&session, &client_wg_pubkey);
        let mut routes = BTreeMap::from([(assigned, path)]);
        // The same pruning rule serves periodic and capacity reclamation.
        retain_routes(&mut routes);
        assert!(routes.contains_key(&assigned));
        allowlist
            .modify(&client_wg_pubkey, |current| current.paused = false)
            .unwrap();
        assert!(routes[&assigned].allowed());
        // Actual expiry remains reclaimable; retention never extends a lease.
        allowlist
            .modify(&client_wg_pubkey, |current| {
                current.expires_at = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            })
            .unwrap();
        retain_routes(&mut routes);
        assert!(routes.is_empty());
    }
}
