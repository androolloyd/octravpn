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
impl Tunnel {
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
        ensure!(path.allowed(), "VPN IP grant expired");
        {
            let mut routes = self.routes.lock();
            if !routes.contains_key(&assigned) && routes.len() >= super::PEERS_CAP {
                routes.retain(|_, previous| previous.allowed());
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
                    routes.retain(|_, previous| previous.allowed());
                }
                ensure!(
                    routes.len() < super::PEERS_CAP,
                    "VPN IP route capacity exhausted"
                );
            }
            routes.insert(assigned, path.clone());
        }
        ensure!(path.allowed(), "VPN IP grant revoked");
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
            if packet::validate_inbound(parsed.bytes, assigned).is_err() || !path.allowed() {
                continue;
            }
            let Ok(payload) = packet::encode(parsed.bytes) else {
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
