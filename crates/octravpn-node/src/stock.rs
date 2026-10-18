//! Explicit stock Tailscale transport. Registration permits the fixed portal;
//! only canonical purchased plaintext bytes permit Internet carriage.
use anyhow::{ensure, Context, Result};
use octravpn_core::session::SessionId;
use octravpn_mesh::{tailscale_wire::MachineRecord, MachineRegistry};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::SystemTime};
pub(crate) mod packet;
pub(crate) mod relay;
#[cfg(test)]
mod tests;
pub use octravpn_mesh::tailscale_wire::wire::DnsRecord;
/// Reserved network offset, never allocated to a per-plan NAT address.
pub const CIRCLE_GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Reserved, stable CGNAT address of this operator's virtual stock peer.
    pub operator_ipv4: Ipv4Addr,
    /// Only this TCP port reaches the separately pinned Circle portal backend.
    pub portal_port: u16,
    #[serde(default)]
    pub circle_gateway: bool,
    /// Explicit public UDP endpoints for direct stock connectivity. Empty
    /// advertises DERP-only; this never discovers or changes host networking.
    #[serde(default)]
    pub endpoints: Vec<std::net::SocketAddr>,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.operator_ipv4 == octravpn_mesh::TailnetIpAllocator::new("").router_ip()
                && self.portal_port > 0,
            "stock exit requires reserved router address 100.64.0.1 and a portal port"
        );
        ensure!(
            self.endpoints.len() <= 8
                && self.endpoints.iter().all(|address| address.is_ipv4()
                    && !address.ip().is_unspecified()
                    && address.port() > 0),
            "invalid stock direct endpoints"
        );
        Ok(())
    }
}

/// Frozen registration facts. A key, address, expiry or re-registration change
/// requires a newer payer-signed connection; an identical public retry cannot
/// silently rebind a durable packet journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub node_key: [u8; 32],
    pub machine_key: String,
    pub node_id: u64,
    pub ipv4: Ipv4Addr,
    pub created: String,
    pub expiry: Option<String>,
}
impl Registration {
    fn capture(record: &MachineRecord) -> Result<Self> {
        let node_key = hex::decode(&record.node_key_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid stock node key"))?;
        ensure!(
            record.node_key_hex == hex::encode(node_key) && node_key != [0; 32],
            "invalid stock node key"
        );
        ensure!(
            record.machine_key_hex.len() == 64 && hex::decode(&record.machine_key_hex)?.len() == 32,
            "invalid stock machine key"
        );
        ensure!(
            record
                .expiry
                .is_none_or(|e| SystemTime::now() < SystemTime::from(e)),
            "stock registration expired"
        );
        let ipv4 = record.ipv4.context("stock exit requires registered IPv4")?;
        let [a, b, _, _] = ipv4.octets();
        ensure!(
            a == 100 && (64..=127).contains(&b),
            "stock address outside tailnet"
        );
        Ok(Self {
            node_key,
            machine_key: record.machine_key_hex.clone(),
            node_id: record.stable_node_id(),
            ipv4,
            created: record.created_at.to_rfc3339(),
            expiry: record.expiry.map(|v| v.to_rfc3339()),
        })
    }
    pub(crate) fn session(&self) -> Result<SessionId> {
        let mut hash = Sha256::new();
        hash.update(b"Octranet stock portal registration v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(SessionId::new(hash.finalize().into()))
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Transport {
    #[default]
    Framed,
    Stock(Registration),
}

pub struct Exit {
    pub(crate) config: Config,
    pub(crate) operator_key: [u8; 32],
    pub(crate) machines: Arc<MachineRegistry>,
    admission: crate::mesh_control::Admission,
    guard: Arc<dyn crate::payments::Guard>,
    pub(crate) relay: headscale_core::derp::native::NativeDerpRelay,
    portals: Mutex<HashMap<[u8; 32], Arc<Peer>>>,
    disco: Mutex<Option<relay::Disco>>,
    pub(crate) sources: Mutex<HashMap<std::net::SocketAddr, [u8; 32]>>,
}
pub(crate) struct Peer {
    pub(crate) registration: Registration,
    pub(crate) session: SessionId,
    exit: std::sync::Weak<Exit>,
}
impl Peer {
    pub(crate) fn live(&self) -> bool {
        self.exit
            .upgrade()
            .is_some_and(|exit| exit.current(&self.registration))
    }
    pub(crate) fn exit(&self) -> Option<Arc<Exit>> {
        self.exit.upgrade()
    }
    pub(crate) fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let exit = self.exit.upgrade().context("stock exit stopped")?;
        exit.guard
            .current(&mut || exit.with_registration(&self.registration, action))
    }
}
impl Exit {
    pub(crate) fn new(
        config: Config,
        operator_key: [u8; 32],
        machines: Arc<MachineRegistry>,
        admission: crate::mesh_control::Admission,
        guard: Arc<dyn crate::payments::Guard>,
        relay: headscale_core::derp::native::NativeDerpRelay,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        ensure!(operator_key != [0; 32], "stock operator key is zero");
        Ok(Arc::new(Self {
            config,
            operator_key,
            machines,
            admission,
            guard,
            relay,
            portals: Mutex::new(HashMap::new()),
            disco: Mutex::new(None),
            sources: Mutex::new(HashMap::new()),
        }))
    }
    pub(crate) fn registration(&self, key: &[u8; 32]) -> Result<Registration> {
        ensure!(
            (self.admission)() && *key != self.operator_key,
            "stock exit unavailable"
        );
        let record = self
            .machines
            .get(&hex::encode(key))
            .context("stock key is not registered")?;
        let registration = Registration::capture(&record)?;
        ensure!(
            registration.ipv4 != self.config.operator_ipv4,
            "stock address is reserved"
        );
        // Duplicate IPs are never an authentication choice.
        ensure!(
            self.machines
                .snapshot()
                .values()
                .filter(|r| r.ipv4 == Some(registration.ipv4))
                .count()
                == 1,
            "ambiguous stock IP registration"
        );
        Ok(registration)
    }
    pub(crate) fn with_registration(
        &self,
        registration: &Registration,
        action: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        // Caller holds the canonical publication guard before this registry
        // guard. No await, disk work or registry mutation may occur here.
        self.machines.with_snapshot(|records| {
            let record = records
                .get(&hex::encode(registration.node_key))
                .context("stock registration removed")?;
            ensure!(
                Registration::capture(record)? == *registration,
                "stock registration rotated"
            );
            ensure!(
                records
                    .values()
                    .filter(|r| r.ipv4 == Some(registration.ipv4))
                    .count()
                    == 1,
                "ambiguous stock address"
            );
            action()
        })
    }
    pub(crate) fn current(&self, registration: &Registration) -> bool {
        self.registration(&registration.node_key)
            .is_ok_and(|current| current == *registration)
    }
    pub(crate) fn peer(self: &Arc<Self>, key: &[u8; 32]) -> Option<Arc<Peer>> {
        let registration = self.registration(key).ok()?;
        let mut peers = self.portals.lock();
        if let Some(peer) = peers.get(key) {
            if peer.registration == registration {
                return Some(peer.clone());
            }
        }
        peers.retain(|_, peer| peer.live());
        if peers.len() >= 4096 {
            return None;
        }
        let peer = Arc::new(Peer {
            session: registration.session().ok()?,
            registration,
            exit: Arc::downgrade(self),
        });
        peers.insert(*key, peer.clone());
        Some(peer)
    }
    pub(crate) fn adjacent(&self, a: &[u8; 32], b: &[u8; 32]) -> bool {
        if a == b {
            return false;
        }
        if *a == self.operator_key {
            self.registration(b).is_ok()
        } else if *b == self.operator_key {
            self.registration(a).is_ok()
        } else {
            false
        }
    }
}

impl Exit {
    pub(crate) fn install(
        config: Config,
        operator_key: [u8; 32],
        machines: Arc<MachineRegistry>,
        admission: crate::mesh_control::Admission,
        guard: Arc<dyn crate::payments::Guard>,
        relay: headscale_core::derp::native::NativeDerpRelay,
        (directory, policy): (
            &std::path::Path,
            &octravpn_mesh::headscale_api::policy::PolicyStore,
        ),
    ) -> Result<Arc<Self>> {
        use std::io::{Read, Write};
        config.validate()?;
        ensure!(operator_key != [0; 32], "stock operator key is zero");
        let private = directory.join("stock-exit");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&private) {
            Ok(()) => std::fs::File::open(directory)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&private)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "stock identity directory is not regular"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode().trailing_zeros() >= 6,
                "stock identity directory must be private"
            );
        }
        let directory = private.as_path();
        let path = directory.join("stock-exit-v1.json");
        let expected = serde_json::to_vec(&(
            1u8,
            config.operator_ipv4,
            config.portal_port,
            config.circle_gateway,
            operator_key,
        ))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(&expected)?;
                file.sync_all()?;
                std::fs::File::open(directory)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
                }
                let mut file = options.open(path)?;
                ensure!(
                    file.metadata()?.is_file() && file.metadata()?.len() <= 4096,
                    "invalid stock identity file"
                );
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                ensure!(
                    bytes == expected,
                    "stock operator identity or portal config changed"
                );
            }
            Err(error) => return Err(error.into()),
        }
        ensure!(
            !machines
                .snapshot()
                .values()
                .any(|r| r.ipv4 == Some(config.operator_ipv4)
                    && r.node_key_hex != hex::encode(operator_key)),
            "stock operator IP already allocated"
        );
        let disco = relay::Disco::open(directory)?;
        let key = hex::encode(operator_key);
        let mut record = MachineRecord::new_at(
            SystemTime::UNIX_EPOCH.into(),
            key.clone(),
            hex::encode(Sha256::digest(
                [b"Octranet virtual machine v1\0".as_slice(), &operator_key].concat(),
            )),
            "octranet-operator".into(),
            "octranet-exit".into(),
            config.operator_ipv4,
            false,
        );
        record.disco_key = Some(format!("discokey:{}", hex::encode(disco.public())));
        record.home_derp = 1;
        record.os = "linux".into();
        record.endpoints = config.endpoints.iter().map(ToString::to_string).collect();
        // Stock Tailscale requires both exit routes. IPv6 is deliberately
        // captured then refused; this implementation forwards IPv4 only.
        record.available_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
        record.approved_routes.clone_from(&record.available_routes);
        machines.upsert(key, record);
        let mut destinations = vec![
            format!("{}:*", config.operator_ipv4),
            "autogroup:internet:*".to_owned(),
        ];
        if config.circle_gateway {
            destinations.push(format!("{CIRCLE_GATEWAY}:443"));
        }
        let raw = serde_json::to_string(&serde_json::json!({"acls":[
            {"action":"accept","src":[config.operator_ipv4.to_string()],"dst":["*:*"]},
            {"action":"accept","src":["*"],"dst":destinations},
        ]}))?;
        policy.set(octravpn_mesh::policy::parse_hujson_policy(&raw)?, raw);
        let exit = Self::new(config, operator_key, machines, admission, guard, relay)?;
        *exit.disco.lock() = Some(disco);
        Ok(exit)
    }
}
