//! Sealed host-route intent. This records no command text or payment authority.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    version: u8,
    scope: [u8; 32],
    mark: u32,
    pub(super) namespace: Namespace,
    pub(super) bypasses: Vec<Bypass>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Namespace {
    pub boot: String,
    pub network: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bypass {
    pub address: Ipv4Addr,
    pub device: String,
    pub index: u64,
    pub gateway: Option<Ipv4Addr>,
}
impl Network {
    pub fn socket_mark(&self) -> u32 {
        self.mark
    }
    pub fn validate(&self, profiles: &[crate::PrivateRouteProfile]) -> Result<()> {
        ensure!(
            (2..=octravpn_core::onion::MAX_HOPS).contains(&profiles.len()),
            "network plan requires its original route"
        );
        let controls = profiles
            .iter()
            .map(|p| p.endpoint.pins.control)
            .collect::<Vec<_>>();
        let peers = profiles[1..]
            .iter()
            .map(|p| p.endpoint.pins.wireguard)
            .collect::<Vec<_>>();
        let names = profiles
            .iter()
            .map(|p| p.interface_name.clone())
            .collect::<Vec<_>>();
        self.bindings(
            profiles[0].endpoint.pins.wireguard,
            &controls,
            &peers,
            &names,
            self.mark,
        )
    }
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new(
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        names: &[String],
        mark: u32,
        namespace: Namespace,
        bypasses: Vec<Bypass>,
    ) -> Result<Self> {
        let plan = Self {
            version: 1,
            scope: scope(entry, controls, peers, names, mark)?,
            mark,
            namespace,
            bypasses,
        };
        plan.bindings(entry, controls, peers, names, mark)?;
        Ok(plan)
    }
    pub(super) fn bindings(
        &self,
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        names: &[String],
        mark: u32,
    ) -> Result<()> {
        ensure!(
            self.version == 1
                && self.mark == mark
                && mark != 0
                && self.scope == scope(entry, controls, peers, names, mark)?,
            "network plan belongs to another route"
        );
        ensure!(
            self.namespace.boot.len() == 36
                && self.namespace.boot.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
                && self.namespace.network != 0,
            "invalid kernel namespace identity"
        );
        let mut expected = BTreeSet::from([*entry.ip()]);
        if !controls[0].ip().is_loopback() {
            expected.insert(*controls[0].ip());
        }
        ensure!(
            self.bypasses.len() == expected.len(),
            "network bypass count differs"
        );
        for bypass in &self.bypasses {
            super::validate_interface(&bypass.device)?;
            ensure!(
                bypass.device != "tailscale0"
                    && !names.contains(&bypass.device)
                    && bypass.index > 0
                    && expected.remove(&bypass.address),
                "unaccepted network bypass"
            );
        }
        ensure!(expected.is_empty(), "network bypass missing");
        Ok(())
    }
}
fn scope(
    entry: SocketAddrV4,
    controls: &[SocketAddrV4],
    peers: &[SocketAddrV4],
    names: &[String],
    mark: u32,
) -> Result<[u8; 32]> {
    ensure!(
        (2..=octravpn_core::onion::MAX_HOPS).contains(&names.len())
            && controls.len() == names.len()
            && peers.len() + 1 == names.len(),
        "network route shape differs"
    );
    let mut hash = Sha256::new();
    hash.update(b"Octranet private route network v1\0");
    hash.update(serde_json::to_vec(&(entry, controls, peers, names, mark))?);
    Ok(hash.finalize().into())
}
