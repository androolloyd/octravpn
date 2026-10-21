//! Transport consent that can be checked before a channel ID exists.
use super::PrivateControl;
use crate::MultiRoutePins;
use anyhow::{ensure, Result};
use octravpn_core::{ip_tunnel, payments::PrivateTarget};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub control_url: String,
    pub control_ca_pem: String,
    pub control_spki: Vec<[u8; 32]>,
    pub wireguard_endpoint: String,
    pub pins: MultiRoutePins,
}
impl Endpoint {
    /// Parse endpoints and build pinned TLS trust without any network IO.
    pub fn control(&self, target: PrivateTarget) -> Result<PrivateControl> {
        crate::wireguard::validate_endpoint(&self.wireguard_endpoint)?;
        let origin = reqwest::Url::parse(&self.control_url)?;
        ensure!(
            ip_tunnel::public_ipv4(*self.pins.control.ip()),
            "private route control pin must be public IPv4"
        );
        crate::multihop::validate_route_pin(&self.wireguard_endpoint, &origin, self.pins)?;
        PrivateControl::new_pinned(
            &self.control_url,
            target,
            &self.control_ca_pem,
            self.control_spki.clone(),
            self.pins.control,
        )
    }
}
