//! Native DERP wiring shared by the Hub and `mesh serve` entry points.

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Context, Result};
use headscale_core::derp::native::NativeDerpRelay;
use octravpn_mesh::tailscale_wire::{derp::NativeDerpRuntime, DerpMap, DerpRegion, DerpRegionNode};

const NATIVE_DERP_REGION_ID: u16 = 1;
const NATIVE_DERP_REGION_CODE: &str = "octra";
const NATIVE_DERP_REGION_NAME: &str = "OctraVPN native DERP";

pub(crate) fn load_native_derp_runtime(
    state_dir: impl AsRef<Path>,
) -> Result<Arc<NativeDerpRuntime>> {
    let key_path = state_dir.as_ref().join("derp.key");
    let runtime = NativeDerpRuntime::load_or_generate(&key_path, NativeDerpRelay::new())
        .with_context(|| format!("load native DERP key from {}", key_path.display()))?;
    Ok(Arc::new(runtime))
}

pub(crate) fn self_derp_map(host_name: impl Into<String>, derp_port: u16) -> DerpMap {
    let region = self_derp_region(host_name, derp_port);
    DerpMap {
        home_params: None,
        regions: HashMap::from([(NATIVE_DERP_REGION_ID, region)]),
        omit_default_regions: true,
    }
}

/// Build the single self-advertised native DERP region, pointing stock
/// Tailscale clients at `host_name:derp_port/derp`. `derp_port` MUST be
/// the port the DERP/HTTPS surface is actually bound to (see callers in
/// `hub/spawn.rs` and `cli/mesh.rs`); hardcoding 443 breaks operators who
/// serve DERP on a non-standard port.
fn self_derp_region(host_name: impl Into<String>, derp_port: u16) -> DerpRegion {
    let node = DerpRegionNode {
        name: NATIVE_DERP_REGION_ID.to_string(),
        region_id: NATIVE_DERP_REGION_ID,
        host_name: host_name.into(),
        cert_name: String::new(),
        ipv4: String::new(),
        ipv6: String::new(),
        derp_port,
        stun_port: -1,
        stun_only: false,
        insecure_for_tests: false,
        stun_test_ip: String::new(),
        can_port80: false,
    };
    DerpRegion {
        region_id: NATIVE_DERP_REGION_ID,
        region_code: NATIVE_DERP_REGION_CODE.to_string(),
        region_name: NATIVE_DERP_REGION_NAME.to_string(),
        latitude: 0.0,
        longitude: 0.0,
        avoid: false,
        no_measure_no_home: false,
        nodes: vec![node],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_derp_map_uses_passed_port_not_hardcoded_443() {
        // Regression: derp_port must reflect the port the DERP/HTTPS
        // surface actually binds, not a hardcoded 443. An operator on
        // e.g. --https-listen 0.0.0.0:8443 must advertise :8443, or
        // stock Tailscale clients dial host:443/derp -> nothing there.
        let map = self_derp_map("relay.example", 8443);
        let region = map
            .regions
            .get(&NATIVE_DERP_REGION_ID)
            .expect("self region present");
        let node = &region.nodes[0];
        assert_eq!(node.derp_port, 8443, "must advertise the passed port");
        assert_ne!(node.derp_port, 443, "must not hardcode 443");
        assert_eq!(node.host_name, "relay.example");
    }
}
