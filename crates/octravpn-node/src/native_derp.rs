//! Native DERP wiring shared by the Hub and `mesh serve` entry points.

use std::{collections::HashMap, path::Path, sync::Arc, time::SystemTime};

use anyhow::{ensure, Context, Result};
use headscale_core::derp::native::NativeDerpRelay;
use octravpn_mesh::{
    headscale_api::policy::{PeerMapNode, PolicyStore},
    tailscale_wire::{
        derp::NativeDerpRuntime, DerpMap, DerpRegion, DerpRegionNode, MachineRecord,
        MachineRegistry,
    },
};

const NATIVE_DERP_REGION_ID: u16 = 1;
const NATIVE_DERP_REGION_CODE: &str = "octra";
const NATIVE_DERP_REGION_NAME: &str = "OctraVPN native DERP";

#[cfg(test)]
mod transport_tests;

pub(crate) fn load_native_derp_runtime(
    state_dir: impl AsRef<Path>,
    noise_public: [u8; 32],
    machines: Arc<MachineRegistry>,
    policy: PolicyStore,
    admission: crate::mesh_control::Admission,
    members: Option<crate::members_policy::SharedMembership>,
) -> Result<Arc<NativeDerpRuntime>> {
    load_with_relay(
        state_dir,
        noise_public,
        machines,
        policy,
        admission,
        members,
        RelayPolicy {
            relay: NativeDerpRelay::new(),
            extra: None,
        },
    )
}

pub(crate) type PeerGate = Arc<dyn Fn(&[u8; 32], &[u8; 32]) -> bool + Send + Sync>;
pub(crate) struct RelayPolicy {
    pub relay: NativeDerpRelay,
    pub extra: Option<PeerGate>,
}
pub(crate) fn load_with_relay(
    state_dir: impl AsRef<Path>,
    noise_public: [u8; 32],
    machines: Arc<MachineRegistry>,
    policy: PolicyStore,
    admission: crate::mesh_control::Admission,
    members: Option<crate::members_policy::SharedMembership>,
    RelayPolicy { relay, extra }: RelayPolicy,
) -> Result<Arc<NativeDerpRuntime>> {
    let key_path = state_dir.as_ref().join("derp.key");
    let runtime = NativeDerpRuntime::load_or_generate(&key_path, relay)
        .with_context(|| format!("load native DERP key from {}", key_path.display()))?;
    ensure!(
        runtime.public_key() != noise_public,
        "DERP and Noise must use distinct keys"
    );
    let clients = machines.clone();
    let available = admission.clone();
    let client_members = members.clone();
    let runtime = runtime
        .with_client_verifier(move |key| {
            available()
                && clients
                    .get(&hex::encode(key))
                    .is_some_and(|record| live(&record, client_members.as_ref()))
        })
        .with_peer_verifier(move |source, destination| {
            admission()
                && extra.as_ref().is_none_or(|gate| gate(source, destination))
                && peer_allowed(&machines, &policy, members.as_ref(), source, destination)
        });
    Ok(Arc::new(runtime))
}

fn live(record: &MachineRecord, members: Option<&crate::members_policy::SharedMembership>) -> bool {
    record
        .expiry
        .is_none_or(|expiry| SystemTime::now() < SystemTime::from(expiry))
        && members.is_none_or(|members| {
            members
                .admit(&record.node_key_hex, &record.machine_key_hex)
                .is_ok()
        })
}

/// DERP sees encrypted WireGuard packets. This enforces peer adjacency, not
/// destination ports, billable bytes or Internet delivery.
fn peer_allowed(
    machines: &MachineRegistry,
    policy: &PolicyStore,
    members: Option<&crate::members_policy::SharedMembership>,
    source: &[u8; 32],
    destination: &[u8; 32],
) -> bool {
    let source = hex::encode(source);
    let destination = hex::encode(destination);
    let snapshot = machines.snapshot();
    let (Some(source), Some(destination)) = (snapshot.get(&source), snapshot.get(&destination))
    else {
        return false;
    };
    if !live(source, members) || !live(destination, members) {
        return false;
    }
    let nodes = [peer(source), peer(destination)];
    policy.build_peer_map(&nodes).is_some_and(|map| {
        map.get(&nodes[0].id)
            .is_some_and(|peers| peers.contains(&nodes[1].id))
    })
}

fn peer(record: &MachineRecord) -> PeerMapNode {
    use octravpn_mesh::tailscale_wire::routes::{active_approved_routes, active_exit_routes};
    let mut routes = active_approved_routes(&record.available_routes, &record.approved_routes);
    routes.extend(active_exit_routes(
        &record.available_routes,
        &record.approved_routes,
    ));
    routes.sort();
    routes.dedup();
    PeerMapNode {
        id: record.stable_node_id(),
        addr: record.primary_addr_string().unwrap_or_default(),
        addrs: record.address_strings(),
        user: (!record.user.is_empty()).then(|| record.user.clone()),
        tags: record.forced_tags.clone(),
        routes,
    }
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
    use chrono::{Duration, Utc};
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicBool, Ordering},
    };

    fn register(machines: &MachineRegistry, key: [u8; 32], user: &str, last: u8) {
        let key = hex::encode(key);
        machines.upsert(
            key.clone(),
            MachineRecord::new_at(
                Utc::now(),
                key,
                "machine".into(),
                user.into(),
                user.into(),
                Ipv4Addr::new(100, 64, 0, last),
                false,
            ),
        );
    }

    fn policy(store: &PolicyStore, raw: &str) {
        store.set(
            octravpn_mesh::policy::parse_hujson_policy(raw).unwrap(),
            raw.into(),
        );
    }

    #[test]
    fn relay_refuses_unknown_expired_and_unavailable_clients() {
        let directory = tempfile::tempdir().unwrap();
        let machines = Arc::new(MachineRegistry::new());
        let available = Arc::new(AtomicBool::new(true));
        let observed = available.clone();
        let relay = load_native_derp_runtime(
            directory.path(),
            [0; 32],
            machines.clone(),
            PolicyStore::new(),
            Arc::new(move || observed.load(Ordering::SeqCst)),
            None,
        )
        .unwrap();
        let key = [1; 32];
        assert!(relay.client_verification_enabled());
        assert!(relay.peer_verification_enabled());
        assert!(!relay.admit_client(&key));
        register(&machines, key, "alice", 1);
        assert!(relay.admit_client(&key));
        available.store(false, Ordering::SeqCst);
        assert!(!relay.admit_client(&key));
        available.store(true, Ordering::SeqCst);
        let mut record = machines.get(&hex::encode(key)).unwrap();
        record.expiry = Some(Utc::now() - Duration::seconds(1));
        machines.upsert(hex::encode(key), record);
        assert!(!relay.admit_client(&key));
    }

    #[test]
    fn relay_peer_policy_is_explicit_live_and_bound_to_both_registered_keys() {
        let directory = tempfile::tempdir().unwrap();
        let machines = Arc::new(MachineRegistry::new());
        let store = PolicyStore::new();
        let relay = load_native_derp_runtime(
            directory.path(),
            [0; 32],
            machines.clone(),
            store.clone(),
            Arc::new(|| true),
            None,
        )
        .unwrap();
        let alice = [1; 32];
        let bob = [2; 32];
        let carol = [3; 32];
        register(&machines, alice, "alice", 1);
        register(&machines, bob, "bob", 2);
        register(&machines, carol, "carol", 3);
        assert!(
            !relay.admit_peer(&alice, &bob),
            "missing ACL cannot grant relay traffic"
        );
        policy(
            &store,
            r#"{"acls":[{"action":"accept","src":["100.64.0.1"],"dst":["100.64.0.2:443"]}]}"#,
        );
        assert!(relay.admit_peer(&alice, &bob));
        assert!(
            relay.admit_peer(&bob, &alice),
            "peer adjacency permits response packets"
        );
        assert!(!relay.admit_peer(&alice, &carol));
        assert!(!relay.admit_peer(&carol, &bob));
        assert!(!relay.admit_peer(&alice, &[4; 32]));
        assert!(!relay.admit_peer(&alice, &alice));
        policy(&store, r#"{"acls":[]}"#);
        assert!(!relay.admit_peer(&alice, &bob));
        policy(
            &store,
            r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
        );
        assert!(relay.admit_peer(&alice, &bob));
        let mut record = machines.get(&hex::encode(bob)).unwrap();
        record.expiry = Some(Utc::now() - Duration::seconds(1));
        machines.upsert(hex::encode(bob), record);
        assert!(!relay.admit_peer(&alice, &bob));
        assert!(!relay.admit_peer(&bob, &alice));
    }

    #[test]
    fn derp_key_must_not_reuse_noise_identity() {
        let directory = tempfile::tempdir().unwrap();
        let machines = Arc::new(MachineRegistry::new());
        let relay = load_native_derp_runtime(
            directory.path(),
            [0; 32],
            machines.clone(),
            PolicyStore::new(),
            Arc::new(|| true),
            None,
        )
        .unwrap();
        assert!(load_native_derp_runtime(
            directory.path(),
            relay.public_key(),
            machines,
            PolicyStore::new(),
            Arc::new(|| true),
            None
        )
        .is_err());
    }

    #[test]
    fn relay_routed_adjacency_requires_active_approved_routes() {
        let machines = MachineRegistry::new();
        let store = PolicyStore::new();
        let alice = [1; 32];
        let router = [2; 32];
        register(&machines, alice, "alice", 1);
        register(&machines, router, "router", 2);
        policy(
            &store,
            r#"{"acls":[{"action":"accept","src":["100.64.0.1"],"dst":["10.20.0.0/24:*"]}]}"#,
        );
        let mut record = machines.get(&hex::encode(router)).unwrap();
        record.available_routes = vec!["10.20.0.0/24".into()];
        machines.upsert(hex::encode(router), record.clone());
        assert!(!peer_allowed(&machines, &store, None, &alice, &router));
        record.approved_routes = record.available_routes.clone();
        machines.upsert(hex::encode(router), record.clone());
        assert!(peer_allowed(&machines, &store, None, &alice, &router));
        record.available_routes.clear();
        machines.upsert(hex::encode(router), record);
        assert!(!peer_allowed(&machines, &store, None, &alice, &router));
    }

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
