use super::*;
use crate::payments::Guard;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn operator_address_cannot_overlap_the_deterministic_client_pool() {
    let mut config = Config {
        operator_ipv4: "100.64.0.1".parse().unwrap(),
        portal_port: 443,
        circle_gateway: false,
        endpoints: vec![],
    };
    config.validate().unwrap();
    for address in [
        "100.64.0.0",
        "100.64.0.2",
        "100.64.0.9",
        "100.127.255.254",
        "100.127.255.255",
    ] {
        config.operator_ipv4 = address.parse().unwrap();
        assert!(config.validate().is_err(), "{address}");
    }
}
pub(super) struct Available(AtomicBool);
impl Guard for Available {
    fn live(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        ensure!(self.live(), "fixture host suspended");
        action()
    }
}
pub(super) fn register(machines: &MachineRegistry, key: [u8; 32], ip: Ipv4Addr) {
    let key = hex::encode(key);
    machines.upsert(
        key.clone(),
        MachineRecord::new_at(
            SystemTime::UNIX_EPOCH.into(),
            key,
            "02".repeat(32),
            "user".into(),
            "client".into(),
            ip,
            false,
        ),
    );
}
pub(super) fn fixture() -> (Arc<Exit>, Arc<Available>) {
    let machines = Arc::new(MachineRegistry::new());
    let guard = Arc::new(Available(AtomicBool::new(true)));
    let available = guard.clone();
    let exit = Exit::new(
        Config {
            operator_ipv4: "100.64.0.1".parse().unwrap(),
            portal_port: 443,
            circle_gateway: false,
            endpoints: vec![],
        },
        [9; 32],
        machines,
        Arc::new(move || available.live()),
        guard.clone(),
        headscale_core::derp::native::NativeDerpRelay::new(),
    )
    .unwrap();
    (exit, guard)
}
#[test]
fn registration_is_live_key_ip_machine_creation_expiry_and_host_bound() {
    let (exit, guard) = fixture();
    let key = [1; 32];
    register(&exit.machines, key, "100.64.0.2".parse().unwrap());
    let first = exit.peer(&key).unwrap();
    assert!(first.live());
    assert!(Arc::ptr_eq(&first, &exit.peer(&key).unwrap()));
    let mut record = exit.machines.get(&hex::encode(key)).unwrap();
    record.ipv4 = Some("100.64.0.3".parse().unwrap());
    exit.machines.upsert(hex::encode(key), record.clone());
    assert!(!first.live());
    let second = exit.peer(&key).unwrap();
    assert_ne!(first.session, second.session);
    record.machine_key_hex = "03".repeat(32);
    exit.machines.upsert(hex::encode(key), record.clone());
    assert!(!second.live());
    let third = exit.peer(&key).unwrap();
    record.created_at = SystemTime::now().into();
    exit.machines.upsert(hex::encode(key), record.clone());
    assert!(!third.live());
    let fourth = exit.peer(&key).unwrap();
    record.expiry = Some(SystemTime::UNIX_EPOCH.into());
    exit.machines.upsert(hex::encode(key), record.clone());
    assert!(!fourth.live());
    assert!(exit.peer(&key).is_none());
    record.expiry = None;
    exit.machines.upsert(hex::encode(key), record);
    let fifth = exit.peer(&key).unwrap();
    guard.0.store(false, Ordering::Release);
    assert!(!fifth.live());
    assert!(fifth.current(&mut || panic!("revoked portal IO")).is_err());
}
#[test]
fn operator_only_adjacency_does_not_grant_private_peer_free_relay() {
    let (exit, _guard) = fixture();
    let a = [1; 32];
    let b = [2; 32];
    register(&exit.machines, a, "100.64.0.2".parse().unwrap());
    register(&exit.machines, b, "100.64.0.3".parse().unwrap());
    assert!(exit.adjacent(&a, &exit.operator_key));
    assert!(exit.adjacent(&exit.operator_key, &b));
    assert!(!exit.adjacent(&a, &b));
    assert!(!exit.adjacent(&b, &a));
    assert!(!exit.adjacent(&exit.operator_key, &exit.operator_key));
    assert!(!exit.adjacent(&[8; 32], &exit.operator_key));
    let previous = exit.peer(&a).unwrap();
    register(&exit.machines, b, previous.registration.ipv4);
    assert!(!previous.live());
    assert!(!exit.adjacent(&a, &exit.operator_key));
}
#[test]
fn virtual_operator_identity_and_disco_secret_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        operator_ipv4: "100.64.0.1".parse().unwrap(),
        portal_port: 443,
        circle_gateway: false,
        endpoints: vec!["127.0.0.1:12345".parse().unwrap()],
    };
    let make = |config: Config, key: [u8; 32]| {
        let guard = Arc::new(Available(AtomicBool::new(true)));
        Exit::install(
            config,
            key,
            Arc::new(MachineRegistry::new()),
            Arc::new(|| true),
            guard,
            headscale_core::derp::native::NativeDerpRelay::new(),
            (
                directory.path(),
                &octravpn_mesh::headscale_api::policy::PolicyStore::new(),
            ),
        )
    };
    let first = make(config.clone(), [9; 32]).unwrap();
    let disco = first.disco.lock().as_ref().unwrap().public();
    let record = first
        .machines
        .get(&hex::encode(first.operator_key))
        .unwrap();
    assert_eq!(record.endpoints, ["127.0.0.1:12345"]);
    assert_eq!(record.approved_routes, ["0.0.0.0/0", "::/0"]);
    drop(first);
    let mut moved = config.clone();
    moved.endpoints.clear();
    let second = make(moved, [9; 32]).unwrap();
    assert_eq!(second.disco.lock().as_ref().unwrap().public(), disco);
    let mut changed = config;
    changed.operator_ipv4 = "100.64.0.9".parse().unwrap();
    assert!(make(changed, [9; 32]).is_err());
    assert!(make(second.config.clone(), [8; 32]).is_err());
}

#[test]
fn stock_map_policy_routes_only_the_operator_and_never_adds_private_client_adjacency() {
    use octravpn_mesh::headscale_api::policy::{PeerMapNode, PolicyStore};
    let directory = tempfile::tempdir().unwrap();
    let machines = Arc::new(MachineRegistry::new());
    let policy = PolicyStore::new();
    let guard = Arc::new(Available(AtomicBool::new(true)));
    let exit = Exit::install(
        Config {
            operator_ipv4: "100.64.0.1".parse().unwrap(),
            portal_port: 443,
            circle_gateway: true,
            endpoints: vec![],
        },
        [9; 32],
        machines.clone(),
        Arc::new(|| true),
        guard,
        headscale_core::derp::native::NativeDerpRelay::new(),
        (directory.path(), &policy),
    )
    .unwrap();
    register(&machines, [1; 32], "100.64.0.2".parse().unwrap());
    register(&machines, [2; 32], "100.64.0.3".parse().unwrap());
    let nodes = machines
        .snapshot()
        .values()
        .map(|r| PeerMapNode {
            id: r.stable_node_id(),
            addr: r.primary_addr_string().unwrap(),
            addrs: r.address_strings(),
            user: Some(r.user.clone()),
            tags: vec![],
            routes: if r.node_key_hex == hex::encode(exit.operator_key) {
                r.approved_routes.clone()
            } else {
                vec![]
            },
        })
        .collect::<Vec<_>>();
    let map = policy.build_peer_map(&nodes).unwrap();
    let id = |key: [u8; 32]| machines.get(&hex::encode(key)).unwrap().stable_node_id();
    assert!(!map[&id([1; 32])].contains(&id([2; 32])));
    assert!(!map[&id([2; 32])].contains(&id([1; 32])));
    assert!(map[&id([1; 32])].contains(&id([9; 32])));
    assert!(map[&id([2; 32])].contains(&id([9; 32])));
}

#[tokio::test(start_paused = true)]
async fn managed_map_online_presence_is_owned_by_the_live_operator_transport() {
    use octravpn_mesh::tailscale_wire::{self, noise::NoisePeerMachineKey};
    use octravpn_mesh::{PreauthMinter, ServerNoiseKey, TailnetIpAllocator, WireStateBuilder};
    let directory = tempfile::tempdir().unwrap();
    let machines = Arc::new(MachineRegistry::new());
    let policy = octravpn_mesh::headscale_api::policy::PolicyStore::new();
    let exit = Exit::install(
        Config {
            operator_ipv4: "100.64.0.1".parse().unwrap(),
            portal_port: 443,
            circle_gateway: false,
            endpoints: vec![],
        },
        [9; 32],
        machines.clone(),
        Arc::new(|| true),
        Arc::new(Available(AtomicBool::new(true))),
        headscale_core::derp::native::NativeDerpRelay::new(),
        (directory.path(), &policy),
    )
    .unwrap();
    register(&machines, [1; 32], "100.64.0.2".parse().unwrap());
    let node = machines
        .get(&hex::encode(exit.operator_key))
        .unwrap()
        .stable_node_id();
    let wire = WireStateBuilder::new(
        Arc::new(ServerNoiseKey::load_or_generate(directory.path()).unwrap()),
        Arc::new(PreauthMinter::new()),
        Arc::new(TailnetIpAllocator::new("stock-presence-test")),
        machines.clone(),
        Arc::new(policy),
        tailscale_wire::DerpMapStore::shared(tailscale_wire::DerpMap::default()),
    )
    .build();
    async fn online(wire: &tailscale_wire::WireState, node: u64) -> bool {
        let raw = serde_json::to_vec(
            &serde_json::json!({"Version":113,"NodeKey":format!("nodekey:{}",hex::encode([1;32]))}),
        )
        .unwrap();
        let response = tailscale_wire::map::handle_map_flat(
            axum::extract::State(wire.clone()),
            Some(axum::Extension(NoisePeerMachineKey("02".repeat(32)))),
            bytes::Bytes::from(raw),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let raw = axum::body::to_bytes(response.into_body(), 131_072)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        response["Peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["ID"].as_u64() == Some(node))
            .unwrap()["Online"]
            .as_bool()
            .unwrap()
    }
    assert!(
        !online(&wire, node).await,
        "binding a mesh does not establish a transport"
    );
    let task = tokio::spawn(exit.clone().run_relay("127.0.0.1:9".parse().unwrap()));
    for _ in 0..128 {
        if machines.is_stream_connected(node) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(machines.is_stream_connected(node));
    assert!(online(&wire, node).await);
    let first = machines.connection_generation(node).unwrap();
    task.abort();
    let _ = task.await;
    assert!(!machines.is_stream_connected(node));
    tokio::task::yield_now().await;
    let task = tokio::spawn(exit.clone().run_relay("127.0.0.1:9".parse().unwrap()));
    for _ in 0..128 {
        if machines.is_stream_connected(node) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(machines.is_stream_connected(node));
    assert!(machines.connection_generation(node).unwrap() > first);
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert!(
        online(&wire, node).await,
        "old offline generation must not revoke a replacement session"
    );
    task.abort();
    let _ = task.await;
    assert!(!machines.is_stream_connected(node));
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    assert!(!online(&wire, node).await);
}
