//! Mandatory real-kernel branch when the dedicated qualification feature is
//! selected. Never enabled by a production configuration or an ordinary test.
use super::*;
use std::{net::SocketAddr, path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
};

const SERVER: &str = "octraprivsrv";
const CLIENT: &str = "octraprivcli";
pub(super) struct Addresses {
    pub browser: SocketAddr,
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
}
pub(super) struct Operator {
    pub wallet: Wallet,
    pub stop: watch::Sender<bool>,
    pub task: JoinHandle<Result<()>>,
    pub addresses: Addresses,
    pub source: Arc<Pool>,
}
pub(super) struct Client {
    pub plan: octravpn_client::AcceptedPrivatePlan,
    pub journal: PathBuf,
    pub receipt: Arc<KeyPair>,
    pub purchases: [String; 2],
}
struct Observation {
    status: octravpn_core::payments::SignedShieldedStatus,
    evidence: Value,
}
pub(super) fn configuration() -> octravpn_node::embedded::IpTunnelConfig {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "private kernel qualification requires isolated Linux"
    );
    let scope: Value = serde_json::from_slice(
        &std::fs::read("/evidence/kernel-scope.json")
            .expect("isolated kernel scope marker is required"),
    )
    .unwrap();
    assert_eq!(scope["fixture_only"], true);
    assert_eq!(scope["network_none"], true);
    octravpn_node::embedded::IpTunnelConfig {
        name: SERVER.into(),
        address_book: None,
    }
}
async fn python(args: &[&str]) -> Value {
    let output = tokio::time::timeout(
        Duration::from_secs(45),
        Command::new("python3")
            .arg("/usr/local/bin/private_kernel.py")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "kernel helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn topology() -> Child {
    let log = std::fs::File::create("/evidence/private-link.log").unwrap();
    let child = Command::new("python3")
        .args(["/usr/local/bin/private_kernel.py", "serve", SERVER])
        .stdin(Stdio::piped())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if std::fs::read("/evidence/private-link.json")
                .ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
                .is_some_and(|v| v["ready"] == true)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    child
}
async fn phase(client: &Client, number: u8) -> Observation {
    let options = || octravpn_client::PrivatePaymentOptions {
        plan: client.plan.clone(),
        journal: client.journal.clone(),
        receipt_key: client.receipt.clone(),
        interface_name: CLIENT.into(),
        mode: octravpn_client::JournalMode::Resume,
    };
    let opened = Box::pin(octravpn_client::PrivatePaymentClient::open(options()))
        .await
        .unwrap();
    let interface = opened.interface();
    assert_eq!(interface.name, CLIENT);
    let address = interface.address.to_string();
    let route = python(&["client", CLIENT, SERVER, &address]).await;
    assert_eq!(route["client_route"], CLIENT);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(opened.run(async move { stopped.await.map_err(anyhow::Error::from) }));
    let number_arg = number.to_string();
    let traffic = python(&["traffic", &address, &number_arg]).await;
    stop.send(()).unwrap();
    let summary = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(summary.confirmed_bytes[0] > 0);
    assert_eq!(summary.authorized_bytes, client.plan.prepaid_bytes);
    for ((used, held), cap) in summary
        .confirmed_bytes
        .iter()
        .zip(&summary.held_bytes)
        .zip(&summary.authorized_bytes)
    {
        assert!(used.checked_add(*held).unwrap() <= *cap);
    }
    let observed = Box::pin(octravpn_client::PreparedPrivateClient::new(options()))
        .await
        .unwrap();
    let status = observed.status().clone();
    assert_eq!(status.status.purchased_totals, client.plan.prepaid_bytes);
    assert!(status.status.committed_totals[0] > 0);
    assert_eq!(status.status.purchased_totals[1], 0);
    let evidence = json!({ "phase":number, "traffic":traffic, "route":route,
        "connection_sequence":status.status.connection.sequence,
        "purchased":status.status.purchased_totals, "committed":status.status.committed_totals,
        "held":status.status.held_totals, "service_sequence":status.status.service_sequence,
        "client_confirmed":summary.confirmed_bytes, "client_held":summary.held_bytes });
    drop(observed);
    Observation { status, evidence }
}
pub(super) async fn run(
    fixture: &mut Fixture,
    operator: Operator,
    client: Client,
) -> (watch::Sender<bool>, JoinHandle<Result<()>>) {
    let mut link = topology().await;
    let before = Box::pin(phase(&client, 1)).await;
    operator.stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), operator.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let channel = operator
        .wallet
        .channel(client.plan.binding.plan)
        .await
        .unwrap();
    let paid = channel.paid_ou;
    drop(operator.wallet);
    // Stopping the combined browser/VPN service revokes the node publication.
    // Reauthenticate the retained store, then publish a genuinely newer QC;
    // never keep an old funding capability live through service shutdown.
    assert!(fixture.node.snapshot().is_err());
    assert!(fixture.node.resume().await.unwrap());
    fixture.publish(vec![]).await;
    let wallet = Wallet::resume(
        &fixture.directory.path().join("private-runner-operator"),
        Key::from_bytes([200; 32]),
        operator.source,
    )
    .await
    .unwrap();
    assert_eq!(
        wallet
            .channel(client.plan.binding.plan)
            .await
            .unwrap()
            .paid_ou,
        paid
    );
    let service = fixture
        .node
        .bind_shielded_purchases(
            operator.addresses.browser,
            octravpn_node::payments::Config {
                control_listen: operator.addresses.control,
                tunnel_listen: operator.addresses.tunnel,
                data_dir: fixture.directory.path().join("private-runner-service"),
                operator_key: Arc::new(KeyPair::from_secret_bytes(&[11; 32])),
                wireguard_secret: x25519_dalek::StaticSecret::from([197; 32]),
                ip_tunnel: Some(configuration()),
            },
            &wallet,
            shielded::wallet::rpc::Policy {
                max_channels: 16,
                max_requests: 128,
                max_ceiling_ou: 100,
                max_invoice_lifetime_ms: 120_000,
            },
        )
        .await
        .unwrap();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(service.run(stopped));
    let after = Box::pin(phase(&client, 2)).await;
    assert!(after.status.status.connection.sequence > before.status.status.connection.sequence);
    assert!(after.status.status.service_sequence >= before.status.status.service_sequence);
    assert!(after.status.status.committed_totals[0] > before.status.status.committed_totals[0]);
    assert_eq!(
        after.status.status.purchased_totals,
        before.status.status.purchased_totals
    );
    assert_eq!(after.status.status.paid_ou, before.status.status.paid_ou);
    assert_eq!(
        wallet
            .channel(client.plan.binding.plan)
            .await
            .unwrap()
            .paid_ou,
        paid
    );
    drop(link.stdin.take());
    assert!(tokio::time::timeout(Duration::from_secs(5), link.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    let archived = super::exex::verify(
        &fixture.node,
        fixture.directory.path(),
        &client.purchases,
        client.plan.target.pool.program.display(),
    )
    .await;
    let report = json!({"kernel_flow_passed":true,"shielded_payments":true,
        "exex":archived,
        "operator_wallet_and_service_reopened":true,"client_journal_reopened":true,
        "before":before.evidence,"after":after.evidence,
        "scope":"in-process canonical four-validator signed-QC fixture, real pinned HTTPS, WireGuard/TUN and isolated second kernel; not public-network or multi-hop qualification"});
    std::fs::write(
        "/evidence/private-kernel.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    (stop, task)
}
