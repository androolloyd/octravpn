//! Exercise the executable's real adapters, including a validator returning
//! after the other three have continued to commit. No synthetic QCs or escrow.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer;
use octra_node::{devnet, devnet::Config};
use octra_node_protocol::transaction::{self, Nonce, OpType, Transaction};
use std::{
    net::{Ipv4Addr, TcpListener, UdpSocket},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, task::JoinHandle};

fn start(config: Config) -> (watch::Sender<bool>, JoinHandle<anyhow::Result<()>>) {
    let (stop, mut shutdown) = watch::channel(false);
    (
        stop,
        tokio::spawn(async move {
            let path = config.data.join("process-test.json");
            std::fs::write(&path, serde_json::to_vec(&config)?)?;
            let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_octra-node"))
                .args(["run", "--config"])
                .arg(path)
                // Transport admission is distinct from validator authority.
                .env("OCTRA_CONSENSUS_ALLOW_DYNAMIC_PEERS", "1")
                .env_remove("OCTRA_JOIN_RPC")
                .env_remove("OCTRA_STATE_SYNC_SOURCES")
                .env_remove("OCTRA_OBSERVER_RELAY_SUBMITS")
                .env_remove("OCTRA_OPERATOR_RPC_URL")
                .kill_on_drop(true)
                .spawn()?;
            let status = tokio::select! {
                status = child.wait() => status?,
                _ = shutdown.changed() => {
                    let pid = child.id().ok_or_else(|| anyhow::anyhow!("node already exited"))?;
                    anyhow::ensure!(tokio::process::Command::new("kill")
                        .args(["-TERM", &pid.to_string()]).status().await?.success(),
                        "node termination signal failed");
                    child.wait().await?
                }
            };
            anyhow::ensure!(status.success(), "node exited with {status}");
            Ok(())
        }),
    )
}
async fn epoch(http: &reqwest::Client, config: &Config) -> Option<u64> {
    http.get(format!("http://{}/operator/status", config.rpc))
        .send()
        .await
        .ok()?
        .json::<serde_json::Value>()
        .await
        .ok()?["epoch"]
        .as_u64()
}
async fn reached(http: &reqwest::Client, config: &Config, target: u64) {
    tokio::time::timeout(Duration::from_secs(90), async {
        while epoch(http, config).await.unwrap_or(0) < target {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} did not reach epoch {target}", config.rpc));
}
async fn stopped(stop: watch::Sender<bool>, task: JoinHandle<anyhow::Result<()>>) {
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
fn archive(path: &Path, height: u64) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(path.join("exex").join(format!("{height:016x}.json"))).unwrap(),
    )
    .unwrap()
}

struct Ports {
    base: u16,
    _tcp: Vec<TcpListener>,
    _udp: Vec<UdpSocket>,
}

impl Ports {
    fn reserve() -> Self {
        // Stay below the ephemeral range used by outgoing peer connections.
        // Reserve the four validators and a nonmember observer until configured.
        let start = u16::try_from(std::process::id() % 120).unwrap();
        for offset in 0..120 {
            let base = 24_000 + ((start + offset) % 120) * 50;
            let mut tcp = Vec::new();
            let mut udp = Vec::new();
            let reserved = (0..5).all(|node| {
                let port = base + node * 10;
                for endpoint in [0, 1, 2, 3, 5, 6, 7] {
                    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port + endpoint))
                    else {
                        return false;
                    };
                    tcp.push(listener);
                }
                let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, port + 4)) else {
                    return false;
                };
                udp.push(socket);
                true
            });
            if reserved {
                return Self {
                    base,
                    _tcp: tcp,
                    _udp: udp,
                };
            }
        }
        panic!("no free five-node port block in 24000..30000");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn executable_devnet_transfers_browses_and_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let ports = Ports::reserve();
    let paths = devnet::init(&temp.path().join("network"), ports.base)
        .await
        .unwrap();
    let token_file = temp.path().join("mesh-admin.token");
    std::fs::write(&token_file, b"native-mesh-test-token").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let configs = paths
        .iter()
        .enumerate()
        .map(|(index, p)| {
            let mut config = devnet::read(p).unwrap();
            config.gateway = Some(octra_node::gateway::Config {
                listen: (std::net::Ipv4Addr::LOCALHOST, config.p2p.port() + 5).into(),
                origin: "https://circles.example.ts.net".into(),
                sites: std::collections::BTreeMap::new(),
            portal: None,
            });
            if index == 3 {
                config.mesh = Some(octravpn_node::mesh_control::Config {
                    state_dir: config.data.join("mesh"),
                    admin_token_file: Some(token_file.clone()),
                    http_addr: Some((Ipv4Addr::LOCALHOST, config.p2p.port() + 6).into()),
                    https_addr: Some((Ipv4Addr::LOCALHOST, config.p2p.port() + 7).into()),
                    dns: Some(
                        serde_json::from_value(serde_json::json!({
                            "base_domain":"octranet.test", "override_local_dns":false, "extra_records":[{
                                "name":"circles.octranet.test", "type":"A", "value":"100.64.0.1"
                            }]
                        }))
                        .unwrap(),
                    ),
                    ..Default::default()
                });
            }
            config
        })
        .collect::<Vec<_>>();
    let mut observer = configs[0].clone();
    observer.voting = false;
    observer.data = temp.path().join("observer");
    std::fs::create_dir(&observer.data).unwrap();
    observer.key = observer.data.join("observer.key");
    let identity = octra_node::identity::create(&observer.key).unwrap();
    let observer_key = std::fs::read(&observer.key).unwrap();
    let observer_address = identity["address"].as_str().unwrap();
    let observer_prefix = format!("{observer_address}:");
    assert!(observer
        .genesis
        .validators
        .iter()
        .all(|entry| !entry.starts_with(&observer_prefix)));
    let socket = |offset| (Ipv4Addr::LOCALHOST, ports.base + 40 + offset).into();
    observer.p2p = socket(0);
    observer.rpc = socket(1);
    observer.browser = socket(2);
    observer.control = socket(3);
    observer.tunnel = socket(4);
    observer.gateway.as_mut().unwrap().listen = socket(5);
    observer.peers = configs.iter().map(|config| config.p2p).collect();
    drop(ports);
    let mut running = configs.iter().cloned().map(start).collect::<Vec<_>>();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    for config in &configs {
        reached(&http, config, 2).await;
        let diagnostics: serde_json::Value = http
            .get(format!("http://{}/operator/peers", config.rpc))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(diagnostics["connected"].is_number());
        assert!(diagnostics["score_reasons"].is_object());
    }
    let mesh = configs[3].mesh.as_ref().unwrap();
    let mesh_base = format!("http://{}", mesh.http_addr.unwrap());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if http
                .get(format!("{mesh_base}/key?v=113"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    let mesh_key = http
        .get(format!("{mesh_base}/key?v=113"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let policy = "// native-node persistent ACL\n{\"acls\":[]}";
    assert_eq!(
        http.put(format!("{mesh_base}/api/v1/policy"))
            .bearer_auth("native-mesh-test-token")
            .body(policy)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let certificate = std::fs::read(mesh.state_dir.join("tls.crt")).unwrap();
    let tls = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .add_root_certificate(reqwest::Certificate::from_pem(&certificate).unwrap())
        .build()
        .unwrap();
    let tls_response = tls
        .get(format!(
            "https://localhost:{}/key?v=113",
            mesh.https_addr.unwrap().port()
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(tls_response, mesh_key);
    let mut stalled_tls = tokio::net::TcpStream::connect(mesh.https_addr.unwrap())
        .await
        .unwrap();
    let browser = format!("http://{}/open", configs[0].browser);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = http
                .get(&browser)
                .query(&[(
                    "u",
                    format!("oct://{}/index.html", configs[0].genesis.circle),
                )])
                .send()
                .await
                .unwrap();
            if !response.status().is_success() {
                continue;
            }
            let shell = response.text().await.unwrap();
            let asset = shell
                .split("<iframe")
                .nth(1)
                .unwrap()
                .split("src=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let response = http
                .get(format!("http://{}{asset}", configs[0].browser))
                .send()
                .await
                .unwrap();
            if !response.status().is_success() {
                continue;
            }
            assert!(response.text().await.unwrap().contains("Octra Rust devnet"));
            break;
        }
    })
    .await
    .unwrap();
    eprintln!("checkpoint: quorum and committed Circle asset");
    gateway_read(&http, &configs[0]).await;
    let key = devnet::read_key(&configs[0].faucet).unwrap();
    let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
    let mut tx = Transaction {
        from: transaction::address_from_public_key(&public),
        to: configs[0].genesis.circle.as_bytes().to_vec(),
        amount: 100.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 1000.into(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64(),
        signature: vec![],
        public_key: Some(public),
        message: None,
        encrypted_data: None,
        op_type: OpType::Standard,
    };
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    // Commits may invalidate a capture between proof preparation and insertion.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = http
                .post(format!("http://{}/transactions", configs[0].rpc))
                .header("content-type", "application/json")
                .body(tx.to_json_bytes().unwrap())
                .send()
                .await
                .unwrap();
            if response.status() == reqwest::StatusCode::ACCEPTED {
                break;
            }
            let error = response.text().await.unwrap();
            assert!(
                error.contains("stale")
                    || error.contains("busy")
                    || error.contains("publishing")
                    || error.contains("advanced")
                    || error.contains("revoked"),
                "submission: {error}"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let result = http
                .get(format!(
                    "http://{}/account/{}",
                    configs[1].rpc, configs[0].genesis.circle
                ))
                .send()
                .await
                .unwrap();
            if result.status().is_success()
                && result.json::<serde_json::Value>().await.unwrap()["balance"] == "100"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    eprintln!("checkpoint: signed transfer committed on a peer");
    let (stop, task) = running.pop().unwrap();
    stopped(stop, task).await;
    assert!(TcpListener::bind(mesh.http_addr.unwrap()).is_ok());
    assert!(TcpListener::bind(mesh.https_addr.unwrap()).is_ok());
    use tokio::io::AsyncReadExt;
    let mut buffer = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), stalled_tls.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let before = epoch(&http, &configs[0]).await.unwrap();
    reached(&http, &configs[0], before + 3).await;
    eprintln!("checkpoint: quorum advanced with one validator stopped");
    running.push(start(configs[3].clone()));
    reached(&http, &configs[3], before + 4).await;
    eprintln!("checkpoint: restarted validator caught up");
    gateway_read(&http, &configs[3]).await;
    let restored: serde_json::Value = http
        .get(format!("{mesh_base}/api/v1/policy"))
        .bearer_auth("native-mesh-test-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored["loaded"], true);
    assert_eq!(restored["raw"], policy);
    assert_eq!(
        http.get(format!("{mesh_base}/key?v=113"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        mesh_key
    );
    eprintln!("checkpoint: native mesh TLS, stable Noise identity and persisted ACL recovered");
    let (stop, task) = start(observer.clone());
    reached(&http, &observer, before + 4).await;
    gateway_read(&http, &observer).await;
    let mut refused = tx.clone();
    refused.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    refused.signature = STANDARD
        .encode(key.sign(&refused.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let response = http
                .post(format!("http://{}/rpc", observer.rpc))
                .json(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "method": "octra_submit",
                    "params": [serde_json::from_slice::<serde_json::Value>(&refused.to_json_bytes().unwrap()).unwrap()]
                }))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let value = response.json::<serde_json::Value>().await.unwrap();
            if value["error"]["code"] == 117 {
                break;
            }
            let error = value.to_string();
            assert!(
                error.contains("stale")
                    || error.contains("busy")
                    || error.contains("publishing")
                    || error.contains("advanced")
                    || error.contains("revoked")
                    || error.contains("transaction admission unavailable:"),
                "observer submission: {error}"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    let observed = epoch(&http, &observer).await.unwrap();
    stopped(stop, task).await;
    reached(&http, &configs[0], observed + 2).await;
    let (stop, task) = start(observer.clone());
    reached(&http, &observer, observed + 2).await;
    gateway_read(&http, &observer).await;
    stopped(stop, task).await;
    assert!(std::fs::read(&observer.key).unwrap() == observer_key);
    eprintln!("checkpoint: nonmember observer served, refused RPC submissions and recovered");
    for (stop, task) in running {
        stopped(stop, task).await;
    }
    // Payment deadlines use the authenticated header clock, including after
    // recovery. Neither a local commit date nor a substituted head can supply it.
    let store = octra_node_runtime::canonical::CanonicalStore::open(
        &configs[0].data.join("canonical.db"),
        &configs[0].genesis.chain,
    )
    .await
    .unwrap();
    let head = store.head().await.unwrap();
    use octra_node_protocol::consensus::{codec::Wire, Finalize};
    let certificate = store.certificate(head.cursor.sequence).await.unwrap();
    let finalized = Finalize::decode(&certificate).unwrap();
    let clock =
        octra_node_protocol::consensus::policy::time_of_seconds(finalized.header.ts).unwrap();
    assert!(clock > 0);
    let reader = store.reader();
    assert_eq!(reader.epoch_time_ms(&head).await.unwrap(), Some(clock));
    let mut substituted = head.clone();
    substituted.date += 1;
    assert!(reader.epoch_time_ms(&substituted).await.is_err());
    store.close().await;
    for config in &configs[1..] {
        assert_eq!(archive(&configs[0].data, 2), archive(&config.data, 2));
    }
    let hash = hex::encode(tx.hash().unwrap());
    let delivered = std::fs::read_dir(configs[0].data.join("exex"))
        .unwrap()
        .map(|p| {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(p.unwrap().path()).unwrap())
                .unwrap()
        })
        .find(|event| {
            event["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tx| tx["hash"] == hash)
        })
        .expect("signed transfer missing from ExEx");
    let height = delivered["cursor"]["epoch"].as_u64().unwrap();
    for config in &configs[1..] {
        assert_eq!(delivered, archive(&config.data, height));
    }
    assert!(configs
        .iter()
        .all(|c| c.data.join("validator_journal.lock").exists()));
}

async fn gateway_read(http: &reqwest::Client, config: &Config) {
    let timeout = if config.voting { 10 } else { 90 };
    tokio::time::timeout(Duration::from_secs(timeout), async {
        loop {
            let response = http
                .get(format!(
                    "http://{}/circles/{}/index.html",
                    config.gateway.as_ref().unwrap().listen,
                    config.genesis.circle
                ))
                .header("host", "circles.example.ts.net")
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                // RPC becomes reachable before the remaining service sockets.
                Err(error) if error.is_connect() => {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    continue;
                }
                Err(error) => panic!("gateway request failed: {error}"),
            };
            if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                tokio::time::sleep(Duration::from_millis(30)).await;
                continue;
            }
            assert!(response.status().is_success());
            assert_eq!(
                response.headers()["x-octra-chain"],
                config.genesis.chain.chain_id
            );
            assert!(
                response.headers()["x-octra-epoch"]
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    >= 2
            );
            let document = response.text().await.unwrap();
            assert!(document.contains("Octra Rust devnet"));
            assert!(!document.contains("<iframe"));
            break;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn genesis_settings_cannot_reuse_a_chain_identity() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("network");
    let paths = devnet::init(&directory, 19870).await.unwrap();
    let mut config = devnet::read(&paths[0]).unwrap();
    let key = std::fs::read(&config.key).unwrap();
    assert!(devnet::init(&directory, 19870).await.is_err());
    assert_eq!(key, std::fs::read(&config.key).unwrap());
    config.genesis.validators.remove(0);
    let (_stop, shutdown) = watch::channel(false);
    let error = devnet::run(config, shutdown).await.unwrap_err();
    assert!(error.to_string().contains("genesis commitment differs"));
}
