//! Exercise the executable's real adapters, including a validator returning
//! after the other three have continued to commit. No synthetic QCs or escrow.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer;
use octra_node::{devnet, devnet::Config};
use octra_node_protocol::transaction::{self, Nonce, OpType, Transaction};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, task::JoinHandle};

fn start(config: Config) -> (watch::Sender<bool>, JoinHandle<anyhow::Result<()>>) {
    let (stop, shutdown) = watch::channel(false);
    (
        stop,
        tokio::spawn(async move {
            let result = devnet::run(config, shutdown).await;
            if let Err(error) = &result {
                eprintln!("validator stopped: {error:#}");
            }
            result
        }),
    )
}
async fn epoch(http: &reqwest::Client, config: &Config) -> Option<u64> {
    http.get(format!("http://{}/status", config.rpc))
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
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn executable_devnet_transfers_browses_and_recovers() {
    let temp = tempfile::tempdir().unwrap();
    // Ask the OS for a candidate base; init checks every endpoint when running.
    let base = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .min(65000);
    let paths = devnet::init(&temp.path().join("network"), base)
        .await
        .unwrap();
    let configs = paths
        .iter()
        .map(|p| devnet::read(p).unwrap())
        .collect::<Vec<_>>();
    let mut running = configs.iter().cloned().map(start).collect::<Vec<_>>();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    for config in &configs {
        reached(&http, config, 2).await;
    }
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
    let before = epoch(&http, &configs[0]).await.unwrap();
    reached(&http, &configs[0], before + 3).await;
    eprintln!("checkpoint: quorum advanced with one validator stopped");
    running.push(start(configs[3].clone()));
    reached(&http, &configs[3], before + 4).await;
    eprintln!("checkpoint: restarted validator caught up");
    for (stop, task) in running {
        stopped(stop, task).await;
    }
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
