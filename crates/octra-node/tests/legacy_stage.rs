//! Opt-in full acquisition/staging against private real native physical stores.
//! The physical qualifier creates/certifies each source and pins its backend;
//! these actual TCP peers use only fixed development signing keys.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node::legacy_repair::{stage_if_proven, StageOptions};
use octra_node_protocol::{
    consensus::{codec::Wire, hash, profile::Settings, EpochRootQuery, EpochRootResponse},
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{Config, Handler, MessageFuture, Swarm},
    },
    transaction,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{net::TcpListener, task::JoinHandle};

const CHAIN: &[u8] = b"legacy-repair-fixture";
const NAME: &str = "signed_peer_selection_stages_only_an_unprotected_native_empty_suffix";
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn address(seed: u8) -> Vec<u8> {
    transaction::address_from_public_key(
        STANDARD
            .encode(key(seed).verifying_key().as_bytes())
            .as_bytes(),
    )
}
fn variables() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("OCTRA_CHAIN_ID".into(), CHAIN.to_vec()),
        ("OCTRA_CONSENSUS_CONFIG_HASH".into(), vec![b'1'; 64]),
        (
            "OCTRA_VALIDATORS".into(),
            (1..=4)
                .map(|seed| {
                    format!(
                        "{}:{}",
                        std::str::from_utf8(&address(seed)).unwrap(),
                        STANDARD.encode(key(seed).verifying_key().as_bytes())
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
        ),
        ("OCTRA_QUARANTINE_AHEAD_GRACE_EPOCHS".into(), b"0".to_vec()),
        (
            "OCTRA_QUARANTINE_AHEAD_DRIFT_TOLERANCE".into(),
            b"0".to_vec(),
        ),
    ])
}
struct Server {
    seed: u8,
    mode: String,
    target: [u8; 32],
    source: [u8; 32],
    changed: Arc<AtomicBool>,
    directory: PathBuf,
    current_queries: Arc<AtomicUsize>,
    target_queries: Arc<AtomicUsize>,
}
impl Handler for Server {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let seed = self.seed;
        let mode = self.mode.clone();
        let target = self.target;
        let source = self.source;
        let changed = self.changed.clone();
        let directory = self.directory.clone();
        let current_queries = self.current_queries.clone();
        let target_queries = self.target_queries.clone();
        Box::pin(async move {
            if frame.message != 0x34 {
                return Ok(());
            }
            let query = EpochRootQuery::decode(&frame.payload).unwrap();
            assert_eq!(query.chain_id, CHAIN);
            assert!(matches!(query.epoch_id, 0 | 1));
            if query.epoch_id == 0 {
                target_queries.fetch_add(1, Ordering::SeqCst);
            } else {
                current_queries.fetch_add(1, Ordering::SeqCst);
            }
            if query.epoch_id == 0
                && mode == "source-changed"
                && !changed.swap(true, Ordering::SeqCst)
            {
                let path = directory.join("HEAD.json");
                let mut head: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                head["ts"] = json!(1.);
                std::fs::write(path, serde_json::to_vec(&head).unwrap()).unwrap();
            }
            let root = if query.epoch_id == 1 {
                (mode == "current-root").then_some(source.to_vec())
            } else if mode == "weak-target" && seed == 4 {
                None
            } else if mode == "target-mismatch" {
                let mut root = target;
                root[0] ^= 1;
                Some(root.to_vec())
            } else {
                Some(target.to_vec())
            };
            let mut response = EpochRootResponse {
                chain_id: CHAIN.to_vec(),
                epoch_id: query.epoch_id,
                state_root: root,
                responder_addr: if mode == "unknown-signer" {
                    b"not-a-configured-validator".to_vec()
                } else {
                    address(seed)
                },
                responder_head_epoch: 0,
                signature: vec![],
            };
            response.signature = key(seed)
                .sign(&hash::epoch_root_response_sign_bytes(&response).unwrap())
                .to_bytes()
                .to_vec();
            if mode == "bad-signature" {
                response.signature[0] ^= 1;
            }
            peer.enqueue_wait(Frame {
                message: 0x35,
                payload: response.encode().unwrap(),
            })
            .await;
            Ok(())
        })
    }
}
struct Running {
    swarm: Swarm,
    task: JoinHandle<()>,
    current_queries: Arc<AtomicUsize>,
    target_queries: Arc<AtomicUsize>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
async fn server(
    seed: u8,
    mode: &str,
    target: [u8; 32],
    source: [u8; 32],
    directory: &Path,
    changed: Arc<AtomicBool>,
    config_hash: &[u8],
) -> (Running, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = listener.local_addr().unwrap();
    let swarm = Swarm::new(
        Config {
            chain_id: CHAIN.to_vec(),
            node_address: address(seed),
            config_hash: config_hash.to_vec(),
            binary_hash: vec![0; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: (1..=4)
                .map(|n| key(n).verifying_key().to_bytes().to_vec())
                .collect(),
            bootstrap: vec![],
            maximum_validators: 4,
            advertised: Endpoint {
                host: b"127.0.0.1".to_vec(),
                port: socket.port(),
            },
            timeouts: Timeouts::default(),
            head: Arc::new(move || (0, target)),
        },
        key(seed),
    )
    .unwrap();
    let current_queries = Arc::new(AtomicUsize::new(0));
    let target_queries = Arc::new(AtomicUsize::new(0));
    let dispatch = Arc::new(Server {
        seed,
        mode: mode.to_owned(),
        target,
        source,
        changed,
        directory: directory.to_owned(),
        current_queries: current_queries.clone(),
        target_queries: target_queries.clone(),
    });
    let runner = swarm.clone();
    (
        Running {
            swarm,
            current_queries,
            target_queries,
            task: tokio::spawn(async move {
                runner.run(listener, dispatch).await.unwrap();
            }),
        },
        socket.to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a fresh pinned native physical fixture from legacy-repair-qualify.py"]
async fn signed_peer_selection_stages_only_an_unprotected_native_empty_suffix() -> Result<()> {
    let metadata = PathBuf::from(std::env::var("OCTRA_LEGACY_STAGE_FIXTURE")?);
    let fixture: Value = serde_json::from_slice(&std::fs::read(&metadata)?)?;
    assert_eq!(fixture["schema"], "octra-legacy-stage-test-v1");
    assert_eq!(fixture["test"], NAME);
    assert_eq!(fixture["test_only"], true);
    let directory = PathBuf::from(
        fixture["directory"]
            .as_str()
            .context("fixture directory missing")?,
    );
    assert!(directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("stage-"));
    assert_eq!(directory.parent().and_then(Path::parent), metadata.parent());
    let source_head = std::fs::read(directory.join("HEAD.json"))?;
    assert_eq!(
        hex::encode(Sha256::digest(&source_head)),
        fixture["source_head_sha256"]
    );
    assert!(!directory.join("fork_repair.json").exists());
    let plan = &fixture["plan"];
    assert_eq!(plan["source"]["epoch_id"], 1);
    assert_eq!(plan["head"]["epoch_id"], 0);
    let root = |value: &Value| -> Result<[u8; 32]> {
        hex::decode(value.as_str().context("fixture root missing")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("fixture root length"))
    };
    let target = root(&plan["head"]["state_root"])?;
    let source = root(&plan["source"]["state_root"])?;
    let mode = fixture["mode"].as_str().context("fixture mode missing")?;
    assert!([
        "positive",
        "current-root",
        "weak-target",
        "bad-signature",
        "unknown-signer",
        "target-mismatch",
        "source-changed",
        "protected-prepare",
        "protected-commit",
        "protected-aborted",
        "missing-finality",
        "tampered-qc",
        "origin-mismatch",
        "environment-mismatch"
    ]
    .contains(&mode));
    let values = variables();
    let settings = Settings::from_values(values.clone())?;
    let crypto = hex::encode(octra_hfhe::seeded_rng::aes_kat()).into_bytes();
    let profile = settings.hash(CHAIN, 2, &crypto)?;
    let config_hash = hash::network_hash(CHAIN, None, Some(&profile.to_vec()))?;
    let changed = Arc::new(AtomicBool::new(false));
    let mut servers = vec![];
    let mut peers = vec![];
    for seed in 2..=4 {
        let (server, endpoint) = server(
            seed,
            mode,
            target,
            source,
            &directory,
            changed.clone(),
            &config_hash,
        )
        .await;
        servers.push(server);
        peers.push(endpoint);
    }
    let temporary = tempfile::tempdir()?;
    let key_path = temporary.path().join("identity.key");
    std::fs::write(&key_path, [1; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let environment = temporary.path().join("network.env");
    use std::fmt::Write as _;
    let mut raw = String::new();
    for (name, value) in &values {
        writeln!(raw, "{name}={}", std::str::from_utf8(value).unwrap()).unwrap();
    }
    if mode == "environment-mismatch" {
        raw = raw.replace(
            "OCTRA_CHAIN_ID=legacy-repair-fixture",
            "OCTRA_CHAIN_ID=another-chain",
        );
    }
    std::fs::write(&environment, raw)?;
    let entries = (1..=4)
        .map(|seed| {
            format!(
                "{}:{}",
                std::str::from_utf8(&address(seed)).unwrap(),
                STANDARD.encode(key(seed).verifying_key().as_bytes())
            )
        })
        .collect::<Vec<_>>();
    let mut origin = target;
    if mode == "origin-mismatch" {
        origin[0] ^= 1;
    }
    let config = temporary.path().join("network.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "network":{"identity":ChainIdentity::genesis("legacy-repair-fixture",StateRoot(origin)),"config_hash":"1".repeat(64),"validators":entries,"exporters":entries,"minimum_epoch":0,"migration_root":null},
            "environment":environment,"data":directory,"key":key_path,"p2p":"127.0.0.1:0","advertised":"127.0.0.1:9","rpc":"127.0.0.1:0","browser":"127.0.0.1:0","control":"127.0.0.1:0","tunnel":"127.0.0.1:0","peers":peers,"startup_seconds":20
        }))?,
    )?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(75),
        stage_if_proven(&StageOptions {
            config,
            backend: PathBuf::from(fixture["backend"].as_str().unwrap()),
            backend_sha256: fixture["backend_sha256"].as_str().unwrap().to_owned(),
        }),
    )
    .await?;
    let expected_error = matches!(
        mode,
        "target-mismatch"
            | "source-changed"
            | "protected-prepare"
            | "protected-commit"
            | "protected-aborted"
            | "missing-finality"
            | "tampered-qc"
            | "origin-mismatch"
            | "environment-mismatch"
    );
    let report = if expected_error {
        assert!(
            result.is_err(),
            "native storage/authority refusal was bypassed: {result:?}"
        );
        json!({"refused":true,"reason":format!("{:#}",result.unwrap_err())})
    } else {
        let report = result?;
        assert_eq!(report["staged"], mode == "positive");
        let reason = match mode {
            "current-root" => Some("current_root_has_quorum"),
            "weak-target" => Some("target_root_unproved"),
            "bad-signature" | "unknown-signer" => Some("low_peer_responses"),
            _ => None,
        };
        if let Some(reason) = reason {
            assert_eq!(report["reason"], reason);
        }
        report
    };
    if !matches!(mode, "origin-mismatch" | "environment-mismatch") {
        for server in &servers {
            assert!(
                !server.task.is_finished(),
                "fixture TCP peer stopped unexpectedly"
            );
            assert!(
                server.current_queries.load(Ordering::SeqCst) > 0,
                "the actual source query did not reach every fixture peer"
            );
            if !matches!(mode, "current-root" | "bad-signature" | "unknown-signer") {
                assert!(
                    server.target_queries.load(Ordering::SeqCst) > 0,
                    "the actual target query did not reach every fixture peer"
                );
            }
        }
    }
    assert_eq!(
        directory.join("fork_repair.json").exists(),
        mode == "positive"
    );
    if mode == "positive" {
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(directory.join("fork_repair.json"))?)?,
            *plan
        );
        assert_eq!(
            std::fs::read(directory.join("HEAD.json"))?,
            source_head,
            "staging must not rewind physical HEAD"
        );
    }
    if mode == "source-changed" {
        assert!(changed.load(Ordering::SeqCst));
    }
    std::fs::write(
        fixture["report"].as_str().context("report path missing")?,
        serde_json::to_vec_pretty(&report)?,
    )?;
    drop(servers);
    Ok(())
}
