//! Isolated development deployment using the real canonical store, native
//! executor, authenticated peer transport and validator driver.
use crate::{
    consensus::Canonical,
    driver,
    executor::{self, Native, Pending},
    peers::Network,
    rpc::Submission,
    Node,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, ChainIdentity, CommittedEpoch,
    ExEx, StateRoot,
};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    consensus::{
        engine::{Engine, TimeoutConfig},
        journal::JournalOwner,
        policy::Protocol,
    },
    epoch_index,
    network::{endpoint::Endpoint, session::Timeouts, swarm},
    rules::Graph,
    state::Account,
    transaction::{self, RuleMode},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    account_store,
    canonical::CanonicalStore,
    circle::{CircleRuntime, HfheBackend},
    consensus_driver::{Driver, Host as _},
    epoch_footer,
    finality::proposal::Policy,
    state_batch::StateBatch,
    validator_history::{Authority, CanonicalValidators, Environment, ReceiptPolicy},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub chain: ChainIdentity,
    pub time: f64,
    pub validators: Vec<String>,
    pub funded_public: String,
    pub circle: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub genesis: Genesis,
    pub data: PathBuf,
    pub key: PathBuf,
    pub faucet: PathBuf,
    pub p2p: SocketAddr,
    pub rpc: SocketAddr,
    pub browser: SocketAddr,
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
    pub peers: Vec<SocketAddr>,
}
fn key() -> SigningKey {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}
fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().as_bytes())
}
fn address(key: &SigningKey) -> Vec<u8> {
    transaction::address_from_public_key(public(key).as_bytes())
}
fn state(genesis: &Genesis) -> Result<StateBatch> {
    let mut state = StateBatch::default();
    state.begin()?;
    // Bind trusted startup parameters to the genesis commitment. Editing a
    // validator list or activation setting must create a different local chain.
    state.set(
        &[b"meta", b"local_devnet"],
        serde_json::to_vec(&serde_json::json!({
            "chain_id":genesis.chain.chain_id,"time":genesis.time,"validators":genesis.validators,
            "profile":"devnet_full_v1","proposal_activation":2,"receipts_activation":0,
            "upstream":"7f9be4489870645cfcc95439638cde40f5da9f50"
        }))?,
    )?;
    for (name, value) in [
        (b"last_epoch".as_slice(), b"0".as_slice()),
        (b"emission_remaining", b"0"),
        (b"total_supply", b"100000000000"),
    ] {
        state.set(&[b"meta", name], value.to_vec())?;
    }
    account_store::set(
        &mut state,
        &transaction::address_from_public_key(genesis.funded_public.as_bytes()),
        &Account {
            balance: 100_000_000_000_u64.into(),
            public_key: Some(genesis.funded_public.as_bytes().to_vec()),
            ..Account::default()
        },
        RuleMode::Active,
    )?;
    let circle = genesis.circle.as_bytes();
    state.set(
        &[b"circles", circle, b"browser", b"mode"],
        b"gateway_allowed".to_vec(),
    )?;
    state.set(
        &[b"circles", circle, b"resources", b"mode"],
        b"public_resources".to_vec(),
    )?;
    let body=b"<!doctype html><html><meta charset=utf-8><title>Octra Rust devnet</title><h1>Octra Rust devnet</h1><p>This Circle asset is served from the committed state of your local Rust node.</p><p>VPN escrow is not configured on this development chain.</p></html>";
    let path = circles::path_key(b"/index.html");
    let meta = AssetMeta {
        path_key: path.as_bytes().to_vec(),
        canonical_path: b"/index.html".to_vec(),
        content_type: b"text/html".to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: body.len() as i64,
        blob_hash: hex::encode(Sha256::digest(body)).into_bytes(),
        body_mode: ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: path.as_bytes().to_vec(),
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: MetadataMode::Reveal,
    };
    state.set(
        &[
            b"circles",
            circle,
            b"assets",
            b"by_hash",
            path.as_bytes(),
            b"meta",
        ],
        meta.to_json_bytes(),
    )?;
    state.set(
        &[
            b"circles",
            circle,
            b"assets",
            b"by_hash",
            path.as_bytes(),
            b"body_b64",
        ],
        STANDARD.encode(body).into_bytes(),
    )?;
    Ok(state)
}
fn root(state: &StateBatch) -> Result<StateRoot> {
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])?;
    Ok(StateRoot(epoch_index::folded_state_root(
        hex::encode(state.root()?).as_bytes(),
        hex::encode(index).as_bytes(),
    )?))
}
/// New directory only: never replace validator keys or erase an existing chain.
pub async fn init(directory: &Path, base: u16) -> Result<Vec<PathBuf>> {
    ensure!((1024..=65500).contains(&base), "invalid base port");
    std::fs::create_dir(directory).context("devnet directory must be new")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let directory = std::fs::canonicalize(directory)?;
    let keys = (0..4).map(|_| key()).collect::<Vec<_>>();
    let faucet = key();
    let circle = String::from_utf8(address(&key()))?;
    let mut genesis = Genesis {
        chain: ChainIdentity {
            chain_id: format!(
                "octra-rust-local-{}",
                hex::encode(&Sha256::digest(faucet.verifying_key().as_bytes())[..8])
            ),
            genesis_root: StateRoot([0; 32]),
        },
        time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
        validators: keys
            .iter()
            .map(|k| format!("{}:{}", String::from_utf8_lossy(&address(k)), public(k)))
            .collect(),
        funded_public: public(&faucet),
        circle,
    };
    genesis.chain.genesis_root = root(&state(&genesis)?)?;
    let faucet_path = directory.join("faucet.key");
    crate::storage::publish(&faucet_path, &faucet.to_bytes())?;
    let peers = (0..4)
        .map(|i| SocketAddr::from(([127, 0, 0, 1], base + i * 10)))
        .collect::<Vec<_>>();
    let mut configs = vec![];
    for (i, key) in keys.into_iter().enumerate() {
        let data = directory.join(format!("node-{i}"));
        std::fs::create_dir(&data)?;
        let key_path = data.join("validator.key");
        crate::storage::publish(&key_path, &key.to_bytes())?;
        let port = peers[i].port();
        let socket = |offset| SocketAddr::from(([127, 0, 0, 1], port + offset));
        let config = Config {
            genesis: genesis.clone(),
            data: data.clone(),
            key: key_path,
            faucet: faucet_path.clone(),
            p2p: socket(0),
            rpc: socket(1),
            browser: socket(2),
            control: socket(3),
            tunnel: socket(4),
            peers: peers.iter().copied().filter(|p| p != &peers[i]).collect(),
        };
        let file = data.join("config.json");
        crate::storage::publish(&file, &serde_json::to_vec_pretty(&config)?)?;
        configs.push(file);
    }
    crate::storage::publish(
        &directory.join("genesis.json"),
        &serde_json::to_vec_pretty(&genesis)?,
    )?;
    Ok(configs)
}
pub fn read(path: &Path) -> Result<Config> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
pub fn read_key(path: &Path) -> Result<SigningKey> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let mut file: std::fs::File = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?
        .into();
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() == 32 && meta.permissions().mode().trailing_zeros() >= 6,
            "validator key must be a private 32-byte regular file"
        );
        let mut bytes = [0; 32];
        file.read_exact(&mut bytes)?;
        Ok(SigningKey::from_bytes(&bytes))
    }
    #[cfg(not(unix))]
    anyhow::bail!("devnet keys require Unix file permissions")
}
struct HfheUnavailable;
impl HfheBackend for HfheUnavailable {
    fn call(
        &self,
        _: &serde_json::Value,
    ) -> Result<serde_json::Value, octra_node_runtime::circle::Error> {
        Err(octra_node_runtime::circle::Error::Unavailable(
            "Circle HFHE backend is not configured".into(),
        ))
    }
}
struct Unfunded;
impl crate::vpn::Settlement for Unfunded {
    fn session(
        &self,
        _: &crate::Committed,
        _: &octravpn_core::control::AnnounceSessionRequest,
        _: &octravpn_core::receipt::ReceiptContext,
    ) -> Result<Option<octravpn_node::admission::FundedSession>> {
        Ok(None)
    }
    fn lifecycle(
        &self,
        _: &crate::Committed,
        _: &octravpn_core::session::SessionId,
        _: &octravpn_core::receipt::ReceiptContext,
    ) -> Result<octravpn_node::admission::RelayLifecycle> {
        anyhow::bail!("VPN settlement Circle is not configured")
    }
}
struct Archive(PathBuf);
impl ExEx<NativeTransaction> for Archive {
    fn name(&self) -> &'static str {
        "devnet-archive"
    }
    async fn on_epoch(&mut self, event: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        let path = self
            .0
            .join(format!("{:016x}.json", event.cursor.sequence.0));
        let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        tokio::task::spawn_blocking(move || crate::storage::publish(&path, &bytes))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
}
struct Stop {
    signal: watch::Sender<bool>,
    swarm: swarm::Swarm,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.signal.send_replace(true);
        self.swarm.stop();
    }
}

pub async fn run(config: Config, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    ensure!(
        config
            .genesis
            .chain
            .chain_id
            .starts_with("octra-rust-local-"),
        "this launcher only supports isolated local devnets"
    );
    for socket in [
        config.p2p,
        config.rpc,
        config.browser,
        config.control,
        config.tunnel,
    ]
    .into_iter()
    .chain(config.peers.iter().copied())
    {
        ensure!(
            socket.ip().is_loopback(),
            "local devnet sockets must bind loopback"
        );
    }
    let initial = state(&config.genesis)?;
    ensure!(
        root(&initial)? == config.genesis.chain.genesis_root,
        "genesis commitment differs"
    );
    let key = read_key(&config.key)?;
    let address = address(&key);
    let journal = JournalOwner::open(&config.data)?;
    let database = config.data.join("canonical.db");
    let store = if database.exists() {
        CanonicalStore::open(&database, &config.genesis.chain).await?
    } else {
        CanonicalStore::create(
            &database,
            config.genesis.chain.clone(),
            initial.snapshot(),
            0,
        )
        .await?
    };
    let reader = store.reader();
    let environment = Environment {
        current: Some(config.genesis.validators.join(",").into_bytes()),
        ..Environment::default()
    };
    let profile = Profile::from_values(Some(b"devnet_full_v1"), None, None);
    let receipts = ReceiptPolicy::new(Some(b"0"), &profile, None);
    let runtime = CircleRuntime::new(Arc::new(HfheUnavailable));
    let checkpoints = Arc::new(SqliteCheckpoints::open(&config.data.join("exex.db")).await?);
    let membership = CanonicalValidators::new(reader.clone(), environment.clone());
    let node = Arc::new(
        Node::open(
            store,
            Authority::new(reader.clone(), environment, receipts, journal.clone()),
            runtime.clone(),
            Arc::new(UnavailableHost),
            checkpoints,
        )
        .await?,
    );
    node.register(Archive(config.data.join("exex"))).await?;
    let head = node.head().await?;
    // Establish the native genesis floor before a first-start catch-up. A
    // retained non-genesis store without a floor still requires explicit repair.
    if head.cursor.epoch.0 == 0 && journal.floor()?.is_none() {
        journal.set_floor(0)?;
    }
    let validators = membership
        .expected_set(&head, head.cursor.epoch.0 as i64 + 1, None, &|_| {
            journal
                .latest_relief(head.cursor.epoch.0 as i64 + 1)
                .map_err(|e| e.as_bytes().to_vec())
        })
        .await?;
    ensure!(
        validators.public_key(&address) == Some(key.verifying_key().as_bytes()),
        "local key is not in the genesis validator set"
    );
    let native_config = membership.config(&head).await?;
    let protocol = Protocol::new(2)?;
    let policy = Policy {
        protocol,
        genesis_time: Some(config.genesis.time),
    };
    let executor = Native::new(
        executor::Config {
            graph: Graph::new(config.genesis.chain.chain_id.as_bytes().to_vec(), None),
            protocol,
            profile,
            payload: octra_node_protocol::transaction_payload::Limits::default(),
            bundle: executor::Limits::new(100_000, 50_000_000, 10_000_000_000_u64.into()),
            validators: octra_node_protocol::validator::policy::Policy::Inactive,
            emission: epoch_footer::Policy {
                emission_guard: true,
                schedule: octra_node_protocol::emission::Schedule::Inactive,
                legacy_total: None,
            },
            sender_key_activation: Some(0),
            private_result_activation: 0,
            max_fhe: 32,
            ready_max_lag: 10,
            pvac_dir: config.data.join("pvac"),
        },
        runtime,
        node.history(),
    )?;
    let view = node.clone();
    let fallback = head.clone();
    let endpoint = |socket: SocketAddr| Endpoint {
        host: socket.ip().to_string().into_bytes(),
        port: socket.port(),
    };
    let mut network = Network::new(
        TcpListener::bind(config.p2p).await?,
        swarm::Config {
            chain_id: config.genesis.chain.chain_id.as_bytes().to_vec(),
            node_address: address.clone(),
            config_hash: native_config.hash.to_vec(),
            binary_hash: Sha256::digest(b"octra-rust-local-devnet-v1").to_vec(),
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: native_config.allowed_pubkeys,
            bootstrap: config.peers.iter().copied().map(endpoint).collect(),
            maximum_validators: 16,
            advertised: endpoint(config.p2p),
            timeouts: Timeouts::default(),
            head: Arc::new(move || {
                let head = view
                    .snapshot()
                    .map_or_else(|_| fallback.clone(), |v| v.head().clone());
                (head.cursor.epoch.0 as i64, head.cursor.state_root.0)
            }),
        },
        key.clone(),
        node.history(),
        reader,
        membership,
        validators.clone(),
        journal.clone(),
    )?;
    let pending = Arc::new(Pending::new(octra_node_runtime::staging::Pool::default()));
    let submission = Arc::new(Submission {
        node: node.clone(),
        executor: executor.clone(),
        pending: pending.clone(),
        swarm: network.swarm.clone(),
        policy,
        address: address.clone(),
    });
    let (stop, stopped) = watch::channel(false);
    let _stop = Stop {
        signal: stop.clone(),
        swarm: network.swarm.clone(),
    };
    let authority = network.authority.clone();
    let swarm = network.swarm.clone();
    let finality = network.finality.clone();
    let bundles = network.bundles.clone();
    let validator = driver::Validator::new(
        node.clone(),
        executor.clone(),
        pending.clone(),
        &network,
        driver::Config {
            key: key.clone(),
            address: address.clone(),
            policy,
            journal: journal.clone(),
            epoch_capacity: 10_000_000_000_u64.into(),
            stealth_slots: 4,
            evidence_dir: config.data.join("evidence"),
        },
    )?;
    let inbox = network.inbox.take().context("transaction inbox missing")?;
    let mut tasks = JoinSet::new();
    tasks.spawn(async move { network.run(stopped).await.map_err(anyhow::Error::from) });
    let startup = async {
        // Peer announcements select a target only. Historical QCs and local
        // execution authenticate every imported epoch before voting starts.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while swarm.peers().len() < 2 {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "waiting for devnet quorum timed out"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let target = swarm
            .peers()
            .iter()
            .map(|p| p.hello().best_epoch)
            .max()
            .unwrap_or(0)
            .max(0) as u64;
        if target > node.head().await?.cursor.epoch.0 {
            ensure!(
                node.catch_up_range(target, &finality, &executor, 10.)
                    .await?
                    .reached,
                "startup catch-up incomplete"
            );
        }
        ensure!(node.resume().await?, "startup serving lease revoked");
        let height = node.head().await?.cursor.epoch.0 as i64 + 1;
        let set = validator.activate(height).await?;
        let mut engine = Engine::new(
            config.genesis.chain.chain_id.as_bytes().to_vec(),
            address,
            set,
            height,
            protocol,
            TimeoutConfig::default(),
        );
        validator.recover(&mut engine).await?;
        validator.set_enabled(true);
        let publication = Canonical::new(node.clone(), bundles, executor, 10.)
            .await?
            .with_pending(pending);
        let (handle, driver) = Driver::new(
            engine,
            journal,
            swarm.clone(),
            validator,
            publication,
            Ok(vec![]),
        )?;
        authority.attach(handle)?;
        let signal = stop.subscribe();
        tasks.spawn(async move { driver.run(signal).await.map_err(anyhow::Error::from) });
        let signal = stop.subscribe();
        tasks.spawn(submission.clone().ingress(inbox, signal));
        let listener = TcpListener::bind(config.rpc).await?;
        let mut signal = stop.subscribe();
        tasks.spawn(async move {
            axum::serve(listener, submission.router())
                .with_graceful_shutdown(async move {
                    let _ = signal.wait_for(|v| *v).await;
                })
                .await
                .map_err(anyhow::Error::from)
        });
        let vpn_key = Sha256::digest([b"devnet-vpn-receipts".as_slice(), &key.to_bytes()].concat());
        let wg_key = Sha256::digest([b"devnet-vpn-wireguard".as_slice(), &key.to_bytes()].concat());
        let operator = octravpn_core::address::Address::from_pubkey(key.verifying_key().as_bytes());
        let services = node
            .bind(
                config.browser,
                octravpn_node::embedded::Config {
                    control_listen: config.control,
                    tunnel_listen: config.tunnel,
                    data_dir: config.data.join("vpn"),
                    receipt_key: Arc::new(octravpn_core::sig::KeyPair::from_secret_bytes(
                        &vpn_key.into(),
                    )),
                    wireguard_secret: x25519_dalek::StaticSecret::from(<[u8; 32]>::from(wg_key)),
                    receipt_context: octravpn_core::receipt::ReceiptContext::v2(
                        operator.clone(),
                        9871,
                        operator,
                    ),
                },
                Arc::new(Unfunded),
            )
            .await?;
        tasks.spawn(services.run(stop.subscribe()));
        eprintln!(
            "devnet serving: RPC http://{} browser http://{}/open?u=oct://{}/index.html",
            config.rpc, config.browser, config.genesis.circle
        );
        Ok::<_, anyhow::Error>(())
    };
    let started = tokio::select! {r=startup=>r,_=shutdown.wait_for(|v|*v)=>Ok(())};
    let result = if started.is_err() {
        started
    } else {
        tokio::select! {
            result=tasks.join_next()=>match result {Some(Ok(Err(e)))=>Err(e),Some(Err(e))=>Err(e.into()),_=>Err(anyhow::anyhow!("node service stopped unexpectedly"))},
            _=shutdown.wait_for(|v|*v)=>Ok(()),
        }
    };
    stop.send_replace(true);
    swarm.stop();
    node.suspend("devnet shutting down");
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(8), drain)
        .await
        .is_err()
    {
        tasks.abort_all();
    }
    node.shutdown().await?;
    result
}
