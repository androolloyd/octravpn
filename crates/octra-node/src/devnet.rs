//! Isolated development deployment using the real canonical store, native
//! executor, authenticated peer transport and validator driver.
use crate::executor;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    consensus::{engine::TimeoutConfig, journal::JournalOwner, policy::Protocol},
    epoch_index,
    network::endpoint::Endpoint,
    rules::Graph,
    state::Account,
    transaction::{self, RuleMode},
    transaction_policy::Profile,
};
use octra_node_runtime::{
    account_store,
    canonical::CanonicalStore,
    circle::CircleRuntime,
    epoch_footer,
    state_batch::StateBatch,
    validator_history::{Environment, ReceiptPolicy},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub chain: ChainIdentity,
    pub time: f64,
    pub validators: Vec<String>,
    pub funded_public: String,
    pub circle: String,
    /// Local qualification only; included in the genesis commitment.
    #[serde(default)]
    pub activated_applications: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_portal: Option<crate::gateway::StockPortalConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_circle_gateway: Option<crate::gateway::StockCircleConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<octravpn_node::mesh_control::Config>,
    #[serde(default)]
    pub compute_provider: bool,
    /// Local transport identities may observe without joining the validator set.
    #[serde(default = "default_voting")]
    pub voting: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<crate::vpn::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payments: Option<crate::vpn::payments::ServiceConfig>,
    pub peers: Vec<SocketAddr>,
}
fn default_voting() -> bool {
    true
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
    let mut commitment = serde_json::json!({
        "chain_id":genesis.chain.chain_id,"time":genesis.time,"validators":genesis.validators,
        "profile":"devnet_full_v1","proposal_activation":2,"receipts_activation":0,
        "upstream":"7f9be4489870645cfcc95439638cde40f5da9f50"
    });
    if genesis.activated_applications {
        commitment["activated_applications"] = serde_json::json!(true);
    }
    state.set(
        &[b"meta", b"local_devnet"],
        serde_json::to_vec(&commitment)?,
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
    init_with_applications(directory, base, false).await
}
pub async fn init_with_applications(
    directory: &Path,
    base: u16,
    activated_applications: bool,
) -> Result<Vec<PathBuf>> {
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
        chain: ChainIdentity::genesis(
            format!(
                "octra-rust-local-{}",
                hex::encode(&Sha256::digest(faucet.verifying_key().as_bytes())[..8])
            ),
            StateRoot([0; 32]),
        ),
        time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
        validators: keys
            .iter()
            .map(|k| format!("{}:{}", String::from_utf8_lossy(&address(k)), public(k)))
            .collect(),
        funded_public: public(&faucet),
        circle,
        activated_applications,
    };
    genesis.chain.origin = octra_exex::ChainOrigin::Genesis {
        state_root: root(&state(&genesis)?)?,
    };
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
            gateway: None,
            stock_portal: None,
            stock_circle_gateway: None,
            mesh: None,
            compute_provider: false,
            voting: true,
            vpn: None,
            payments: None,
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
    let mut config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let source = std::fs::canonicalize(path)?;
    let parent = source.parent().context("configuration directory")?;
    if let Some(portal) = &mut config.stock_portal {
        portal.resolve_paths(parent);
    }
    if let Some(circle) = &mut config.stock_circle_gateway {
        circle.resolve_paths(parent);
    }
    if let Some(book) = config
        .payments
        .as_mut()
        .and_then(|p| p.ip_tunnel.address_book.as_mut())
    {
        if book.is_relative() {
            *book = parent.join(&*book);
        }
    }
    if let Some(mesh) = &mut config.mesh {
        mesh.resolve_paths(parent);
    }
    Ok(config)
}
pub use crate::identity::read as read_key;

pub async fn run(
    config: Config,
    runtime: CircleRuntime,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    crate::launch::require_crypto(&runtime)?;
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
        root(&initial)?
            == config
                .genesis
                .chain
                .genesis_root()
                .context("local devnet requires genesis origin")?,
        "genesis commitment differs"
    );
    let key = read_key(&config.key)?;
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
    let profile = Profile::from_values(Some(b"devnet_full_v1"), None, None);
    let protocol = Protocol::new(2)?;
    let environment = Environment {
        current: Some(config.genesis.validators.join(",").into_bytes()),
        ..Environment::default()
    };
    let endpoint = |socket: SocketAddr| Endpoint {
        host: socket.ip().to_string().into_bytes(),
        port: socket.port(),
    };
    Box::pin(crate::launch::run(
        crate::launch::Plan {
            status_release: None,
            state_sync: None,
            services: crate::launch::Services {
                data: config.data.clone(),
                rpc: config.rpc,
                browser: config.browser,
                control: config.control,
                tunnel: config.tunnel,
                gateway: config.gateway,
                stock_portal: config.stock_portal,
                stock_circle_gateway: config.stock_circle_gateway,
                mesh: config.mesh,
            },
            transport: crate::launch::Transport {
                listen: config.p2p,
                proxy: None,
                advertised: endpoint(config.p2p),
                peers: config.peers.into_iter().map(endpoint).collect(),
                maximum_peers: 16,
                config_hash: None,
                binary_hash: Sha256::digest(b"octra-rust-local-devnet-v1").to_vec(),
                require_binary_hash: false,
                upgrade: None,
                profiles: vec![],
            },
            store,
            key,
            journal,
            environment,
            receipts: ReceiptPolicy::new(Some(b"0"), &profile, None),
            policy: octra_node_runtime::finality::proposal::Policy {
                protocol,
                genesis_time: Some(config.genesis.time),
            },
            execution: executor::Config {
                graph: if config.genesis.activated_applications {
                    Graph::isolated_applications(
                        config.genesis.chain.chain_id.as_bytes().to_vec(),
                        None,
                        config
                            .genesis
                            .chain
                            .genesis_root()
                            .context("local devnet requires genesis origin")?
                            .0,
                    )
                    .map_err(anyhow::Error::msg)?
                } else {
                    Graph::new(config.genesis.chain.chain_id.as_bytes().to_vec(), None)
                },
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
                max_stealth: 32,
                max_multi_exec_calls: 8,
                ready_max_lag: 10,
                pvac_dir: config.data.join("pvac"),
                migration: None,
            },
            runtime,
            compute: octra_node_protocol::resource_compute::provider::Config::from_inputs(
                config.compute_provider,
                |name| std::env::var_os(name).map(|value| value.as_encoded_bytes().to_vec()),
            )?,
            vpn: config.vpn,
            payments: config.payments,
            voting: config.voting,
            minimum_peers: 2,
            health: octra_node_protocol::consensus::health::Config::default(),
            startup_timeout: Duration::from_secs(60),
            timeouts: TimeoutConfig::default(),
            epoch_capacity: 10_000_000_000_u64.into(),
            stealth_slots: 4,
        },
        shutdown,
    ))
    .await
}
