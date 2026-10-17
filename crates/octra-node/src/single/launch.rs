//! Explicit private-prior Single fixture launcher. The pristine native CLI's
//! public-chain restriction is not bypassed or relabeled as a public deployment.
use super::{History, Node, Settings};
use crate::executor::{self, Native};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, ChainIdentity, CommittedEpoch,
    ExEx,
};
use octra_node_protocol::{
    consensus::policy::Protocol, emission::Schedule, rules::Graph, transaction,
    transaction_policy::Profile,
};
use octra_node_runtime::{
    canonical::single::{Authority, Store},
    circle::CircleRuntime,
    epoch_footer, ledger_image,
    state_batch::StateBatch,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    #[serde(default, skip_serializing_if = "is_false")]
    pub activated_applications: bool,
    pub release: Option<String>,
    pub crypto_profile: Option<String>,
    pub admit_ops: Option<String>,
    pub emission_guard: bool,
    pub emission_activation: Option<i64>,
    pub legacy_total: Option<Vec<u8>>,
    pub sender_key_activation: Option<i64>,
    pub private_result_activation: i64,
    pub maximum_fhe: usize,
    pub maximum_stealth: usize,
    pub maximum_multi_exec: usize,
    pub ready_max_lag: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub ledger_root: String,
    pub maximum_records: u64,
    pub maximum_string_bytes: u64,
    pub date: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<super::service::Services>,
    pub chain: ChainIdentity,
    pub data: PathBuf,
    pub key: PathBuf,
    pub seed: Seed,
    pub settings: Settings,
    pub execution: Execution,
    pub rpc: SocketAddr,
    pub maximum_http_body: usize,
}
// Serde's skip callback receives a reference even for a one-byte scalar.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}
pub fn read(path: &Path) -> Result<Config> {
    let mut config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    if let Some(mesh) = config
        .services
        .as_mut()
        .and_then(|services| services.mesh.as_mut())
    {
        mesh.resolve_paths(
            std::fs::canonicalize(path)?
                .parent()
                .context("configuration directory")?,
        );
    }
    Ok(config)
}
fn now() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
fn seed(config: &Config) -> Result<StateBatch> {
    let meta = std::fs::metadata(&config.seed.path)?;
    ensure!(
        meta.is_file() && meta.len() == config.seed.bytes,
        "Single seed image size differs"
    );
    let file = std::fs::File::open(&config.seed.path)?;
    let restored = ledger_image::restore(
        file,
        config.seed.bytes,
        &config.seed.ledger_root,
        ledger_image::Limits {
            bytes: config.seed.bytes,
            records: config.seed.maximum_records,
            string_bytes: config.seed.maximum_string_bytes,
        },
    )?;
    // Read-only hash validation is bounded by the explicit image byte budget.
    use std::io::Read;
    let mut file = std::fs::File::open(&config.seed.path)?;
    let mut hash = Sha256::new();
    let mut chunk = vec![0; 65_536].into_boxed_slice();
    loop {
        let len = file.read(&mut chunk)?;
        if len == 0 {
            break;
        }
        hash.update(&chunk[..len]);
    }
    ensure!(
        hex::encode(hash.finalize()) == config.seed.sha256,
        "Single seed image hash differs"
    );
    Ok(StateBatch::from_snapshot(restored.state))
}
pub async fn open(config: &Config) -> Result<Arc<Node>> {
    validate(config)?;
    let key = crate::identity::read(&config.key)?;
    let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
    ensure!(
        config.settings.wallet_public == public
            && config.settings.wallet_address == transaction::address_from_public_key(&public),
        "Single wallet and journal authority differ"
    );
    std::fs::create_dir_all(&config.data)?;
    let database = config.data.join("canonical.db");
    // An unopened store supplies only anchor reads while Native is constructed.
    // Resolve policy with an explicit graph; this graph has no public activation.
    let execution = &config.execution;
    let graph = if execution.activated_applications {
        Graph::isolated_single_applications(
            config.chain.chain_id.as_bytes().to_vec(),
            None,
            config
                .chain
                .genesis_root()
                .context("Single requires genesis origin")?
                .0,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        Graph::new(config.chain.chain_id.as_bytes().to_vec(), None)
    };
    let config_native = || executor::Config {
        graph: graph.clone(),
        protocol: Protocol::default(),
        profile: Profile::from_values(
            execution.release.as_deref().map(str::as_bytes),
            execution.crypto_profile.as_deref().map(str::as_bytes),
            execution.admit_ops.as_deref().map(str::as_bytes),
        ),
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        bundle: executor::Limits::new(100_000, 50_000_000, 10_000_000_000_u64.into()),
        validators: octra_node_protocol::validator::policy::Policy::Inactive,
        emission: epoch_footer::Policy {
            emission_guard: execution.emission_guard,
            schedule: execution
                .emission_activation
                .map_or(Schedule::Inactive, |activation_epoch| {
                    Schedule::SecurityCurve { activation_epoch }
                }),
            legacy_total: execution.legacy_total.clone(),
        },
        sender_key_activation: execution.sender_key_activation,
        private_result_activation: execution.private_result_activation,
        max_fhe: execution.maximum_fhe,
        max_stealth: execution.maximum_stealth,
        max_multi_exec_calls: execution.maximum_multi_exec,
        ready_max_lag: execution.ready_max_lag,
        pvac_dir: config.data.join("pvac"),
        migration: None,
    };
    let runtime = CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend));
    let policy = Native::single_policy_for(&config_native(), &config.settings)?;
    let authority = Authority::new(config.chain.clone(), key, policy)?;
    let store = if database.exists() {
        Store::open(&database, authority).await?
    } else {
        let initial = seed(config)?;
        if let Some(profile) = graph.application_fixture() {
            let raw = initial
                .get(&[b"meta", profile.metadata_key()])
                .context("Single application genesis opt-in missing")?;
            graph
                .check_application_opt_in(raw)
                .map_err(anyhow::Error::msg)?;
        }
        Store::create(
            &database,
            authority,
            initial.snapshot(),
            config.seed.date,
            super::queue::State::empty()?,
        )
        .await?
    };
    let store = Arc::new(store);
    if graph.application_fixture().is_some() {
        // Reauthenticate the original retained genesis after open/create; a
        // current marker or caller-provided flag cannot activate old history.
        octra_node_runtime::circle_view::canonical_with_graph(
            &store.assets().await?,
            &graph,
            &History(store.clone()),
        )
        .await?;
    }
    let native = Native::new(config_native(), runtime, Arc::new(History(store.clone())))?;
    let checkpoints = Arc::new(SqliteCheckpoints::open(&config.data.join("extensions.db")).await?);
    let node = Node::open(store, native, config.settings.clone(), checkpoints, now()?).await?;
    node.register(Archive(config.data.join("single-archive")))
        .await?;
    Ok(node)
}

/// Validate the private role boundary before the standard network launcher
/// opens a key, store, or listener.
pub fn validate(config: &Config) -> Result<()> {
    config.settings.validate()?;
    ensure!(
        config.chain.chain_id.starts_with("octra-single-local-")
            && config.chain.genesis_root().is_some(),
        "Single requires an explicit private genesis origin"
    );
    ensure!(
        config.rpc.ip().is_loopback(),
        "private Single fixture RPC must bind loopback"
    );
    ensure!(
        (1024..=128 * 1024 * 1024).contains(&config.maximum_http_body),
        "Single HTTP body budget invalid"
    );
    Ok(())
}
struct Archive(PathBuf);
impl ExEx<NativeTransaction> for Archive {
    fn name(&self) -> &'static str {
        "private-single-archive"
    }
    async fn on_epoch(
        &mut self,
        epoch: &CommittedEpoch<NativeTransaction>,
    ) -> std::result::Result<(), String> {
        let path = self.0.join(format!("{}.json", epoch.cursor.sequence.0));
        crate::storage::publish(
            &path,
            &serde_json::to_vec(epoch).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}
pub async fn run(config: Config, shutdown: watch::Receiver<bool>) -> Result<()> {
    let node = open(&config).await?;
    let services = config.services.clone().unwrap_or_default();
    let result = super::service::run(&config, node.clone(), services, shutdown).await;
    node.shutdown().await?;
    result
}
