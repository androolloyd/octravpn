//! Public-network startup from independently configured trust and an
//! authenticated snapshot. Local genesis construction is a separate launcher.
use crate::{bootstrap, executor, launch, network_profile::Profile};
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{
    consensus::{engine::TimeoutConfig, journal::JournalOwner, profile::Settings},
    native_integer,
    network::{
        endpoint::{self, Endpoint},
        upgrade,
    },
    rules::Graph,
};
use octra_node_runtime::{
    circle::CircleRuntime,
    epoch_footer,
    finality::proposal::Policy,
    validator_history::{Environment, ReceiptPolicy},
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Operator-selected chain identity and trust roots, never downloaded trust.
    pub network: bootstrap::Network,
    pub environment: PathBuf,
    pub data: PathBuf,
    pub key: PathBuf,
    pub p2p: SocketAddr,
    /// Optional local SOCKS5 relay; all P2P dials fail closed through it.
    #[serde(default)]
    pub p2p_proxy: Option<SocketAddr>,
    pub advertised: String,
    pub rpc: SocketAddr,
    pub browser: SocketAddr,
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
    #[serde(default)]
    pub gateway: Option<crate::gateway::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_portal: Option<crate::gateway::StockPortalConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_circle_gateway: Option<crate::gateway::StockCircleConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<octravpn_node::mesh_control::Config>,
    #[serde(default)]
    pub compute_provider: bool,
    #[serde(default)]
    pub vpn: Option<crate::vpn::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payments: Option<crate::vpn::payments::ServiceConfig>,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub voting: bool,
    /// Explicit native publisher/observer role. Selection still requires a configured exporter key.
    #[serde(default)]
    pub publisher: bool,
    #[serde(default)]
    pub snapshot_limits: crate::snapshot_export::LimitsConfig,
    #[serde(default = "default_startup_seconds")]
    pub startup_seconds: u64,
}

/// A standard network launch is either the existing public BFT configuration
/// or an explicitly tagged, isolated private Single configuration.
pub enum RoleConfig {
    Public(Box<Config>),
    Single(Box<crate::single::launch::Config>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleRole {
    role: String,
    single: crate::single::launch::Config,
}

fn default_startup_seconds() -> u64 {
    180
}
pub fn read(path: &Path) -> Result<Config> {
    let mut config: Config = serde_json::from_slice(&bootstrap::read_limited(path, 1024 * 1024)?)?;
    let parent = std::fs::canonicalize(path)?
        .parent()
        .context("configuration has no directory")?
        .to_owned();
    for file in [&mut config.environment, &mut config.data, &mut config.key] {
        if file.is_relative() {
            *file = parent.join(&*file);
        }
    }
    if let Some(path) = config
        .vpn
        .as_mut()
        .and_then(|vpn| vpn.ip_tunnel.as_mut())
        .and_then(|tunnel| tunnel.address_book.as_mut())
    {
        if path.is_relative() {
            *path = parent.join(&*path);
        }
    }
    if let Some(path) = config
        .payments
        .as_mut()
        .and_then(|p| p.ip_tunnel.address_book.as_mut())
    {
        if path.is_relative() {
            *path = parent.join(&*path);
        }
    }
    if let Some(circle) = &mut config.stock_circle_gateway {
        circle.resolve_paths(&parent);
    }
    if let Some(portal) = &mut config.stock_portal {
        portal.resolve_paths(&parent);
    }
    if let Some(mesh) = &mut config.mesh {
        mesh.resolve_paths(&parent);
    }
    Ok(config)
}

/// Preserve the public `network.json` shape. Private Single requires a
/// separate `{"role":"single","single":{...}}` document; BFT trust fields
/// cannot be mixed into that shape or interpreted as private genesis.
pub fn read_role(path: &Path) -> Result<RoleConfig> {
    let raw = bootstrap::read_limited(path, 1024 * 1024)?;
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    match value.get("role") {
        None => Ok(RoleConfig::Public(Box::new(read(path)?))),
        Some(serde_json::Value::String(role)) if role == "single" => {
            let mut role: SingleRole = serde_json::from_value(value)?;
            ensure!(role.role == "single", "invalid network role");
            crate::single::launch::validate(&role.single)?;
            let parent = std::fs::canonicalize(path)?
                .parent()
                .context("configuration has no directory")?
                .to_owned();
            for file in [
                &mut role.single.data,
                &mut role.single.key,
                &mut role.single.seed.path,
            ] {
                if file.is_relative() {
                    *file = parent.join(&*file);
                }
            }
            if let Some(file) = role
                .single
                .services
                .as_mut()
                .and_then(|services| services.vpn.as_mut())
                .and_then(|vpn| vpn.settlement.ip_tunnel.as_mut())
                .and_then(|tunnel| tunnel.address_book.as_mut())
            {
                if file.is_relative() {
                    *file = parent.join(&*file);
                }
            }
            if let Some(mesh) = role
                .single
                .services
                .as_mut()
                .and_then(|services| services.mesh.as_mut())
            {
                mesh.resolve_paths(&parent);
            }
            Ok(RoleConfig::Single(Box::new(role.single)))
        }
        _ => anyhow::bail!("invalid network role"),
    }
}
fn entries(raw: Option<&[u8]>) -> Vec<Vec<u8>> {
    raw.unwrap_or_default()
        .split(|b| *b == b',')
        .map(endpoint::native_trim)
        .filter(|s| !s.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}
fn equal_entries(raw: Option<&[u8]>, expected: &[String]) -> bool {
    let mut actual = entries(raw);
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect::<Vec<_>>();
    expected.sort();
    actual == expected
}
fn bootstrap_peers(configured: &[String], settings: &Settings) -> Vec<Endpoint> {
    endpoint::bootstrap(
        &configured
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        settings.get("OCTRA_BOOTSTRAP_PEERS").unwrap_or_default(),
        settings
            .get("OCTRA_BOOTSTRAP_PEERS_EXTRA")
            .unwrap_or_default(),
    )
}
pub async fn run(
    config: Config,
    runtime: CircleRuntime,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    launch::require_crypto(&runtime)?;
    if let Some(proxy) = config.p2p_proxy {
        octra_node_protocol::network::proxy::validate(proxy)?;
    }
    ensure!(
        (1..=3600).contains(&config.startup_seconds),
        "invalid startup timeout"
    );
    // Wallet-facing services retain their existing loopback boundary. The HTTPS
    // tailnet gateway has its own explicit bind/Host policy.
    for socket in [config.rpc, config.browser, config.control] {
        ensure!(
            socket.ip().is_loopback(),
            "operator services must bind loopback"
        );
    }
    let advertised =
        Endpoint::parse(config.advertised.as_bytes()).context("invalid advertised endpoint")?;
    let profile = Profile::new(crate::network_profile::parse_env(
        &bootstrap::read_limited(&config.environment, 1024 * 1024)?,
    )?)?;
    let settings = &profile.settings;
    let chain = config.network.identity.chain_id.as_bytes();
    ensure!(
        settings.get("OCTRA_CHAIN_ID") == Some(chain),
        "network environment chain differs from configured trust"
    );
    ensure!(
        settings.get("OCTRA_CONSENSUS_CONFIG_HASH") == Some(config.network.config_hash.as_bytes()),
        "network environment configuration hash differs from configured trust"
    );
    ensure!(
        equal_entries(settings.get("OCTRA_VALIDATORS"), &config.network.validators),
        "network validators differ from configured trust"
    );
    ensure!(
        equal_entries(
            settings.get("OCTRA_STATE_SYNC_EXPORTERS"),
            &config.network.exporters
        ),
        "network exporters differ from configured trust"
    );
    ensure!(
        settings.get("OCTRA_PVAC_MIGRATION_ROOT")
            == config.network.migration_root.as_ref().map(String::as_bytes),
        "network migration root differs from configured trust"
    );
    if let Some(floor) = settings.get("OCTRA_CHECKPOINT_EPOCH") {
        ensure!(
            native_integer::parse_int63(floor).is_some_and(|n| config.network.minimum_epoch >= n),
            "configured snapshot floor precedes network checkpoint"
        );
    }
    let voting = network_voting(
        config.voting,
        config.publisher,
        settings.get("OCTRA_CONSENSUS_MODE"),
    )?;
    let authority = bootstrap::Authority::new(config.network.clone())?;
    let (store, migration) = tokio::select! {
        opened = authority.reopen_with_migration(&config.data) => opened?,
        _ = shutdown.wait_for(|stopping| *stopping) => return Ok(()),
    };
    let migration = migration.map(Arc::new);
    let head = store.head().await?;
    let next = i64::try_from(head.cursor.epoch.0)?
        .checked_add(1)
        .context("epoch overflow")?;
    let key = crate::identity::read(&config.key)?;
    let journal = JournalOwner::open(&config.data)?;
    let environment = Environment {
        current: settings.get("OCTRA_VALIDATORS").map(<[u8]>::to_vec),
        next: settings.get("OCTRA_VALIDATORS_NEXT").map(<[u8]>::to_vec),
        activate: settings
            .get("OCTRA_VALIDATORS_ACTIVATE_EPOCH")
            .map(<[u8]>::to_vec),
        fallback_activate: settings
            .get("OCTRA_VALIDATORS_NEXT_EPOCH")
            .map(<[u8]>::to_vec),
    };
    let peers = bootstrap_peers(&config.peers, settings);
    ensure!(!peers.is_empty(), "network has no bootstrap peers");
    let binary_hash = settings
        .get("OCTRA_BINARY_HASH")
        .map(|s| upgrade::normalize_hash("OCTRA_BINARY_HASH", s))
        .transpose()?
        .unwrap_or_else(|| vec![0; 32]);
    let config_hash = profile.wire_hash(chain, next)?;
    let require_binary_hash = settings.get("OCTRA_P2P_REQUIRE_BINARY_HASH") == Some(b"1");
    let upgrade =
        upgrade::from_inputs(&config_hash, require_binary_hash, |name| settings.get(name))?;
    let protocol = settings.protocol;
    let receipts = ReceiptPolicy::new(
        settings.get("OCTRA_PREVERIFY_RECEIPT_ACTIVATION_EPOCH"),
        &settings.transactions,
        settings.get("OCTRA_STEALTH_MIN_OU"),
    );
    let timeouts = TimeoutConfig::from_values(
        settings.get("OCTRA_BFT_TIMEOUT_BASE_MS"),
        settings.get("OCTRA_BFT_PROPOSE_TIMEOUT_MS"),
        settings.get("OCTRA_BFT_TIMEOUT_ROUND_MS"),
    );
    let ready_max_lag = settings
        .get("OCTRA_VALIDATOR_READY_MAX_LAG_EPOCHS")
        .and_then(native_integer::parse_int63)
        .unwrap_or(64)
        .max(0);
    let execution = executor::Config {
        graph: Graph::new(chain.to_vec(), Some(profile.ready_hash(chain)?)),
        protocol,
        profile: settings.transactions.clone(),
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        bundle: executor::Limits::new(
            settings.proposal_txs as usize,
            settings.proposal_bytes as usize,
            settings.proposal_ou.clone(),
        ),
        validators: settings.validators.clone(),
        emission: epoch_footer::Policy {
            emission_guard: settings.get("OCTRA_EMISSION_GUARD") == Some(b"1"),
            schedule: settings.emission,
            legacy_total: settings
                .get("OCTRA_LEGACY_TOTAL_SUPPLY_RAW")
                .map(<[u8]>::to_vec),
        },
        sender_key_activation: Some(settings.private_result_activation),
        private_result_activation: settings.private_result_activation,
        max_fhe: settings.fhe_slots as usize,
        max_stealth: settings.stealth_slots as usize,
        max_multi_exec_calls: settings.multi_exec as usize,
        ready_max_lag,
        pvac_dir: config.data.join("pvac"),
        migration,
    };
    let state_sync = crate::snapshot_export::Config::capture(
        config.network.clone(),
        config.data.clone(),
        settings,
        config.publisher,
        config.snapshot_limits,
    )?;
    Box::pin(launch::run(
        launch::Plan {
            status_release: Some(profile.status_release()),
            services: launch::Services {
                data: config.data,
                rpc: config.rpc,
                browser: config.browser,
                control: config.control,
                tunnel: config.tunnel,
                gateway: config.gateway,
                stock_portal: config.stock_portal,
                stock_circle_gateway: config.stock_circle_gateway,
                mesh: config.mesh,
            },
            transport: launch::Transport {
                listen: config.p2p,
                proxy: config.p2p_proxy,
                advertised,
                peers,
                maximum_peers: 32,
                config_hash: Some(config_hash),
                binary_hash,
                require_binary_hash,
                upgrade,
                profiles: profile.transitions(chain)?,
            },
            store,
            key,
            journal,
            environment,
            receipts,
            policy: Policy {
                protocol,
                genesis_time: None,
            },
            execution,
            runtime: runtime.with_program_keys(profile.keys.clone()),
            compute: octra_node_protocol::resource_compute::provider::Config::from_inputs(
                config.compute_provider,
                |name| settings.get(name).map(<[u8]>::to_vec),
            )?,
            vpn: config.vpn,
            payments: config.payments,
            voting,
            state_sync: Some(state_sync),
            minimum_peers: 1,
            health: octra_node_protocol::consensus::health::Config::from_inputs(|name| {
                settings.get(name)
            }),
            startup_timeout: Duration::from_secs(config.startup_seconds),
            timeouts,
            epoch_capacity: settings.proposal_ou.clone(),
            stealth_slots: settings.stealth_slots as usize,
        },
        shutdown,
    ))
    .await
}

/// Rust configuration supplies an explicit BFT/observer role. The native
/// shared network environment need not contain a local consensus-mode choice.
fn network_voting(voting: bool, publisher: bool, mode: Option<&[u8]>) -> Result<bool> {
    match mode
        .map(|mode| mode.trim_ascii().to_ascii_lowercase())
        .as_deref()
    {
        Some(b"single") => anyhow::bail!(
            "private Single mode requires an explicit private genesis and the Single launcher"
        ),
        None | Some(b"bft") => Ok(voting && !publisher),
        Some(b"observer") => Ok(false),
        _ => anyhow::bail!("invalid public network consensus mode"),
    }
}
#[cfg(test)]
mod role_tests {
    use super::*;
    use octra_exex::{ChainIdentity, StateRoot};
    use std::collections::BTreeMap;

    #[test]
    fn public_bootstrap_merges_configured_base_and_upstream_extra_once() {
        let settings = Settings::from_values(BTreeMap::from([
            (
                "OCTRA_BOOTSTRAP_PEERS".into(),
                b"base.example:19000,shared.example:19000".to_vec(),
            ),
            (
                "OCTRA_BOOTSTRAP_PEERS_EXTRA".into(),
                b"shared.example:19000,extra.example:19000".to_vec(),
            ),
            ("OCTRA_PEERS".into(), b"legacy.example:19000".to_vec()),
        ]))
        .unwrap();
        let configured = vec!["chosen.example:19000".into(), "base.example:19000".into()];
        let actual = bootstrap_peers(&configured, &settings)
            .iter()
            .map(Endpoint::encode)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                b"chosen.example:19000".to_vec(),
                b"base.example:19000".to_vec(),
                b"shared.example:19000".to_vec(),
                b"extra.example:19000".to_vec(),
            ]
        );
    }

    fn private_single() -> crate::single::launch::Config {
        crate::single::launch::Config {
            services: None,
            chain: ChainIdentity::genesis("octra-single-local-launch-test", StateRoot([7; 32])),
            data: "data".into(),
            key: "key".into(),
            seed: crate::single::launch::Seed {
                path: "seed.image".into(),
                bytes: 1,
                sha256: "00".repeat(32),
                ledger_root: "00".repeat(32),
                maximum_records: 1,
                maximum_string_bytes: 1024,
                date: 0,
            },
            settings: crate::single::Settings {
                mode: "single".into(),
                private_prior_fixture: true,
                wallet_address: vec![],
                wallet_public: vec![],
                validators: None,
                next_validators: None,
                activation: None,
                fee_recipient: None,
                epoch_capacity: "1".into(),
                stealth_minimum: "1".into(),
                maximum_defer: 0,
                inline_ranges: false,
                maximum_timestamp_drift: 0.,
                preverify_ttl: 45.,
                preverify_maximum: 64,
            },
            execution: crate::single::launch::Execution {
                activated_applications: false,
                release: None,
                crypto_profile: None,
                admit_ops: None,
                emission_guard: false,
                emission_activation: None,
                legacy_total: None,
                sender_key_activation: None,
                private_result_activation: 0,
                maximum_fhe: 0,
                maximum_stealth: 0,
                maximum_multi_exec: 0,
                ready_max_lag: 0,
            },
            rpc: "127.0.0.1:19870".parse().unwrap(),
            maximum_http_body: 1024,
        }
    }

    fn read_single(value: &serde_json::Value) -> Result<RoleConfig> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("single.json");
        std::fs::write(&path, serde_json::to_vec(value)?)?;
        read_role(&path)
    }

    #[test]
    fn standard_launcher_selects_only_explicit_private_single_genesis() {
        let mut value = serde_json::json!({"role":"single","single":private_single()});
        match read_single(&value).unwrap() {
            RoleConfig::Single(config) => {
                assert!(config.data.is_absolute());
                assert!(config.key.is_absolute());
                assert!(config.seed.path.is_absolute());
            }
            RoleConfig::Public(_) => panic!("Single config selected BFT"),
        }
        value["single"]["chain"] =
            serde_json::to_value(ChainIdentity::genesis("octra-mainnet", StateRoot([7; 32])))
                .unwrap();
        assert!(read_single(&value).is_err());
        value["single"]["chain"] = serde_json::to_value(private_single().chain).unwrap();
        value["single"]["settings"]["mode"] = serde_json::json!("bft");
        assert!(read_single(&value).is_err());
        value["single"]["settings"]["mode"] = serde_json::json!("single");
        value["network"] = serde_json::json!({});
        assert!(read_single(&value).is_err());
    }

    #[test]
    fn public_network_cannot_reinterpret_private_single_mode() {
        assert!(!network_voting(false, false, None).unwrap());
        assert!(!network_voting(true, false, Some(b"observer")).unwrap());
        assert!(network_voting(true, false, None).unwrap());
        assert!(network_voting(true, false, Some(b" BFT ")).unwrap());
        assert!(network_voting(false, false, Some(b"single")).is_err());
        assert!(network_voting(true, true, Some(b"single")).is_err());
        assert!(network_voting(true, false, Some(b"single")).is_err());
        assert!(network_voting(true, false, Some(b"typo")).is_err());
    }
}
