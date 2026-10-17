//! Shared node lifecycle. Network authority and execution policy are captured
//! by the launcher before any peer or application service is started.
use crate::{
    consensus::Canonical,
    driver,
    executor::{self, Native, Pending},
    peers::Network,
    rpc::Submission,
    Node,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_browser::application::UnavailableHost;
use octra_exex::{
    native_history::NativeTransaction, sqlite::SqliteCheckpoints, CommittedEpoch, ExEx,
    ExtensionStatus,
};
use octra_node_protocol::{
    consensus::{
        engine::{Engine, TimeoutConfig},
        journal::JournalOwner,
    },
    network::{endpoint::Endpoint, session::Timeouts, swarm, upgrade},
};
use octra_node_runtime::{
    canonical::CanonicalStore,
    circle::CircleRuntime,
    consensus_driver::{Driver, Host as _},
    finality::proposal::Policy,
    validator_history::{Authority, CanonicalValidators, Environment, ReceiptPolicy},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
pub(crate) struct Services {
    pub data: PathBuf,
    pub rpc: SocketAddr,
    pub browser: SocketAddr,
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
    pub gateway: Option<crate::gateway::Config>,
    pub mesh: Option<octravpn_node::mesh_control::Config>,
}
pub(crate) struct Transport {
    pub listen: SocketAddr,
    pub proxy: Option<SocketAddr>,
    pub advertised: Endpoint,
    pub peers: Vec<Endpoint>,
    pub maximum_peers: i64,
    pub config_hash: Option<Vec<u8>>,
    pub binary_hash: Vec<u8>,
    pub require_binary_hash: bool,
    pub upgrade: Option<upgrade::Plan>,
    pub profiles: Vec<swarm::Activation>,
}
pub(crate) struct Plan {
    pub services: Services,
    pub transport: Transport,
    pub store: CanonicalStore,
    pub key: SigningKey,
    pub journal: JournalOwner,
    pub environment: Environment,
    pub receipts: ReceiptPolicy,
    pub policy: Policy,
    pub execution: executor::Config,
    pub runtime: CircleRuntime,
    pub compute: octra_node_protocol::resource_compute::provider::Config,
    pub vpn: Option<crate::vpn::Config>,
    pub payments: Option<crate::vpn::payments::ServiceConfig>,
    pub voting: bool,
    pub state_sync: Option<crate::snapshot_export::Config>,
    pub minimum_peers: usize,
    pub startup_timeout: Duration,
    pub timeouts: TimeoutConfig,
    pub epoch_capacity: num_bigint::BigInt,
    pub stealth_slots: usize,
    pub status_release: Option<octra_node_runtime::status_read::Release>,
}
pub(crate) struct Unfunded;
#[async_trait::async_trait]
impl crate::vpn::Settlement for Unfunded {
    async fn session(
        &self,
        _: &crate::Committed,
        _: &octravpn_core::control::AnnounceSessionRequest,
        _: &octravpn_core::receipt::ReceiptContext,
    ) -> Result<Option<octravpn_node::admission::FundedSession>> {
        Ok(None)
    }
    async fn lifecycle(
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
    compute: octra_node_runtime::compute_service::Service,
    tokens: octra_node_runtime::token_rpc::Actor,
    http: Arc<crate::rpc::http::Service>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.signal.send_replace(true);
        self.swarm.stop();
        self.http.shutdown();
        let compute = self.compute.clone();
        let tokens = self.tokens.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                tokens.shutdown().await;
                let _ = compute.shutdown().await;
            });
        }
    }
}
pub(crate) fn service_stopped(
    task: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> anyhow::Error {
    match task {
        Some(Ok(Err(error))) => error,
        Some(Err(error)) => error.into(),
        _ => anyhow::anyhow!("node service stopped unexpectedly"),
    }
}
pub(crate) async fn supervise_archive(
    mut status: watch::Receiver<ExtensionStatus>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if *shutdown.borrow_and_update() {
            return Ok(());
        }
        match status.borrow_and_update().clone() {
            ExtensionStatus::Running { .. } | ExtensionStatus::Processing { .. } => {}
            ExtensionStatus::Failed { reason, .. } => {
                anyhow::bail!("archive ExEx failed: {reason}")
            }
            ExtensionStatus::Stopped { .. } => {
                anyhow::bail!("archive ExEx stopped unexpectedly")
            }
        }
        tokio::select! {
            biased;
            change = shutdown.changed() => {
                if change.is_err() { return Ok(()); }
            }
            change = status.changed() => {
                if change.is_err() { anyhow::bail!("archive ExEx status closed"); }
            }
        }
    }
}

pub(crate) async fn run(plan: Plan, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let Plan {
        services,
        transport,
        store,
        key,
        journal,
        environment,
        receipts,
        policy,
        execution,
        runtime,
        compute: compute_config,
        vpn,
        payments,
        voting,
        state_sync,
        minimum_peers,
        startup_timeout,
        timeouts,
        epoch_capacity,
        stealth_slots,
        status_release,
    } = plan;
    ensure!(
        vpn.is_none() || payments.is_none(),
        "select one VPN payment application"
    );
    let chain = store.chain().clone();
    let runtime = runtime.with_public_keys(Arc::new(octra_node_runtime::pvac::Files(
        execution.pvac_dir.clone(),
    )));
    let address = octra_node_protocol::transaction::address_from_public_key(
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key.verifying_key().as_bytes(),
        )
        .as_bytes(),
    );
    let reader = store.reader();
    let checkpoints = Arc::new(SqliteCheckpoints::open(&services.data.join("exex.db")).await?);
    let membership = CanonicalValidators::new(reader.clone(), environment.clone());
    let status_key = Arc::new(key.clone());
    let history_epoch_limit = match &status_release {
        Some(release) => release
            .settings
            .get("OCTRA_TX_BY_EPOCH_LIMIT_MAX")
            .and_then(octra_node_protocol::native_integer::parse_int63),
        None => std::env::var_os("OCTRA_TX_BY_EPOCH_LIMIT_MAX").and_then(|value| {
            octra_node_protocol::native_integer::parse_int63(value.as_encoded_bytes())
        }),
    }
    .unwrap_or(100)
    .max(1);
    let local_setting = |name: &str| match &status_release {
        Some(release) => release.settings.get(name).map(<[u8]>::to_vec),
        None => std::env::var_os(name).map(|value| value.as_encoded_bytes().to_vec()),
    };
    let fees = octra_node_protocol::submit_rpc::Fees::capture(local_setting);
    let grpc =
        octra_node_protocol::grpc::Config::capture(local_setting).map_err(anyhow::Error::msg)?;
    let http = Arc::new(crate::rpc::http::Service::new(
        services.data.clone(),
        status_release.as_ref().map(|release| &release.settings),
        chain.chain_id.as_bytes().to_vec(),
        key.verifying_key().to_bytes().to_vec(),
    ));
    let operator_rpc = local_setting("OCTRA_OPERATOR_RPC_URL")
        .map(String::from_utf8)
        .transpose()
        .context("operator RPC URL is not UTF-8")?;
    let automatic_duty = voting && execution.validators.lifecycle_enabled();
    let dynamic_handshake = execution.validators.lifecycle_enabled()
        || local_setting("OCTRA_CONSENSUS_ALLOW_DYNAMIC_PEERS").as_deref() == Some(b"1");
    let join = crate::consensus_join::Client::capture(local_setting)?;
    let pending_nonce_window = octra_node_protocol::transaction::Nonce::new(
        local_setting("OCTRA_BFT_PENDING_NONCE_WINDOW")
            .as_deref()
            .and_then(octra_node_protocol::native_integer::parse_int63)
            .unwrap_or(32)
            .max(1),
    )?;
    let observer_submissions = !voting
        && !local_setting("OCTRA_OBSERVER_RELAY_SUBMITS").is_some_and(|raw| {
            matches!(
                octra_node_protocol::network::endpoint::native_trim(&raw)
                    .to_ascii_lowercase()
                    .as_slice(),
                b"1" | b"true" | b"yes"
            )
        });
    let status_signer: octra_node_runtime::status_read::Signer = Arc::new(move |bytes| {
        use ed25519_dalek::Signer;
        status_key.sign(bytes).to_bytes().to_vec()
    });
    let driver_release = status_release.clone();
    let status = octra_node_runtime::status_read::Service::new(
        reader.clone(),
        membership.clone(),
        address.clone(),
        key.verifying_key().to_bytes().to_vec(),
        status_signer,
        status_release,
        Some(octra_node_protocol::view_key::public(key.verifying_key().as_bytes())?.to_vec()),
    )
    .with_control(&services.data);
    let opened = tokio::select! {
        opened = Node::open(
            store,
            Authority::new(reader.clone(), environment, receipts, journal.clone()),
            runtime.clone(),
            Arc::new(UnavailableHost),
            checkpoints,
        ) => opened?,
        _ = shutdown.wait_for(|stopping| *stopping) => return Ok(()),
    };
    let node = Arc::new(opened.with_view_graph(execution.graph.clone())?);
    node.register(Archive(services.data.join("exex"))).await?;
    let archive_status = node
        .extension_status("devnet-archive")
        .await
        .context("archive ExEx status missing")?;
    let head = node.head().await?;
    // The imported certificate authenticates the history floor; never invent
    // genesis or erase retained signing records when opening a snapshot.
    if journal.floor()?.is_none() {
        journal.set_floor(i64::try_from(node.store.anchor().cursor.epoch.0)?)?;
    }
    let validators = membership
        .expected_set(&head, head.cursor.epoch.0 as i64 + 1, None, &|_| {
            journal
                .latest_relief(head.cursor.epoch.0 as i64 + 1)
                .map_err(|e| e.as_bytes().to_vec())
        })
        .await?;
    let native_config = membership.config(&head).await?;
    if voting {
        // Native permissionless operators follow finality and pulse while
        // awaiting selection. Actual engine votes still require membership.
        for member in native_config
            .current
            .iter()
            .chain(&native_config.next)
            .chain(&native_config.active_members)
        {
            ensure!(
                member.address != address
                    || member.pubkey.as_slice() == key.verifying_key().as_bytes().as_slice(),
                "voting key differs from configured validator identity"
            );
        }
        ensure!(
            validators
                .public_key(&address)
                .is_none_or(|public| public == key.verifying_key().as_bytes()),
            "voting key differs from active validator identity"
        );
        ensure!(
            automatic_duty
                || validators.is_validator(&address)
                || native_config
                    .next
                    .iter()
                    .any(|member| member.address == address),
            "voting key is not in the active or scheduled validator set"
        );
    }
    let protocol = policy.protocol;
    // Native p2p_config separates handshake admission from validator authority.
    // Lifecycle mode must admit newly registered keys before their selection.
    let handshake_keys = if dynamic_handshake {
        Vec::new()
    } else {
        native_config.allowed_pubkeys
    };
    let validator_keys = native_config
        .active
        .validators
        .iter()
        .map(|member| member.pubkey.clone())
        .collect::<Vec<_>>();
    let compute_graph = execution.graph.clone();
    let compute_runtime = runtime.clone();
    let executor = Native::new(execution, runtime, node.history())?
        .with_submission_policy(observer_submissions, pending_nonce_window);
    let view = node.clone();
    let fallback = head.clone();
    let mut network = Network::new(
        TcpListener::bind(transport.listen).await?,
        swarm::Config {
            chain_id: chain.chain_id.as_bytes().to_vec(),
            node_address: address.clone(),
            config_hash: transport
                .config_hash
                .unwrap_or_else(|| native_config.hash.to_vec()),
            binary_hash: transport.binary_hash,
            require_binary_hash: transport.require_binary_hash,
            upgrade: transport.upgrade,
            profiles: transport.profiles,
            allowed_public_keys: handshake_keys,
            bootstrap: transport.peers,
            maximum_validators: transport.maximum_peers,
            advertised: transport.advertised,
            timeouts: Timeouts::default(),
            head: Arc::new(move || {
                let head = view.store.cached_head().unwrap_or_else(|| fallback.clone());
                (head.cursor.epoch.0 as i64, head.cursor.state_root.0)
            }),
        },
        key.clone(),
        node.history(),
        reader.clone(),
        membership.clone(),
        validators.clone(),
        journal.clone(),
    )?;
    if let Some(proxy) = transport.proxy {
        network.swarm.set_proxy(proxy)?;
    }
    if !validator_keys.is_empty() {
        network.swarm.set_validators(validator_keys)?;
    }
    let pending = Arc::new(Pending::open(services.data.join("pending.log"), &node.store).await?);
    let compute = crate::compute::open(
        node.clone(),
        reader,
        network.authority.clone(),
        network.swarm.clone(),
        key.clone(),
        address.clone(),
        compute_runtime,
        compute_graph,
        services.data.clone(),
        compute_config,
    )
    .await?;
    let status =
        Arc::new(status.with_consensus(Arc::new(network.authority.clone()), network.swarm.clone()));
    let staging_authority = network.authority.clone();
    let tokens = octra_node_runtime::token_rpc::Actor::new();
    let submission = Arc::new(Submission {
        node: node.clone(),
        executor: executor.clone(),
        pending: pending.clone(),
        swarm: network.swarm.clone(),
        policy,
        address: address.clone(),
        compute: Some(compute.clone()),
        vpn_program: vpn
            .as_ref()
            .map(|config| config.program.clone())
            .or_else(|| {
                payments
                    .as_ref()
                    .map(|config| config.application.program.clone())
            }),
        status: Some(status),
        tokens: Some(tokens.clone()),
        staging_notify: Arc::new(move || {
            if let Ok(Some(driver)) = staging_authority.driver() {
                let _ = driver.wake();
            }
        }),
        history_epoch_limit,
        fees,
        http: http.clone(),
    });
    let (stop, stopped) = watch::channel(false);
    let lifecycle = Stop {
        signal: stop.clone(),
        swarm: network.swarm.clone(),
        compute: compute.clone(),
        tokens,
        http,
    };
    let authority = network.authority.clone();
    let swarm = network.swarm.clone();
    let finality = network.finality.clone();
    let bundles = network.bundles.clone();
    let roots = network.roots.clone();
    let driver_config = driver::Config {
        key: key.clone(),
        address: address.clone(),
        policy,
        journal: journal.clone(),
        epoch_capacity,
        stealth_slots,
        evidence_dir: services.data.join("evidence"),
        release: driver_release,
    };
    let validator = driver::Validator::new(
        node.clone(),
        executor.clone(),
        pending.clone(),
        &network,
        driver_config.clone(),
    )?;
    let inbox = network.inbox.take().context("transaction inbox missing")?;
    let compute_inbox = network
        .compute_inbox
        .take()
        .context("compute inbox missing")?;
    let mut tasks = JoinSet::new();
    let mut archive_guard = tokio::spawn(supervise_archive(archive_status, stop.subscribe()));
    let mut archive_done = false;
    tasks.spawn(crate::compute::ingress(
        compute.clone(),
        compute_inbox,
        stop.subscribe(),
    ));
    tasks.spawn(async move { network.run(stopped).await.map_err(anyhow::Error::from) });
    let startup = async {
        let initialize = async {
            // This marker is a retained local observation, never membership or
            // an import authority. Corruption must not become a ready signal.
            let _ = crate::consensus_join::read_verified(
                &services.data,
                &node,
                key.verifying_key().as_bytes(),
            )
            .await?;
            if join.configured() {
                let report = join
                    .synchronize(
                        &node,
                        &executor,
                        &services.data,
                        &key,
                        voting,
                        tokio::time::Instant::now() + startup_timeout.min(Duration::from_secs(60)),
                    )
                    .await?;
                eprintln!(
                    "HTTP join synced={} verified={} source={} error={}",
                    report.synced,
                    report.records_verified,
                    report.source.as_deref().unwrap_or("none"),
                    report.error.as_deref().unwrap_or("none")
                );
            }
            // Peer announcements select a target only. Historical QCs and local
            // execution authenticate every imported epoch before voting starts.
            let deadline = tokio::time::Instant::now() + startup_timeout;
            while swarm.peers().len() < minimum_peers {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "waiting for authenticated peers timed out"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let peer_target = swarm
                .peers()
                .iter()
                .map(|p| p.hello().best_epoch)
                .max()
                .unwrap_or(0)
                .max(0) as u64;
            let target = join
                .proved_target(
                    &node,
                    &membership,
                    &executor,
                    tokio::time::Instant::now() + Duration::from_secs(20),
                )
                .await?
                .unwrap_or(0)
                .max(peer_target);
            let behind = target > node.head().await?.cursor.epoch.0;
            if behind && voting {
                let reached = node
                    .catch_up_range(target, &finality, &executor, 10.)
                    .await?
                    .reached;
                ensure!(
                    reached
                        || join
                            .catch_up_windows(&node, target, &executor, startup_timeout)
                            .await?
                            .reached,
                    "startup catch-up incomplete"
                );
            }
            if behind && !voting {
                // Expose suspended observer status while live recovery imports
                // authenticated history. Voting startup retains the strict gate.
                node.suspend("observer awaiting authenticated catch-up");
            } else {
                ensure!(node.resume().await?, "startup serving lease revoked");
            }
            if !behind || voting {
                // Restored queue entries need a current admission lease. The
                // observer stays closed until recovery resumes that lease.
                pending.recover(&submission).await?;
            }
            let height = node.head().await?.cursor.epoch.0 as i64 + 1;
            let set = if behind && !voting {
                validator.activate_retained(height).await?
            } else {
                validator.activate(height).await?
            };
            let mut engine = Engine::new(
                chain.chain_id.as_bytes().to_vec(),
                address.clone(),
                set,
                height,
                protocol,
                timeouts,
            );
            if behind && !voting {
                validator.recover_retained(&mut engine).await?;
            } else {
                validator.recover(&mut engine).await?;
            }
            validator.set_enabled(voting);
            let publication = Canonical::new(node.clone(), bundles.clone(), executor.clone(), 10.)
                .await?
                .with_pending(pending.clone());
            let (handle, driver) = Driver::new(
                engine,
                journal.clone(),
                swarm.clone(),
                validator,
                publication,
                Ok(vec![]),
            )?;
            authority.attach(handle)?;
            Ok::<_, anyhow::Error>(driver)
        };
        let mut driver = tokio::select! {
            initialized=initialize=>initialized?,
            task=tasks.join_next()=>return Err(service_stopped(task)),
        };
        let mut duty_handler = None;
        if automatic_duty {
            let duty = Arc::new(crate::duty::Service::new(
                submission.clone(),
                authority.clone(),
                key.clone(),
                &services.data,
                operator_rpc.clone(),
            )?);
            let handler = duty.handler();
            driver = driver.with_duty_handler(handler.clone());
            duty_handler = Some(handler);
            tasks.spawn(duty.run(stop.subscribe()));
        }
        let crate::vpn::Keys {
            receipt: receipt_key,
            wireguard,
            operator,
        } = crate::vpn::Keys::derive(&key);
        let paid = if let Some(config) = payments {
            config.ip_tunnel.validate()?;
            let application = Arc::new(node.payments(config.application, operator.clone())?);
            let directory = services.data.join("octranet-payments");
            tokio::fs::create_dir_all(&directory).await?;
            let (publisher, claims) = crate::vpn::payments::settlement::Service::open(
                submission.clone().context(),
                application.clone(),
                key.clone(),
                directory.join("claims"),
                config.max_claim_fees_ou,
            )
            .await?;
            tasks.spawn(claims.run(stop.subscribe()));
            Some(
                node.bind_payments(
                    services.browser,
                    octravpn_node::payments::Config {
                        control_listen: services.control,
                        tunnel_listen: services.tunnel,
                        data_dir: directory.join("transport"),
                        operator_key: Arc::new(octravpn_core::KeyPair::from_secret_bytes(
                            &key.to_bytes(),
                        )),
                        wireguard_secret: wireguard.clone(),
                        ip_tunnel: config.ip_tunnel,
                        credit: config.credit,
                    },
                    application,
                    publisher,
                )
                .await?,
            )
        } else {
            None
        };
        let mut ip_tunnel = vpn.as_ref().and_then(|config| config.ip_tunnel.clone());
        if let Some(config) = &mut ip_tunnel {
            config.validate()?;
            crate::vpn::storage::transport_book(&services.data, config);
        }
        let mut claim_publisher = None;
        let mut receipt_directory = services.data.join("vpn");
        let (settlement, receipt_context): (Arc<dyn crate::vpn::Settlement>, _) = match vpn {
            Some(config) => {
                let domain = config.domain()?;
                let pinned =
                    crate::vpn::Pinned::new(config, node.store.reader(), receipt_key.public)?;
                pinned.validate(&node.snapshot()?)?;
                let storage = crate::vpn::storage::paid(
                    &services.data,
                    node.store.chain(),
                    pinned.application(),
                    &domain,
                )
                .await?;
                receipt_directory = storage.receipts;
                let pinned = Arc::new(pinned);
                let (publisher, claims) = crate::vpn::settlement::Service::open(
                    submission.clone().context(),
                    pinned.clone(),
                    domain.clone(),
                    receipt_key.public,
                    key.clone(),
                    storage.claims,
                )
                .await?;
                tasks.spawn(claims.run(stop.subscribe()));
                claim_publisher = Some(publisher);
                (pinned, domain)
            }
            None => (
                Arc::new(Unfunded),
                octravpn_core::receipt::ReceiptContext::v2(operator.clone(), 9871, operator),
            ),
        };
        if let Some(config) = state_sync {
            tasks.spawn(crate::snapshot_export::run(
                node.clone(),
                config,
                key.clone(),
                stop.subscribe(),
            ));
        }
        let signal = stop.subscribe();
        let recovery = crate::recovery::Service {
            node: node.clone(),
            submission: submission.clone(),
            executor: executor.clone(),
            pending: pending.clone(),
            authority: authority.clone(),
            swarm: swarm.clone(),
            bundles,
            roots,
            finality,
            membership,
            join,
            config: driver_config,
            timeouts,
            voting,
            minimum_peers,
            budget: startup_timeout,
            duty: duty_handler,
        };
        tasks.spawn(recovery.run(driver, signal));
        let signal = stop.subscribe();
        tasks.spawn(submission.clone().ingress(inbox, signal));
        if let Some(config) = grpc {
            let service =
                crate::rpc::grpc::Service::bind(config, submission.clone().context()).await?;
            tasks.spawn(service.run(stop.subscribe()));
        }
        let listener = TcpListener::bind(services.rpc).await?;
        let mut signal = stop.subscribe();
        tasks.spawn(async move {
            axum::serve(listener, submission.router())
                .with_graceful_shutdown(async move {
                    let _ = signal.wait_for(|v| *v).await;
                })
                .await
                .map_err(anyhow::Error::from)
        });
        let mut bound = if let Some(paid) = paid {
            paid
        } else {
            node.bind_with_ip_tunnel(
                services.browser,
                octravpn_node::embedded::Config {
                    control_listen: services.control,
                    tunnel_listen: services.tunnel,
                    data_dir: receipt_directory,
                    receipt_key,
                    wireguard_secret: wireguard,
                    receipt_context,
                },
                settlement,
                ip_tunnel,
            )
            .await?
        };
        if let Some(publisher) = claim_publisher {
            bound = bound.with_settlement(publisher);
        }
        tasks.spawn(bound.run(stop.subscribe()));
        if let Some(mesh) = services.mesh.clone() {
            let service = mesh.bind().await?;
            tasks.spawn(service.run(stop.subscribe()));
        }
        if let Some(config) = services.gateway.clone() {
            let gateway = node.bind_gateway(config).await?;
            tasks.spawn(gateway.run(stop.subscribe()));
        }
        eprintln!(
            "node serving: chain={} RPC http://{} browser http://{} voting={}",
            chain.chain_id, services.rpc, services.browser, voting
        );
        Ok::<_, anyhow::Error>(())
    };
    let started = tokio::select! {
        r = startup => r,
        archive = &mut archive_guard => {
            archive_done = true;
            Err(service_stopped(Some(archive)))
        },
        _ = shutdown.wait_for(|v|*v) => Ok(()),
    };
    let result = if started.is_err() {
        started
    } else {
        tokio::select! {
            archive=&mut archive_guard=>{
                archive_done = true;
                Err(service_stopped(Some(archive)))
            },
            result=tasks.join_next()=>Err(service_stopped(result)),
            _=shutdown.wait_for(|v|*v)=>Ok(()),
        }
    };
    stop.send_replace(true);
    swarm.stop();
    node.suspend("node shutting down");
    if !archive_done
        && tokio::time::timeout(Duration::from_secs(8), &mut archive_guard)
            .await
            .is_err()
    {
        archive_guard.abort();
        let _ = archive_guard.await;
    }
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(8), drain)
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    executor.shutdown_migration_status().await;
    lifecycle.http.shutdown();
    lifecycle.tokens.shutdown().await;
    let computed = compute.shutdown().await;
    node.shutdown().await?;
    computed?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{Cursor, EpochId, Sequence, StateRoot};

    fn cursor() -> Cursor {
        Cursor {
            sequence: Sequence(0),
            epoch: EpochId(0),
            state_root: StateRoot([0; 32]),
        }
    }

    #[tokio::test]
    async fn archive_failure_ends_service_supervision_even_when_status_precedes_watcher() {
        for before_watch in [false, true] {
            let (status, receiver) = watch::channel(ExtensionStatus::Running {
                checkpoint: cursor(),
            });
            let (_stop, shutdown) = watch::channel(false);
            if before_watch {
                status.send_replace(ExtensionStatus::Failed {
                    checkpoint: cursor(),
                    reason: "archive disk full".into(),
                });
                let error = supervise_archive(receiver, shutdown).await.unwrap_err();
                assert!(error.to_string().contains("archive disk full"));
            } else {
                let watcher = tokio::spawn(supervise_archive(receiver, shutdown));
                status.send_replace(ExtensionStatus::Failed {
                    checkpoint: cursor(),
                    reason: "archive disk full".into(),
                });
                let error = watcher.await.unwrap().unwrap_err();
                assert!(error.to_string().contains("archive disk full"));
            }
        }
    }

    #[tokio::test]
    async fn archive_monitor_rejects_unexpected_stop_but_honors_node_shutdown() {
        let (status, receiver) = watch::channel(ExtensionStatus::Stopped {
            checkpoint: cursor(),
        });
        let (_stop, shutdown) = watch::channel(false);
        assert!(supervise_archive(receiver, shutdown).await.is_err());
        drop(status);

        let (status, receiver) = watch::channel(ExtensionStatus::Running {
            checkpoint: cursor(),
        });
        let (_stop, shutdown) = watch::channel(false);
        drop(status);
        assert!(supervise_archive(receiver, shutdown).await.is_err());

        let (status, receiver) = watch::channel(ExtensionStatus::Running {
            checkpoint: cursor(),
        });
        let (stop, shutdown) = watch::channel(false);
        stop.send_replace(true);
        assert!(supervise_archive(receiver, shutdown).await.is_ok());
        drop(status);
    }
}
