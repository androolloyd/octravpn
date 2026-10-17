//! Authenticated peer selection for a stopped native-format legacy source.
//! Modern canonical stores never furnish this capability. Selection owns its
//! query service; callers cannot provide a target, root or quorum Boolean.
use super::{layout, Backend, Options, UPSTREAM};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{catchup, codec::Wire, health, policy, ValidatorSet},
    fork_repair,
    network::{
        endpoint::{self, Endpoint},
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{self, Handler, MessageFuture, Swarm},
        upgrade,
    },
    state_sync::head::Head,
    transaction,
};
use octra_node_runtime::epoch_roots::{self, EpochRoots, Host, Response, State, WaitFor};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Args)]
pub struct StageOptions {
    /// Trusted public network config; its data path must be a stopped native store.
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub backend: PathBuf,
    #[arg(long)]
    pub backend_sha256: String,
}
impl StageOptions {
    pub async fn run(&self) -> Result<()> {
        println!(
            "{}",
            serde_json::to_string_pretty(&stage_if_proven(self).await?)?
        );
        Ok(())
    }
}
struct Captured {
    raw: Value,
    head: Head,
    active: ValidatorSet,
    stake: ValidatorSet,
}
fn decoded(value: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(
        value[field]
            .as_str()
            .with_context(|| format!("native {field} missing"))?,
    )?)
}
impl Captured {
    fn parse(raw: Value) -> Result<Self> {
        let head = fork_repair::parse_head(&decoded(&raw, "head")?).map_err(anyhow::Error::msg)?;
        let active = ValidatorSet::decode(&decoded(&raw, "active")?)?;
        let stake = ValidatorSet::decode(&decoded(&raw, "stake")?)?;
        ensure!(
            head.epoch_id >= 0 && active.n > 0 && stake.n > 0,
            "invalid native selection authority"
        );
        let token = raw["token"]
            .as_str()
            .context("native source token missing")?;
        ensure!(
            token.len() == 64
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid native source token"
        );
        Ok(Self {
            raw,
            head,
            active,
            stake,
        })
    }
}
struct Authority {
    active: ValidatorSet,
    stake: ValidatorSet,
    head: i64,
    key: SigningKey,
}
#[async_trait::async_trait]
impl Host for Authority {
    async fn state(&self) -> Result<State, octra_node_protocol::consensus::Error> {
        Ok(State {
            active: self.active.clone(),
            stake: self.stake.clone(),
            height: self.head + 1,
            head: self.head,
        })
    }
    async fn root(&self, _: i64) -> Result<Option<Vec<u8>>, octra_node_protocol::consensus::Error> {
        Ok(None)
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, octra_node_protocol::consensus::Error> {
        Ok(self.key.sign(bytes).to_bytes().to_vec())
    }
    fn remember(&self, _: i64, _: &Response) {}
    async fn request_missing_finalize(
        &self,
        _: i64,
        _: &[Response],
    ) -> Result<(), octra_node_protocol::consensus::Error> {
        Ok(())
    }
}
struct Queries(EpochRoots<Authority>);
impl Handler for Queries {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let roots = self.0.clone();
        Box::pin(async move {
            // This stopped-store maintenance session acquires evidence only;
            // it never advertises ledger service, votes, or finality replies.
            if frame.message == 0x35 {
                roots
                    .handle(&peer, &frame)
                    .await
                    .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            }
            Ok(())
        })
    }
}
struct Running {
    swarm: Swarm,
    task: JoinHandle<Result<(), octra_node_protocol::network::Error>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
struct Proof {
    target: i64,
    root: Vec<u8>,
}
enum Selection {
    Proven(Proof),
    Wait(&'static str),
}
fn roots_with_quorum(required: i64, local: &[u8], records: &[Response]) -> health::RootQuorum {
    health::peer_root_quorum(
        required,
        local,
        records.iter().map(|r| r.state_root.as_deref()),
    )
}
async fn select(
    roots: &EpochRoots<Authority>,
    captured: &Captured,
    chain: &[u8],
    config: &health::Config,
) -> Result<Selection> {
    let head = captured.head.epoch_id;
    let local = hex::decode(&captured.head.state_root)?;
    let required = health::required_attesters(
        captured.active.f,
        captured.active.n,
        config.state_attest_min_peers,
    );
    let responses = roots
        .query(head, 5., WaitFor::ConsensusQuorum, false)
        .await?;
    if (responses.len() as i64) < required {
        return Ok(Selection::Wait("low_peer_responses"));
    }
    let heads = responses
        .iter()
        .map(|r| catchup::PeerHead {
            responder_addr: r.responder_addr.clone(),
            responder_head_epoch: r.responder_head_epoch,
        })
        .collect::<Vec<_>>();
    let target = catchup::pick_target_epoch(&heads, captured.active.f, head)?;
    if target >= head {
        return Ok(Selection::Wait("not_ahead_of_peer_target"));
    }
    let initial = roots_with_quorum(required, &local, &responses);
    if matches!(
        initial,
        health::RootQuorum::Matching(_) | health::RootQuorum::Mismatching(_)
    ) {
        return Ok(Selection::Wait("current_root_has_quorum"));
    }
    if health::ahead_no_quorum_plan(
        head,
        head.saturating_sub(target),
        config.ahead_grace_epochs,
        config.ahead_drift_tolerance,
        false,
    ) == health::AheadNoQuorumPlan::WaitCurrentHead
    {
        return Ok(Selection::Wait("ahead_within_native_grace"));
    }
    let fresh = roots
        .query(head, 2., WaitFor::ConsensusQuorum, false)
        .await?;
    if health::ahead_current_root_plan(&roots_with_quorum(required, &local, &fresh))
        != health::AheadCurrentRootPlan::WaitCurrentRootQuorum
    {
        return Ok(Selection::Wait("fresh_current_root_has_quorum"));
    }
    if target < 0 || !policy::rewind_allowed(chain, head, target) {
        return Ok(Selection::Wait("rule_activation_rewind_refused"));
    }
    let target_responses = roots
        .query(target, 5., WaitFor::ConsensusQuorum, false)
        .await?;
    let Some(majority) = health::root_with_quorum(
        required,
        health::peer_root_majority(target_responses.iter().map(|r| r.state_root.as_deref())),
    ) else {
        return Ok(Selection::Wait("target_root_missing"));
    };
    let group = target_responses
        .into_iter()
        .filter(|r| r.state_root.as_ref() == Some(&majority.root))
        .collect::<Vec<_>>();
    if !epoch_roots::reached(
        chain,
        target,
        &captured.stake,
        WaitFor::ConsensusQuorum,
        &group,
    )? {
        return Ok(Selection::Wait("target_root_unproved"));
    }
    Ok(Selection::Proven(Proof {
        target,
        root: majority.root,
    }))
}
fn configured_entries(values: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut entries = values
        .unwrap_or_default()
        .split(|b| *b == b',')
        .map(endpoint::native_trim)
        .filter(|s| !s.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// Stage only. No ledger, chain, finality or signing journal is rewound here;
/// the existing explicit legacy resume command owns those ordered phases.
pub async fn stage_if_proven(options: &StageOptions) -> Result<Value> {
    let config = crate::network::read(&options.config)?;
    let _trust = crate::bootstrap::Authority::new(config.network.clone())?;
    let values = crate::network_profile::parse_env(&crate::bootstrap::read_limited(
        &config.environment,
        1_048_576,
    )?)?;
    let profile = crate::network_profile::Profile::new(values.clone())?;
    let settings = &profile.settings;
    let chain = config.network.identity.chain_id.as_bytes();
    ensure!(
        settings.get("OCTRA_CHAIN_ID") == Some(chain),
        "legacy chain differs from trusted network"
    );
    ensure!(
        settings.get("OCTRA_CONSENSUS_CONFIG_HASH") == Some(config.network.config_hash.as_bytes()),
        "legacy environment config differs from trusted network"
    );
    let mut validators = config
        .network
        .validators
        .iter()
        .map(|v| v.as_bytes().to_vec())
        .collect::<Vec<_>>();
    validators.sort();
    ensure!(
        configured_entries(settings.get("OCTRA_VALIDATORS")) == validators,
        "legacy validators differ from trusted network"
    );
    let directory = layout(&config.data)?;
    let key = crate::identity::read(&config.key)?;
    let backend_options = Options {
        directory: directory.clone(),
        chain_id: config.network.identity.chain_id.clone(),
        backend: options.backend.clone(),
        backend_sha256: options.backend_sha256.clone(),
    };
    let settings_json = Value::Object(
        values
            .into_iter()
            .map(|(name, value)| (name, Value::String(STANDARD.encode(value))))
            .collect(),
    );
    let origin = json!({"epoch":config.network.identity.origin.epoch(),"root":STANDARD.encode(config.network.identity.origin.state_root().0)});
    // Ownership spans every network await: the helper retains SC then SI until
    // its Session is dropped. It never lends a mutable native store to peers.
    let (mut backend, captured) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut backend = Backend::open(&backend_options, &directory)?;
        let captured = Captured::parse(
            backend.request(&json!({"op":"selection","settings":settings_json,"origin":origin}))?,
        )?;
        Ok((backend, captured))
    })
    .await??;
    let next = captured
        .head
        .epoch_id
        .checked_add(1)
        .context("source epoch overflow")?;
    ensure!(
        decoded(&captured.raw, "config_hash")? == profile.wire_hash(chain, next)?,
        "native source handshake profile differs"
    );
    let captured_head = captured.head.epoch_id;
    let state_root: [u8; 32] = hex::decode(&captured.head.state_root)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid native source root"))?;
    let advertised =
        Endpoint::parse(config.advertised.as_bytes()).context("invalid advertised P2P endpoint")?;
    let peers = endpoint::bootstrap(
        &config
            .peers
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        settings.get("OCTRA_BOOTSTRAP_PEERS").unwrap_or_default(),
        settings
            .get("OCTRA_BOOTSTRAP_PEERS_EXTRA")
            .unwrap_or_default(),
    );
    ensure!(
        !peers.is_empty(),
        "legacy selection requires configured bootstrap peers"
    );
    let binary_hash = decoded(&captured.raw, "binary_hash")?;
    let require_binary_hash = captured.raw["require_binary_hash"]
        .as_bool()
        .context("native binary policy missing")?;
    let config_hash = decoded(&captured.raw, "config_hash")?;
    let allowed_public_keys = captured.raw["allowed_keys"]
        .as_array()
        .context("native handshake admission missing")?
        .iter()
        .map(|value| Ok(STANDARD.decode(value.as_str().context("native handshake key missing")?)?))
        .collect::<Result<Vec<_>>>()?;
    let profiles = captured.raw["profiles"]
        .as_array()
        .context("native handshake transitions missing")?
        .iter()
        .map(|value| {
            Ok(swarm::Activation {
                epoch: value["epoch"]
                    .as_str()
                    .context("native transition epoch missing")?
                    .parse()?,
                config_hash: decoded(value, "config_hash")?,
                profile_hash: decoded(value, "profile_hash")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_profiles = profile.transitions(chain)?;
    ensure!(
        profiles.len() == expected_profiles.len()
            && profiles
                .iter()
                .zip(&expected_profiles)
                .all(|(native, rust)| native.epoch == rust.epoch
                    && native.config_hash == rust.config_hash
                    && native.profile_hash == rust.profile_hash),
        "native handshake transitions differ"
    );
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address = transaction::address_from_public_key(public.as_bytes());
    let swarm = Swarm::new(
        swarm::Config {
            chain_id: chain.to_vec(),
            node_address: address.clone(),
            config_hash: config_hash.clone(),
            binary_hash,
            require_binary_hash,
            upgrade: upgrade::from_inputs(&config_hash, require_binary_hash, |name| {
                settings.get(name)
            })?,
            profiles,
            allowed_public_keys,
            bootstrap: peers,
            maximum_validators: captured.active.n.max(1),
            advertised,
            timeouts: Timeouts::default(),
            head: Arc::new(move || (captured_head, state_root)),
        },
        key.clone(),
    )?;
    if let Some(proxy) = config.p2p_proxy {
        swarm.set_proxy(proxy)?;
    }
    let roots = EpochRoots::new(
        chain.to_vec(),
        address,
        Authority {
            active: captured.active.clone(),
            stake: captured.stake.clone(),
            head: captured_head,
            key,
        },
        swarm.clone(),
    );
    let listener = TcpListener::bind(config.p2p).await?;
    let running_swarm = swarm.clone();
    let dispatch = Arc::new(Queries(roots.clone()));
    let running = Running {
        swarm: swarm.clone(),
        task: tokio::spawn(async move { running_swarm.run(listener, dispatch).await }),
    };
    ensure!(
        (1..=3600).contains(&config.startup_seconds),
        "invalid startup timeout"
    );
    tokio::time::timeout(Duration::from_secs(config.startup_seconds), async {
        while swarm.peers().is_empty() {
            ensure!(!running.task.is_finished(), "legacy P2P service stopped");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("legacy peers unavailable")??;
    let selection = select(
        &roots,
        &captured,
        chain,
        &health::Config::from_inputs(|name| settings.get(name)),
    )
    .await?;
    let result = match selection {
        Selection::Wait(reason) => {
            json!({"format":"octra-legacy-repair-stage-v1","upstream":UPSTREAM,"staged":false,"reason":reason,"source":captured.head.epoch_id})
        }
        Selection::Proven(proof) => {
            ensure!(
                proof.target as u64 >= config.network.identity.origin.epoch(),
                "legacy target precedes trusted network origin"
            );
            let token = captured.raw["token"].clone();
            tokio::task::spawn_blocking(move || -> Result<_> {
                let staged = backend.request(&json!({"op":"stage","token":token,"target":proof.target,"root":STANDARD.encode(&proof.root)}))?;
                ensure!(staged["target"] == proof.target && staged["old_head"] == captured.head.epoch_id && staged["root"] == STANDARD.encode(&proof.root) && staged["restart_required"] == true, "native staged result differs");
                backend.close()?;
                Ok(json!({"format":"octra-legacy-repair-stage-v1","upstream":UPSTREAM,"staged":true,"source":captured.head.epoch_id,"target":proof.target,"root":hex::encode(proof.root),"restart_required":true,"all_rust_physical_backend":false}))
            }).await??
        }
    };
    drop(running);
    Ok(result)
}
