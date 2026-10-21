//! Canonical snapshot adapter for the Octranet payment application. Offers stay
//! in Circles; custody can use the existing Program or OCTB Circle host.
//! This reader does not grant packet forwarding without a host-owned meter.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::ChainIdentity;
use octra_node_protocol::{aml::emit::internal_key, transaction::decode_base64};
use octra_node_runtime::{
    canonical::Reader, circle_assets, circle_store, finality::history::History, program::store,
    state_batch::Snapshot,
};
use octravpn_core::{
    parse_native_address,
    payments::{Deployment, SignedUsage, Tariff},
    Address, PublicKey,
};
use octravpn_node::admission::Revocation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::Committed;
pub mod build;
mod offers;
#[cfg(test)]
use octra_node_runtime::{account_store, state_batch::StateBatch};
pub use offers::{Offer, OfferData};
#[cfg(test)]
mod circle_tests;
#[cfg(feature = "private-payments-experimental")]
pub mod shielded;
#[cfg(test)]
#[path = "../../../octra-node-runtime/tests/common/payments_host.rs"]
#[allow(dead_code)]
mod test_host;
#[cfg(test)]
mod tests;
mod transport;

const PLAN_MAX_AGE: Duration = Duration::from_secs(120);
const TARIFF_BYTES: i64 = 65_536;

/// Storage and call authority are selected explicitly. The legacy default is
/// unchanged; Circle applications use a separate receipt domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Application {
    #[default]
    Program,
    Circle,
}
impl Application {
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Serde's skip_serializing_if callback takes a reference"
    )]
    fn is_program(&self) -> bool {
        *self == Self::Program
    }
    fn call(self) -> octra_node_protocol::transaction::OpType {
        use octra_node_protocol::transaction::OpType;
        match self {
            Self::Program => OpType::ContractCall,
            Self::Circle => OpType::CircleCall,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Application::is_program")]
    pub application: Application,
    pub program: String,
    pub code_hash: String,
    pub factory: String,
    pub factory_code_hash: String,
    pub domain: String,
    pub operator_circle: String,
    /// Root offer of this product lineage; successor plans bind their actual ID.
    pub offer: u64,
}

/// Explicit opt-in to the new payment application. The existing VPN config
/// keeps its original wire and application contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub application: Config,
    pub ip_tunnel: octravpn_node::embedded::IpTunnelConfig,
    /// Lifetime relayer fee ceiling for this durable claim directory.
    pub max_claim_fees_ou: u64,
    /// Observer-only intake for already signed claims. Canonical state still
    /// decides whether a purchase completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_rpc_url: Option<String>,
}

/// Full-chain origin, rather than an RPC hostname or short network label.
pub fn network_domain(chain: &ChainIdentity) -> String {
    application_domain(chain, Application::Program)
}
/// Distinct application kinds cannot reinterpret an accepted receipt or journal.
pub fn application_domain(chain: &ChainIdentity, application: Application) -> String {
    let mut hash = Sha256::new();
    hash.update(match application {
        Application::Program => b"Octranet payments network v1\0".as_slice(),
        Application::Circle => b"Octranet Circle payments network v1\0".as_slice(),
    });
    hash.update(
        u64::try_from(chain.chain_id.len())
            .expect("chain identifier fits uint64")
            .to_be_bytes(),
    );
    hash.update(chain.chain_id.as_bytes());
    hash.update(chain.namespace_key());
    hex::encode(hash.finalize())
}

pub struct Payments {
    config: Config,
    history: Reader,
    deployment: Deployment,
    operator: Address,
    shared: Arc<crate::Shared>,
    circle_authority: Option<(octra_node_protocol::rules::Graph, Arc<dyn History>)>,
    retained: tokio::sync::Mutex<RetainedTariff>,
}

// A service's durable claim journal retains immutable tariffs per actual offer
// in the configured lineage. Plain read-only adapters may retain in memory;
// the production settlement service attaches its archive before serving peers.
trait TariffArchive: Send + Sync {
    fn load_tariff(&self, offer: u64) -> Result<Option<Tariff>>;
    fn save_tariff(&self, offer: u64, tariff: Tariff) -> Result<()>;
}
#[derive(Default)]
struct RetainedTariff {
    tariffs: BTreeMap<u64, Tariff>,
    archive: Option<Arc<dyn TariffArchive>>,
}

/// Read-only facts captured from one canonical publication.
#[derive(Clone, Debug)]
pub struct PlanData {
    pub deployment: Deployment,
    pub payer: Address,
    pub receipt_key: PublicKey,
    pub generation: u64,
    pub plan: u64,
    pub offer: u64,
    pub operator_generation: u64,
    pub offer_start_ms: u64,
    pub offer_end_ms: u64,
    pub manifest_hash: String,
    pub tariff: Tariff,
    pub original_budget_ou: u64,
    pub remaining_ou: u64,
    /// Canonical cumulative purchased bytes, independent of packet delivery.
    pub redeemed_bytes: Vec<u64>,
    pub redeemed_ou: Vec<u64>,
    pub opened_ms: u64,
    pub canonical_ms: u64,
    pub claim_deadline_ms: Option<u64>,
}

/// The lease and its bound facts cannot be replaced by an application caller.
#[derive(Clone)]
pub struct Plan {
    data: PlanData,
    eligible: bool,
    claim_eligible: bool,
    lease: Option<Lease>,
}

impl std::ops::Deref for Plan {
    type Target = PlanData;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[derive(Clone)]
struct Lease {
    revocation: Revocation,
    expires: Instant,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("plan", &self.plan)
            .field("offer", &self.offer)
            .field("admissible", &self.admissible())
            .field("claimable", &self.claimable())
            .finish_non_exhaustive()
    }
}

impl Plan {
    fn live(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| !lease.revocation.is_revoked() && Instant::now() < lease.expires)
    }
    pub fn admissible(&self) -> bool {
        self.eligible && self.live()
    }
    pub fn claimable(&self) -> bool {
        self.claim_eligible && self.live()
    }
    /// Validate a payer's exact authorization before queueing any relayed
    /// transaction. Replays never produce another increment or change payee.
    pub fn claim_increment(&self, signed: &SignedUsage) -> Result<u64> {
        ensure!(self.live(), "Octranet canonical plan lease expired");
        self.increment_at_snapshot(signed)
    }
    /// Authenticate an idempotent settlement retry even after the original
    /// authorization was redeemed. This does not grant another increment.
    pub fn validate_usage(&self, signed: &SignedUsage) -> Result<()> {
        ensure!(self.live(), "Octranet canonical plan lease expired");
        self.validate_at_snapshot(signed)
    }
    fn increment_at_snapshot(&self, signed: &SignedUsage) -> Result<u64> {
        self.validate_at_snapshot(signed)?;
        let usage = &signed.usage;
        ensure!(self.claim_eligible, "Octranet claim window closed");
        let class = usize::from(usage.traffic_class);
        let previous = self.redeemed_bytes[class];
        ensure!(
            usage.total_bytes > previous,
            "Octranet usage already redeemed"
        );
        let cumulative = self.tariff.charge(usage.traffic_class, usage.total_bytes)?;
        let increment = cumulative
            .checked_sub(self.redeemed_ou[class])
            .context("Octranet charge decreased")?;
        ensure!(
            increment <= self.remaining_ou,
            "Octranet plan budget exhausted"
        );
        Ok(increment)
    }
    fn validate_at_snapshot(&self, signed: &SignedUsage) -> Result<()> {
        signed.verify()?;
        let usage = &signed.usage;
        ensure!(
            usage.deployment == self.deployment
                && usage.payer == self.payer
                && usage.generation == self.generation
                && usage.plan == self.plan
                && usage.offer == self.offer
                && usage.manifest_hash == self.manifest_hash
                && signed.receipt_key == self.receipt_key,
            "Octranet receipt binding differs"
        );
        let class = usize::from(usage.traffic_class);
        ensure!(
            class < self.redeemed_bytes.len(),
            "Octranet class not found"
        );
        let mut purchased = self.redeemed_bytes.clone();
        purchased[class] = purchased[class].max(usage.total_bytes);
        ensure!(
            self.tariff.total_charge(&purchased)? <= self.original_budget_ou,
            "Octranet purchase exceeds original budget"
        );
        Ok(())
    }
}

impl Payments {
    pub(crate) fn new(
        config: Config,
        history: Reader,
        operator: Address,
        shared: Arc<crate::Shared>,
    ) -> Result<Self> {
        ensure!(
            config.domain == application_domain(history.chain(), config.application),
            "Octranet domain differs from full chain origin"
        );
        let deployment = Deployment {
            domain: config.domain.clone(),
            program: parse_native_address(&config.program)?,
        };
        deployment.validate()?;
        parse_native_address(&config.factory)?;
        parse_native_address(&config.operator_circle)?;
        digest(&config.code_hash)?;
        digest(&config.factory_code_hash)?;
        ensure!(
            parse_native_address(operator.display())? == operator,
            "Octranet operator address differs"
        );
        Ok(Self {
            config,
            history,
            deployment,
            operator,
            shared,
            circle_authority: None,
            retained: tokio::sync::Mutex::new(RetainedTariff::default()),
        })
    }

    pub async fn plan(&self, plan: u64) -> Result<Plan> {
        self.current_plan(plan, false).await
    }

    /// Re-read current custody and code pins against the exact retained tariff.
    /// Asset expiry cannot erase an already canonical purchase acknowledgment.
    /// New purchases still require an open payer and operator. This lease never
    /// grants traffic.
    pub async fn claim_plan(&self, plan: u64) -> Result<Plan> {
        self.current_plan(plan, true).await
    }

    async fn current_plan(&self, plan: u64, claim_only: bool) -> Result<Plan> {
        let serving = self.shared.current()?;
        let expires = serving.observed_at + PLAN_MAX_AGE;
        ensure!(Instant::now() < expires, "Octranet canonical head is stale");
        self.check_value_effects(&serving.committed).await?;
        let mut result = if claim_only {
            let fields = Fields::new(serving.committed.state(), &self.config);
            ensure!(
                plan < fields.uint(b"plan_count", &[])?,
                "Octranet plan not found"
            );
            let offer = fields.uint(b"plan_offer", &[&plan.to_string()])?;
            let retained = self.retained_tariff(offer).await?;
            if let Some(tariff) = retained {
                let now = self.canonical_time(&serving.committed).await?;
                self.read_state_with_tariff(serving.committed.state(), plan, now, Some(tariff))?
            } else {
                self.project(&serving.committed, plan).await?
            }
        } else {
            self.project(&serving.committed, plan).await?
        };
        if claim_only {
            result.eligible = false;
        }
        ensure!(
            !serving.revocation.is_revoked(),
            "Octranet canonical snapshot changed"
        );
        ensure!(Instant::now() < expires, "Octranet canonical head is stale");
        result.lease = Some(Lease {
            revocation: serving.revocation.clone(),
            expires,
        });
        Ok(result)
    }

    async fn check_value_effects(&self, view: &Committed) -> Result<()> {
        if self.config.application == Application::Circle {
            let (graph, history) = self
                .circle_authority
                .as_ref()
                .context("Octranet Circle execution authority is missing")?;
            let rules = octra_node_runtime::circle_view::canonical_with_graph(
                &view.assets,
                graph,
                history.as_ref(),
            )
            .await?;
            ensure!(
                rules.proof_exec == octra_node_protocol::transaction::RuleMode::Active,
                "Octranet Circle value effects are inactive"
            );
        }
        Ok(())
    }

    async fn canonical_time(&self, view: &Committed) -> Result<u64> {
        let octra_browser::Provenance::Canonical(identity) = view.provenance() else {
            anyhow::bail!("Octranet requires canonical state");
        };
        let head = view.head();
        ensure!(
            identity.chain_id == self.history.chain().chain_id
                && identity.origin == self.history.chain().origin
                && identity.epoch == head.cursor.epoch.0
                && identity.state_root == hex::encode(head.cursor.state_root.0)
                && identity.ledger_root == head.ledger_root
                && identity.irmin_commit == head.irmin_commit,
            "Octranet canonical identity differs"
        );
        ensure!(
            self.history.head_at(head.cursor.sequence).await? == *head,
            "Octranet retained head differs"
        );
        let millis = self
            .history
            .epoch_time_ms(head)
            .await?
            .context("Octranet canonical epoch clock missing")?;
        let now = u64::try_from(millis).context("Octranet canonical epoch clock invalid")?;
        ensure!(now > 0, "Octranet canonical epoch clock invalid");
        Ok(now)
    }

    async fn project(&self, view: &Committed, plan: u64) -> Result<Plan> {
        let now = self.canonical_time(view).await?;
        let plan = self.read_state(view.state(), plan, now)?;
        self.visible_tariff(view, &plan.manifest_hash, &plan.tariff)
            .await?;
        // With the production archive attached, durability precedes the grant.
        // Failed retention therefore prevents forwarding on this publication.
        self.retain_tariff(plan.offer, plan.tariff.clone()).await?;
        Ok(plan)
    }

    async fn visible_tariff(
        &self,
        view: &Committed,
        manifest: &str,
        tariff: &Tariff,
    ) -> Result<()> {
        // The storage primitive above binds bytes; the canonical resolver also
        // enforces Circle visibility, activation, expiry and revocation policy.
        use octra_browser::AssetResolver;
        let url = octra_browser::OctUrl::parse(&format!(
            "oct://{}/offers/{}/tariff.json",
            self.config.operator_circle, manifest
        ))?;
        let asset = view.assets.resolve(&url).await?;
        ensure!(
            asset.bytes.as_ref() == tariff.canonical_bytes()?,
            "Octranet public tariff differs"
        );
        Ok(())
    }

    fn read_state(&self, snapshot: &Snapshot, plan: u64, now: u64) -> Result<Plan> {
        self.read_state_with_tariff(snapshot, plan, now, None)
    }

    fn read_state_with_tariff(
        &self,
        snapshot: &Snapshot,
        plan: u64,
        now: u64,
        retained: Option<Tariff>,
    ) -> Result<Plan> {
        let claim_only = retained.is_some();
        let state = self.directory(snapshot)?;
        ensure!(
            plan < state.uint(b"plan_count", &[])?,
            "Octranet plan not found"
        );
        let plan_key = plan.to_string();
        let offer = state.uint(b"plan_offer", &[&plan_key])?;
        let quoted = self.offer_fields(&state, offer, now, retained)?;
        let payer_text = state.text(b"plan_payer", &[&plan_key])?;
        let payer = parse_native_address(&payer_text)?;
        let generation = state.uint(b"plan_generation", &[&plan_key])?;
        let active_generation = state.uint(b"generation", &[&payer_text])?;
        let active = state.uint(b"active", &[&payer_text])? == 1
            && active_generation == generation
            && generation > 0;
        let receipt_key_text = state.text(b"plan_receipt_key", &[&plan_key])?;
        let key = decode_base64(receipt_key_text.as_bytes())?;
        ensure!(
            STANDARD.encode(&key) == receipt_key_text,
            "Octranet receipt key encoding differs"
        );
        let receipt_key = PublicKey(
            key.try_into()
                .map_err(|_| anyhow::anyhow!("Octranet receipt key size differs"))?,
        );
        let mut redeemed_bytes = Vec::with_capacity(quoted.data.tariff.classes().len());
        let mut redeemed_ou = Vec::with_capacity(quoted.data.tariff.classes().len());
        for class in 0..quoted.data.tariff.classes().len() {
            let class_key = class.to_string();
            let bytes = state.uint(b"class_bytes", &[&plan_key, &class_key])?;
            let paid = state.uint(b"class_paid", &[&plan_key, &class_key])?;
            ensure!(
                quoted.data.tariff.charge(u8::try_from(class)?, bytes)? == paid,
                "Octranet redeemed charge differs"
            );
            redeemed_bytes.push(bytes);
            redeemed_ou.push(paid);
        }
        let total_paid = redeemed_ou
            .iter()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value))
            .context("Octranet redeemed total overflow")?;
        let remaining = state.uint(b"plan_remaining", &[&plan_key])?;
        let budget = state.uint(b"plan_budget", &[&plan_key])?;
        ensure!(
            budget > 0
                && remaining
                    .checked_add(total_paid)
                    .is_some_and(|total| total <= budget),
            "Octranet plan accounting differs"
        );
        let opened_ms = state.uint(b"plan_opened_ms", &[&plan_key])?;
        ensure!(
            opened_ms > 0 && opened_ms <= now,
            "Octranet plan clock differs"
        );
        let reserved = state.uint(b"reserved", &[&payer_text])?;
        let funds = state.uint(b"funds", &[&payer_text])?;
        ensure!(reserved <= funds, "Octranet custody accounting differs");
        let stopped = quoted.data.operator_stopped_ms;
        let user_deadline = state.uint(b"exit_deadline", &[&payer_text])?;
        ensure!(
            user_deadline == 0 || user_deadline <= now,
            "Octranet payer exit clock differs"
        );
        let claim_deadline_ms = match (user_deadline, stopped) {
            (0, 0) => None,
            (0, stop) => Some(stop),
            (exit, 0) => Some(exit),
            (exit, stop) => Some(exit.min(stop)),
        };
        let available = active && quoted.liquid && remaining <= reserved && remaining <= funds;
        Ok(Plan {
            data: PlanData {
                deployment: self.deployment.clone(),
                payer,
                receipt_key,
                generation,
                plan,
                offer,
                operator_generation: quoted.data.operator_generation,
                offer_start_ms: quoted.data.offer_start_ms,
                offer_end_ms: quoted.data.offer_end_ms,
                manifest_hash: quoted.data.manifest_hash,
                tariff: quoted.data.tariff,
                original_budget_ou: budget,
                remaining_ou: remaining,
                redeemed_bytes,
                redeemed_ou,
                opened_ms,
                canonical_ms: now,
                claim_deadline_ms,
            },
            eligible: !claim_only
                && available
                && quoted.provider_available
                && user_deadline == 0
                && quoted.quote_started,
            claim_eligible: available
                && quoted.provider_available
                && user_deadline == 0
                && quoted.purchase_open,
            lease: None,
        })
    }

    async fn retain_tariff(&self, offer: u64, tariff: Tariff) -> Result<()> {
        let mut retained = self.retained.lock().await;
        if let Some(previous) = retained.tariffs.get(&offer) {
            ensure!(
                previous == &tariff,
                "Octranet retained offer tariff changed"
            );
            return Ok(());
        }
        if let Some(archive) = retained.archive.clone() {
            let saved = tariff.clone();
            tokio::task::spawn_blocking(move || archive.save_tariff(offer, saved)).await??;
        }
        retained.tariffs.insert(offer, tariff);
        Ok(())
    }

    async fn retained_tariff(&self, offer: u64) -> Result<Option<Tariff>> {
        let mut retained = self.retained.lock().await;
        if !retained.tariffs.contains_key(&offer) {
            if let Some(archive) = retained.archive.clone() {
                // A cancelled grant may have durably saved before installing
                // its memory copy. Reload the exact offer after cancellation.
                if let Some(tariff) =
                    tokio::task::spawn_blocking(move || archive.load_tariff(offer)).await??
                {
                    retained.tariffs.insert(offer, tariff);
                }
            }
        }
        Ok(retained.tariffs.get(&offer).cloned())
    }

    async fn attach_archive(&self, archive: Arc<dyn TariffArchive>) -> Result<()> {
        let mut retained = self.retained.lock().await;
        ensure!(
            retained.archive.is_none(),
            "Octranet tariff archive already attached"
        );
        for (&offer, current) in &retained.tariffs {
            let disk = archive.clone();
            let existing = tokio::task::spawn_blocking(move || disk.load_tariff(offer)).await??;
            if let Some(existing) = existing {
                ensure!(current == &existing, "Octranet tariff archives differ");
            } else {
                let current = current.clone();
                let disk = archive.clone();
                tokio::task::spawn_blocking(move || disk.save_tariff(offer, current)).await??;
            }
        }
        retained.archive = Some(archive);
        Ok(())
    }

    fn tariff(&self, snapshot: &Snapshot, hash: &str) -> Result<Tariff> {
        let path = format!("/offers/{hash}/tariff.json");
        let asset = circle_assets::public_asset(
            snapshot,
            self.config.operator_circle.as_bytes(),
            path.as_bytes(),
            TARIFF_BYTES,
        )?;
        ensure!(
            asset.resource_mode == b"public_resources"
                && asset.meta.body_mode == octra_node_protocol::circles::ResourceMode::Public,
            "Octranet tariff must be a public Circle asset"
        );
        ensure!(
            asset.body_b64.len() <= (TARIFF_BYTES as usize).div_ceil(3) * 4,
            "Octranet tariff encoding exceeds bound"
        );
        let raw = decode_base64(asset.body_b64)?;
        ensure!(
            raw.len() == usize::try_from(asset.meta.size_bytes)?
                && hex::encode(Sha256::digest(&raw)) == hash
                && asset.meta.blob_hash == hash.as_bytes(),
            "Octranet tariff hash or size differs"
        );
        let tariff = Tariff::from_bytes(&raw)?;
        ensure!(
            tariff.canonical_bytes()? == raw && tariff.hash_hex()? == hash,
            "Octranet tariff must use canonical bytes"
        );
        Ok(tariff)
    }
}

impl<A: crate::Host> crate::Node<A> {
    /// Bind payment reads to the same suspension and revocation capability as
    /// the node's other native services. A history reader alone cannot grant it.
    pub fn payments(&self, config: Config, operator: Address) -> Result<Payments> {
        let mut payments =
            Payments::new(config, self.store.reader(), operator, self.shared.clone())?;
        payments.circle_authority = Some((self.view_graph.clone(), self.publisher.clone()));
        Ok(payments)
    }
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid Octranet digest"
    );
    Ok(())
}

fn check_application(
    application: Application,
    state: &Snapshot,
    program: &str,
    hash: &str,
    owner: Option<&[u8]>,
) -> Result<()> {
    if application == Application::Circle {
        let address = program.as_bytes();
        let info = circle_store::info(state, address)?.context("Octranet Circle not deployed")?;
        ensure!(
            info.runtime == b"octb"
                && info.circle_id == address
                && info.code_hash == hash.as_bytes()
                && owner.is_none_or(|owner| info.owner == owner),
            "Octranet Circle metadata differs"
        );
        ensure!(
            state.get(&[b"circles", address, b"call_code"]) == Some(hash.as_bytes()),
            "Octranet Circle value effects require current code admission"
        );
        let code = state
            .get(&[b"circles", address, b"program", b"code_b64"])
            .context("Octranet Circle bytecode missing")?;
        ensure!(
            hex::encode(Sha256::digest(decode_base64(code)?)) == hash,
            "Octranet Circle bytecode pin differs"
        );
        // Initialization writes a native stable root; a metadata-only spawn is
        // deliberately not an initialized payment application.
        if owner.is_some() {
            let root = state
                .hash_at(&[b"circles", address, b"stable"])?
                .context("Octranet Circle stable storage missing")?;
            ensure!(
                hex::encode(root).as_bytes() == info.stable_root,
                "Octranet Circle stable root differs"
            );
        }
        return Ok(());
    }
    let address = program.as_bytes();
    let meta = store::meta(state, address)?.context("Octranet program not deployed")?;
    ensure!(
        meta.address == address
            && meta.code_hash == hash.as_bytes()
            && owner.is_none_or(|owner| meta.owner == owner),
        "Octranet program metadata differs"
    );
    let raw = decode_base64(store::bytecode(state, address).context("Octranet bytecode missing")?)?;
    ensure!(
        hex::encode(Sha256::digest(&raw)) == hash,
        "Octranet bytecode pin differs"
    );
    Ok(())
}

struct Fields<'a> {
    snapshot: &'a Snapshot,
    program: &'a [u8],
    application: Application,
}
impl<'a> Fields<'a> {
    fn new(snapshot: &'a Snapshot, config: &'a Config) -> Self {
        Self {
            snapshot,
            program: config.program.as_bytes(),
            application: config.application,
        }
    }
    fn bytes(&self, field: &[u8], indices: &[&str]) -> Result<Option<Vec<u8>>> {
        let key = if indices.is_empty() {
            field.to_vec()
        } else {
            let mut key = internal_key(b"map", field);
            key.push(b'/');
            for index in indices {
                key.extend_from_slice(index.len().to_string().as_bytes());
                key.push(b'#');
                key.extend_from_slice(index.as_bytes());
            }
            key
        };
        if self.application == Application::Program {
            return Ok(self
                .snapshot
                .get(&[b"contracts", self.program, b"storage", &key])
                .map(<[u8]>::to_vec));
        }
        let hash = octra_node_protocol::circles::stable_key(&key);
        let Some(raw) = self.snapshot.get(&[
            b"circles",
            self.program,
            b"stable",
            b"by_hash",
            hash.as_bytes(),
        ]) else {
            return Ok(None);
        };
        ensure!(
            raw.len() <= 6 * 65_536 + 1024,
            "Octranet Circle field exceeds bound"
        );
        let entry = circle_store::StableEntry::parse(raw)?;
        ensure!(
            entry.key == key && entry.hash == hash.as_bytes(),
            "Octranet Circle field binding differs"
        );
        let circle_store::StableValue::Inline(value) = entry.value else {
            anyhow::bail!("Octranet Circle field is not inline");
        };
        ensure!(value.len() <= 65_536, "Octranet Circle value exceeds bound");
        Ok(Some(value))
    }
    fn uint(&self, field: &[u8], indices: &[&str]) -> Result<u64> {
        let Some(raw) = self.bytes(field, indices)? else {
            return Ok(0);
        };
        let text = std::str::from_utf8(&raw)?;
        let value: u64 = text.parse()?;
        ensure!(
            value.to_string() == text,
            "noncanonical Octranet numeric state"
        );
        Ok(value)
    }
    fn text(&self, field: &[u8], indices: &[&str]) -> Result<String> {
        Ok(std::str::from_utf8(
            &self
                .bytes(field, indices)?
                .context("Octranet state field missing")?,
        )?
        .to_owned())
    }
}

#[cfg(test)]
mod canonical_tests;

pub(crate) mod settlement;
