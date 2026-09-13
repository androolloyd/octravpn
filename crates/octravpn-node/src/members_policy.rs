//! Item 4 of the VPN design improvements — enforce the anchored member
//! set on the Tailscale wire.
//!
//! The tailnet's member set is sealed in the operator's circle at
//! `/auth/members.json` and bound by `state_root.auth_members_hash`; the
//! state root itself is anchored on chain (`get_circle_state_root`). Until
//! this module existed the wire `PolicyStore` started empty, so every
//! registered machine received the `allow_all_packet_filter` fallback and
//! the anchored membership was a fact nobody enforced.
//!
//! [`MembersPolicySync`] closes that gap. Each tick it:
//!
//! 1. reads the current epoch and re-reads the anchor only when the epoch
//!    moved (the anchor cannot change between epoch applies — same pattern
//!    as the relay keepers);
//! 2. verifies the sealed blob against the anchored hash and reduces it to
//!    the set of node keys (a Tailscale node key *is* the WireGuard key, so
//!    a member's `wg_pubkey_b64` is exactly the registry key);
//! 3. intersects that set with the live [`MachineRegistry`] and renders an
//!    ACL whose only `accept` rule has the matched machines' tailnet IPs as
//!    `src` and `*:*` as `dst`;
//! 4. installs it in the shared [`PolicyStore`] — which recomputes the
//!    packet filter and wakes every parked `/map` long-poller — but only
//!    when the rendered document actually changed.
//!
//! With `enforce_registration` on (the default), membership is also the
//! tailnet's *admission* rule rather than only its firewall:
//! [`MembersRegistrationGate`] refuses `register` for a node key outside
//! the anchored set, and each fetch deletes the registrations of devices
//! that have left it. A non-member therefore never appears in a member's
//! netmap at all — the packet filter alone leaves it visible-but-mute.
//!
//! Failure posture is fail-closed at boot and sticky afterwards: with no
//! good anchor loaded yet the wire gets a deny-all filter and refuses
//! registration (an unreachable chain must not degrade to allow-all), and
//! once a good anchor has been applied a later read failure keeps that
//! last good policy and set. Eviction only ever runs off a *verified*
//! fetch, so a chain outage cannot delete an operator's tailnet.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;

use anyhow::{anyhow, Context, Result};
use octravpn_core::v3_members::TailnetMembers;
use octravpn_mesh::policy::{parse_hujson_policy, PolicyDoc, PolicyStore};
use octravpn_mesh::tailscale_wire::{
    MachineRecord, MachineRegistrationStore, MachineRegistry, RegistrationAdmission,
    RegistrationGate,
};
use tracing::{debug, info, warn};

use crate::chain_v3::ChainCtxV3;
use crate::circle_update::{self, SealedAssetCreds, SealedRead};
use crate::config::NodeConfig;
use crate::control::enroll_circle::{KEY_ID, MEMBERS_PATH};
use crate::hub::Hub;

/// The anchored member set reduced to what the wire needs: the two
/// identities a registered device can be recognised by, plus the anchor
/// they were verified against.
///
/// Two, because the wire has two kinds of member. octravpn's own client
/// owns a stable WireGuard key, which is also its Tailscale *node* key —
/// that is the identity the packet filter and IP derivation use. A stock
/// `tailscale` device regenerates its node key on every
/// re-authentication (a refused registration burns it immediately), so
/// the only identity an operator can name ahead of time is its *machine*
/// key. A member matches on either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchoredMembers {
    /// `state_root.auth_members_hash` the blob was verified against;
    /// `None` when the circle has no anchor (or no member set) yet.
    pub root: Option<String>,
    /// Lowercase hex of each member's WireGuard/node key.
    pub node_keys: BTreeSet<String>,
    /// Lowercase hex of each member's Tailscale machine key.
    pub machine_keys: BTreeSet<String>,
}

impl AnchoredMembers {
    pub(crate) fn empty(root: Option<String>) -> Self {
        Self {
            root,
            node_keys: BTreeSet::new(),
            machine_keys: BTreeSet::new(),
        }
    }

    /// Reduce a verified member set to the identities the wire matches on.
    /// A member whose WireGuard key does not decode to 32 bytes fails the
    /// whole set: the anchored blob is validated on write, so this is
    /// corruption, not a per-member nit, and the caller keeps its last
    /// good policy.
    pub(crate) fn from_members(root: Option<String>, members: &TailnetMembers) -> Result<Self> {
        let mut node_keys = BTreeSet::new();
        let mut machine_keys = BTreeSet::new();
        for m in &members.members {
            if !m.wg_pubkey_b64.is_empty() {
                let key = member_node_key_hex(&m.wg_pubkey_b64)
                    .with_context(|| format!("member {}", m.wallet))?;
                node_keys.insert(key);
            }
            if !m.machine_key_hex.is_empty() {
                machine_keys.insert(m.machine_key_hex.to_ascii_lowercase());
            }
        }
        Ok(Self {
            root,
            node_keys,
            machine_keys,
        })
    }

    /// How many devices this set names.
    pub(crate) fn len(&self) -> usize {
        self.node_keys.len() + self.machine_keys.len()
    }

    /// Does this set name the device behind `(node_key, machine_key)`?
    /// Either identity is enough; both arrive from the wire in whatever
    /// case the client sent.
    pub(crate) fn admits(&self, node_key_hex: &str, machine_key_hex: &str) -> bool {
        (!node_key_hex.is_empty() && self.node_keys.contains(&node_key_hex.to_ascii_lowercase()))
            || (!machine_key_hex.is_empty()
                && self
                    .machine_keys
                    .contains(&machine_key_hex.to_ascii_lowercase()))
    }
}

/// Decode a member's `wg_pubkey_b64` into the node-key hex the wire
/// registry is keyed by.
pub(crate) fn member_node_key_hex(wg_pubkey_b64: &str) -> Result<String> {
    let raw = octravpn_core::b64::decode(wg_pubkey_b64)
        .map_err(|e| anyhow!("wg_pubkey_b64 is not base64: {e}"))?;
    if raw.len() != 32 {
        return Err(anyhow!(
            "wg_pubkey_b64 decodes to {} bytes, want 32",
            raw.len()
        ));
    }
    Ok(hex::encode(raw))
}

/// A rendered policy: the parsed document the store consumes, the raw
/// HuJSON that `GET /api/v1/policy` round-trips, and how many registered
/// machines were members.
pub(crate) struct RenderedPolicy {
    pub doc: PolicyDoc,
    pub raw: String,
    pub matched: usize,
}

/// Render the anchored member set against the live machine registry.
///
/// Every registered machine whose node key is a member contributes its
/// tailnet IPs to the single `accept` rule's `src`; everything else is
/// simply absent, which the packet filter reads as deny. With no member
/// registered the document still carries an (empty) `acls` key so the
/// store does not fall back to allow-all.
pub(crate) fn render_policy(
    circle_id: &str,
    anchored: &AnchoredMembers,
    machines: &HashMap<String, MachineRecord>,
) -> Result<RenderedPolicy> {
    let mut srcs: BTreeSet<String> = BTreeSet::new();
    let mut matched = 0usize;
    for rec in machines.values() {
        if !anchored.admits(&rec.node_key_hex, &rec.machine_key_hex) {
            continue;
        }
        matched += 1;
        if let Some(v4) = rec.ipv4 {
            srcs.insert(v4.to_string());
        }
        if let Some(v6) = rec.ipv6 {
            srcs.insert(v6.to_string());
        }
    }
    let acls = if srcs.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{
            "action": "accept",
            "src": srcs.iter().collect::<Vec<_>>(),
            "dst": ["*:*"],
        }])
    };
    let body = serde_json::to_string_pretty(&serde_json::json!({ "acls": acls }))
        .context("serialise members policy")?;
    // The header is part of the raw document on purpose: an operator
    // reading `GET /api/v1/policy` sees which anchor produced it. It must
    // stay free of anything that changes per tick (no epoch, no time) so
    // an unchanged policy compares equal and does not wake `/map` pollers.
    let raw = format!(
        "// octravpn members-policy: circle={circle_id} auth_members_hash={} members={} matched={matched}\n{body}\n",
        anchored.root.as_deref().unwrap_or("-"),
        anchored.len(),
    );
    let doc = parse_hujson_policy(&raw).map_err(|e| anyhow!("render members policy: {e}"))?;
    Ok(RenderedPolicy { doc, raw, matched })
}

/// Read the anchored member set: state root → `auth_members_hash` →
/// sealed `/auth/members.json` verified against it.
pub(crate) async fn fetch_anchored_members(
    ctx: &ChainCtxV3,
    circle_id: &str,
    creds: &SealedAssetCreds,
) -> Result<AnchoredMembers> {
    let sr = circle_update::fetch_current_state_root(ctx, circle_id, creds)
        .await
        .context("members policy: fetch circle state root")?;
    let Some(expected) = sr.as_ref().and_then(|s| s.auth_members_hash.as_deref()) else {
        return Ok(AnchoredMembers::empty(None));
    };
    match circle_update::read_sealed_asset(ctx, circle_id, MEMBERS_PATH, KEY_ID, creds, expected)
        .await
        .context("members policy: read sealed member set")?
    {
        SealedRead::Valid(bytes) => {
            let members = TailnetMembers::decode_lenient(&bytes)
                .map_err(|e| anyhow!("members policy: decode {MEMBERS_PATH}: {e}"))?;
            AnchoredMembers::from_members(Some(expected.to_string()), &members)
        }
        SealedRead::Absent => {
            warn!(
                circle = circle_id,
                auth_members_hash = expected,
                "members policy: state root anchors a member set but {MEMBERS_PATH} is absent; treating as empty"
            );
            Ok(AnchoredMembers::empty(Some(expected.to_string())))
        }
        SealedRead::Corrupt => Err(anyhow!(
            "members policy: {MEMBERS_PATH} failed hash/decrypt verification against auth_members_hash={expected}"
        )),
    }
}

/// Refusal text for a key that is not in the anchored set. It reaches the
/// person running `tailscale up`, so it says what to do about it.
pub(crate) const NOT_A_MEMBER_REFUSAL: &str =
    "this device is not in the tailnet's anchored member set — ask the operator to admit its \
     machine key with `octravpn-node auth members admit --machine-key …`; this login completes \
     on its own once they do";
/// Refusal text before any anchor has verified. Fail-closed, and a stock
/// client retries registration on its own.
pub(crate) const MEMBERS_NOT_LOADED_REFUSAL: &str =
    "the tailnet's member set has not been read from chain yet — retry shortly";

/// The anchored set as the registration gate sees it.
///
/// The sync task publishes each verified fetch here; the gate reads it on
/// every `register`. `None` means "nothing has verified yet", which the
/// gate treats as deny — the same posture as the deny-all packet filter.
#[derive(Clone, Default)]
pub(crate) struct SharedMembership {
    inner: Arc<RwLock<Option<AnchoredMembers>>>,
}

impl SharedMembership {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn publish(&self, anchored: &AnchoredMembers) {
        *self.inner.write() = Some(anchored.clone());
    }

    /// Admission verdict for a device, by either identity (hex, either
    /// case). `Err` carries the reason the client is shown.
    pub(crate) fn admit(&self, node_key_hex: &str, machine_key_hex: &str) -> Result<(), String> {
        let guard = self.inner.read();
        let Some(anchored) = guard.as_ref() else {
            return Err(MEMBERS_NOT_LOADED_REFUSAL.to_string());
        };
        if anchored.admits(node_key_hex, machine_key_hex) {
            Ok(())
        } else {
            Err(NOT_A_MEMBER_REFUSAL.to_string())
        }
    }
}

/// Registration gate backed by the anchored member set: membership on
/// chain is what admits a device to the tailnet.
pub(crate) struct MembersRegistrationGate {
    membership: SharedMembership,
}

impl MembersRegistrationGate {
    pub(crate) fn new(membership: SharedMembership) -> Self {
        Self { membership }
    }
}

#[async_trait]
impl RegistrationGate for MembersRegistrationGate {
    async fn admit(&self, req: RegistrationAdmission<'_>) -> Result<(), String> {
        self.membership.admit(req.node_key_hex, req.machine_key_hex)
    }
}

/// The wire handles the sync task drives: the registry and policy store the
/// wire surface reads, plus the durable store to delete evicted rows from.
pub(crate) struct MembersPolicyWiring {
    pub machines: Arc<MachineRegistry>,
    pub policy: Arc<PolicyStore>,
    pub registration_store: Option<Arc<dyn MachineRegistrationStore>>,
}

/// Node keys that hold a registration but are not in `anchored`.
///
/// Case-folded on the registry side: the wire stores the key as the client
/// sent it, while the anchored set is lowercase hex.
pub(crate) fn non_member_registrations(
    registered: &HashMap<String, MachineRecord>,
    anchored: &AnchoredMembers,
) -> Vec<String> {
    let mut stale: Vec<String> = registered
        .iter()
        .filter(|(node_key, rec)| !anchored.admits(node_key, &rec.machine_key_hex))
        .map(|(node_key, _)| node_key.clone())
        .collect();
    stale.sort();
    stale
}

/// What one tick does, decided from the epoch and registry generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Plan {
    fetch: bool,
    render: bool,
}

/// Pure tick bookkeeping, kept free of I/O so the epoch/generation
/// gating is unit-testable.
#[derive(Default)]
struct SyncState {
    last_epoch: Option<u64>,
    last_generation: Option<u64>,
    /// Last anchor that verified. `None` until the first good read.
    anchored: Option<AnchoredMembers>,
    /// Raw document last handed to the store; unchanged ⇒ no `set`.
    applied_raw: Option<String>,
}

impl SyncState {
    /// The anchor can only move with the epoch, so it is re-read when the
    /// epoch moved, could not be read, or nothing good is loaded yet. A
    /// render is due whenever the anchor or the machine set may have
    /// changed, and always until something has been applied.
    fn plan(&mut self, epoch: Option<u64>, generation: u64) -> Plan {
        let epoch_moved = match epoch {
            Some(e) => self.last_epoch != Some(e),
            None => true,
        };
        let generation_moved = self.last_generation != Some(generation);
        let fetch = epoch_moved || self.anchored.is_none();
        let render = fetch || generation_moved || self.applied_raw.is_none();
        if let Some(e) = epoch {
            self.last_epoch = Some(e);
        }
        self.last_generation = Some(generation);
        Plan { fetch, render }
    }

    /// The set the wire is rendered from: the last good anchor, or — fail
    /// closed — an empty set while none has loaded.
    fn effective(&self) -> AnchoredMembers {
        self.anchored
            .clone()
            .unwrap_or_else(|| AnchoredMembers::empty(None))
    }
}

/// Where the sync reads chain state from: the Hub's own context, or a
/// standalone one built from `[chain]` for `mesh serve` (the wire surface
/// stock `tailscale up` can actually reach — the Hub has no TLS listener).
pub(crate) enum ChainHandle {
    Hub(Arc<Hub>),
    Owned(Arc<ChainCtxV3>),
}

impl ChainHandle {
    fn ctx(&self) -> &ChainCtxV3 {
        match self {
            Self::Hub(hub) => &hub.chain_v3,
            Self::Owned(ctx) => ctx,
        }
    }
}

/// The boot-resolved half of the sync task. Config errors surface here,
/// at boot, so a misconfigured operator fails loudly instead of running
/// with a silently unenforced wire.
pub(crate) struct MembersPolicySync {
    chain: ChainHandle,
    circle_id: String,
    creds: SealedAssetCreds,
    period: Duration,
    /// Published on every verified fetch; read by the registration gate.
    membership: SharedMembership,
    /// Refuse registration for non-members and delete the registrations of
    /// devices that leave the set. See `[control.members_policy]
    /// enforce_registration`.
    enforce_registration: bool,
}

impl MembersPolicySync {
    /// Hub boot path (`octravpn-node run`): `[control.members_policy]`.
    pub(crate) fn from_hub(hub: &Arc<Hub>) -> Result<Self> {
        let cfg = &hub.cfg.control.members_policy;
        let circle_id = cfg
            .circle_id
            .clone()
            .or_else(|| hub.cfg.chain.circle_id.clone())
            .ok_or_else(|| {
                anyhow!(
                    "[control.members_policy].enabled needs a circle: set \
                     [control.members_policy].circle_id or [chain].circle_id"
                )
            })?;
        let creds = hub
            .sealed_asset_creds()
            .context("[control.members_policy] needs the sealed-asset passphrase")?;
        Ok(Self {
            chain: ChainHandle::Hub(Arc::clone(hub)),
            circle_id,
            creds,
            period: cfg.resolved_sync_period(),
            membership: SharedMembership::new(),
            enforce_registration: cfg.enforce_registration,
        })
    }

    /// `mesh serve --members-policy-circle`: a chain context built from
    /// the `--config` file's `[chain]` table (RPC, program, wallet), the
    /// sealed passphrase from `OCTRAVPN_SEALED_PASSPHRASE` or
    /// `[chain].sealed_passphrase`.
    pub(crate) fn from_config(
        cfg: &NodeConfig,
        circle_override: Option<String>,
        period_secs_override: Option<u64>,
    ) -> Result<Self> {
        let mp = &cfg.control.members_policy;
        let circle_id = circle_override
            .or_else(|| mp.circle_id.clone())
            .or_else(|| cfg.chain.circle_id.clone())
            .ok_or_else(|| {
                anyhow!(
                    "members policy needs a circle: pass --members-policy-circle or set \
                     [control.members_policy].circle_id / [chain].circle_id"
                )
            })?;
        let chain = crate::v3_cli::build_chain_ctx_for_circle(cfg)
            .context("members policy: build chain context from [chain]")?;
        let passphrase = crate::hub::boot::resolve_sealed_passphrase(
            std::env::var("OCTRAVPN_SEALED_PASSPHRASE").ok().as_deref(),
            cfg.chain.sealed_passphrase_expose(),
        )
        .context("members policy needs the sealed-asset passphrase")?;
        let period = period_secs_override.map_or_else(
            || mp.resolved_sync_period(),
            |s| Duration::from_secs(s.clamp(5, 3600)),
        );
        Ok(Self {
            chain: ChainHandle::Owned(Arc::new(chain)),
            circle_id,
            creds: SealedAssetCreds::new(passphrase.as_str()),
            period,
            membership: SharedMembership::new(),
            enforce_registration: mp.enforce_registration,
        })
    }

    /// The gate to hand `WireStateBuilder::registration_gate`, or `None`
    /// when this deployment enforces membership with the packet filter
    /// only. Must be taken before [`Self::run`] consumes the sync — both
    /// share one [`SharedMembership`].
    pub(crate) fn registration_gate(&self) -> Option<Arc<dyn RegistrationGate>> {
        if !self.enforce_registration {
            return None;
        }
        Some(Arc::new(MembersRegistrationGate::new(
            self.membership.clone(),
        )))
    }

    /// The sync loop. Never returns; dropped on shutdown with the runtime.
    pub(crate) async fn run(self, wiring: MembersPolicyWiring) {
        let MembersPolicyWiring {
            machines,
            policy,
            registration_store,
        } = wiring;
        info!(
            circle = %self.circle_id,
            period_secs = self.period.as_secs(),
            enforce_registration = self.enforce_registration,
            "members policy sync started"
        );
        let generation_rx = machines.subscribe_gen();
        let mut state = SyncState::default();
        loop {
            let epoch = match self.chain.ctx().current_epoch().await {
                Ok(e) => Some(e),
                Err(e) => {
                    debug!(error = %e, "members policy: epoch read failed; re-reading anchor anyway");
                    None
                }
            };
            let generation = *generation_rx.borrow();
            let plan = state.plan(epoch, generation);

            if plan.fetch {
                match fetch_anchored_members(self.chain.ctx(), &self.circle_id, &self.creds).await {
                    Ok(a) => {
                        if state.anchored.as_ref() != Some(&a) {
                            info!(
                                circle = %self.circle_id,
                                auth_members_hash = a.root.as_deref().unwrap_or("-"),
                                members = a.len(),
                                "members policy: anchored member set loaded"
                            );
                        }
                        // Publish before evicting: the gate must already be
                        // refusing a key by the time its registration goes,
                        // or the client would simply re-register.
                        self.membership.publish(&a);
                        if self.enforce_registration {
                            evict_non_members(&machines, registration_store.as_ref(), &a).await;
                        }
                        state.anchored = Some(a);
                    }
                    Err(e) if state.anchored.is_some() => {
                        warn!(error = %e, "members policy: anchor read failed; keeping last good policy");
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "members policy: no anchored member set loaded yet; wire stays deny-all until one verifies"
                        );
                    }
                }
            }

            if plan.render {
                let effective = state.effective();
                let snapshot = machines.snapshot();
                match render_policy(&self.circle_id, &effective, &snapshot) {
                    Ok(rendered) if state.applied_raw.as_deref() == Some(rendered.raw.as_str()) => {
                        debug!("members policy: unchanged");
                    }
                    Ok(rendered) => {
                        info!(
                            matched = rendered.matched,
                            registered = snapshot.len(),
                            members = effective.len(),
                            auth_members_hash = effective.root.as_deref().unwrap_or("-"),
                            "members policy applied to wire packet filter"
                        );
                        policy.set(rendered.doc, rendered.raw.clone());
                        state.applied_raw = Some(rendered.raw);
                    }
                    Err(e) => {
                        warn!(error = %e, "members policy: render failed; keeping last applied policy");
                    }
                }
            }

            tokio::time::sleep(self.period).await;
        }
    }
}

/// Delete every registration that is no longer a member, from both the live
/// registry (which wakes each peer's `/map` with a `peers_removed`) and the
/// durable store. Returns how many were dropped.
///
/// Only ever called with a freshly verified anchor: a chain read failure
/// must not be able to dissolve an operator's tailnet.
async fn evict_non_members(
    machines: &MachineRegistry,
    store: Option<&Arc<dyn MachineRegistrationStore>>,
    anchored: &AnchoredMembers,
) -> usize {
    let stale = non_member_registrations(&machines.snapshot(), anchored);
    let mut dropped = 0usize;
    for node_key in &stale {
        let removed = machines.delete(node_key);
        if let Some(store) = store {
            if let Err(e) = store.delete_machine_registration(node_key).await {
                warn!(
                    node_key = %node_key,
                    error = %e,
                    "members policy: could not delete the durable registration of an evicted device"
                );
            }
        }
        if removed {
            dropped += 1;
            info!(
                node_key = %node_key,
                "members policy: registration deleted — the device is no longer an anchored member"
            );
        }
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::v3_members::Member;
    use octravpn_mesh::policy::acl_to_filter_rules;
    use std::net::Ipv4Addr;

    fn key(fill: u8) -> (String, String) {
        let raw = [fill; 32];
        (octravpn_core::b64::encode(raw), hex::encode(raw))
    }

    /// Does any rendered `src_ips` entry (a bare IPv4 or `a.b.c.d/len`)
    /// contain `ip`?
    fn covers(srcs: &BTreeSet<String>, ip: Ipv4Addr) -> bool {
        srcs.iter().any(|s| {
            let (net, len) = match s.split_once('/') {
                Some((net, len)) => (net, len.parse::<u32>().unwrap()),
                None => (s.as_str(), 32),
            };
            let Ok(net) = net.parse::<Ipv4Addr>() else {
                return false;
            };
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        })
    }

    fn machine(node_key_hex: &str, ip: Ipv4Addr) -> MachineRecord {
        MachineRecord::new_at(
            chrono::Utc::now(),
            node_key_hex.to_string(),
            "bb".repeat(32),
            "interop".to_string(),
            format!("host-{}", &node_key_hex[..4]),
            ip,
            false,
        )
    }

    #[test]
    fn node_key_hex_is_the_decoded_wg_key() {
        let (b64, hex) = key(0xab);
        assert_eq!(member_node_key_hex(&b64).unwrap(), hex);
        assert!(member_node_key_hex("not base64!").is_err());
        assert!(member_node_key_hex(&octravpn_core::b64::encode([1u8; 31])).is_err());
    }

    #[test]
    fn from_members_reduces_to_node_keys_and_fails_closed_on_corruption() {
        let (a_b64, a_hex) = key(0x01);
        let (b_b64, b_hex) = key(0x02);
        let members = TailnetMembers::new_v1(
            7,
            "00".repeat(32),
            vec![
                Member {
                    wallet: "octA".into(),
                    wg_pubkey_b64: a_b64,
                    machine_key_hex: String::new(),
                    joined_epoch: 1,
                },
                Member {
                    wallet: "octB".into(),
                    wg_pubkey_b64: b_b64,
                    machine_key_hex: String::new(),
                    joined_epoch: 2,
                },
            ],
            0,
            0,
        );
        let anchored = AnchoredMembers::from_members(Some("r".into()), &members).unwrap();
        assert_eq!(
            anchored.node_keys,
            BTreeSet::from([a_hex, b_hex]),
            "both members present, as lowercase hex"
        );

        let mut corrupt = members;
        corrupt.members[0].wg_pubkey_b64 = "short".into();
        assert!(AnchoredMembers::from_members(None, &corrupt).is_err());
    }

    #[test]
    fn render_admits_exactly_the_registered_members() {
        let (_, a_hex) = key(0x0a);
        let (_, b_hex) = key(0x0b);
        let (_, stranger_hex) = key(0x0c);
        let anchored = AnchoredMembers {
            root: Some("deadbeef".into()),
            node_keys: BTreeSet::from([a_hex.clone(), b_hex.clone()]),
            machine_keys: BTreeSet::new(),
        };
        let mut registry = HashMap::new();
        registry.insert(
            a_hex.clone(),
            machine(&a_hex, Ipv4Addr::new(100, 64, 0, 10)),
        );
        // Registry keys arrive as the wire sent them; matching is
        // case-insensitive on the hex.
        registry.insert(
            b_hex.to_ascii_uppercase(),
            machine(&b_hex.to_ascii_uppercase(), Ipv4Addr::new(100, 64, 0, 11)),
        );
        registry.insert(
            stranger_hex.clone(),
            machine(&stranger_hex, Ipv4Addr::new(100, 64, 0, 99)),
        );

        let rendered = render_policy("octCircle", &anchored, &registry).unwrap();
        assert_eq!(rendered.matched, 2);
        assert!(
            rendered.raw.starts_with("// octravpn members-policy: circle=octCircle auth_members_hash=deadbeef members=2 matched=2\n"),
            "raw: {}",
            rendered.raw
        );
        // The filter compiler may aggregate adjacent hosts into one prefix
        // (100.64.0.10 + .11 ⇒ 100.64.0.10/31), so assert coverage, not
        // literal strings.
        let rules = acl_to_filter_rules(&rendered.doc);
        let srcs: BTreeSet<String> = rules.iter().flat_map(|r| r.src_ips.clone()).collect();
        assert!(
            covers(&srcs, Ipv4Addr::new(100, 64, 0, 10)),
            "srcs: {srcs:?}"
        );
        assert!(
            covers(&srcs, Ipv4Addr::new(100, 64, 0, 11)),
            "srcs: {srcs:?}"
        );
        assert!(
            !covers(&srcs, Ipv4Addr::new(100, 64, 0, 99)),
            "the stranger must not be a source: {srcs:?}"
        );
        // Same inputs ⇒ byte-identical raw, so an unchanged tick is a no-op.
        assert_eq!(
            render_policy("octCircle", &anchored, &registry)
                .unwrap()
                .raw,
            rendered.raw
        );
    }

    #[test]
    fn render_with_no_members_is_deny_all_not_allow_all() {
        let (_, stranger_hex) = key(0x0c);
        let mut registry = HashMap::new();
        registry.insert(
            stranger_hex.clone(),
            machine(&stranger_hex, Ipv4Addr::new(100, 64, 0, 99)),
        );
        let rendered =
            render_policy("octCircle", &AnchoredMembers::empty(None), &registry).unwrap();
        assert_eq!(rendered.matched, 0);
        assert!(acl_to_filter_rules(&rendered.doc).is_empty());
        // The store decides allow-all by the *absence* of an acls key;
        // the rendered document must always carry one.
        let store = PolicyStore::new();
        store.set(rendered.doc, rendered.raw);
        assert!(store.is_loaded());
    }

    #[test]
    fn gate_admits_members_refuses_strangers_and_fails_closed_before_the_first_anchor() {
        let (_, member_hex) = key(0x21);
        let (_, stranger_hex) = key(0x22);
        let membership = SharedMembership::new();

        // Nothing verified yet ⇒ deny, with the retry-shaped reason.
        assert_eq!(
            membership.admit(&member_hex, ""),
            Err(MEMBERS_NOT_LOADED_REFUSAL.to_string())
        );

        membership.publish(&AnchoredMembers {
            root: Some("deadbeef".into()),
            node_keys: BTreeSet::from([member_hex.clone()]),
            machine_keys: BTreeSet::new(),
        });
        assert_eq!(membership.admit(&member_hex, ""), Ok(()));
        // The wire hands the key back as the client sent it.
        assert_eq!(
            membership.admit(&member_hex.to_ascii_uppercase(), ""),
            Ok(())
        );
        assert_eq!(
            membership.admit(&stranger_hex, ""),
            Err(NOT_A_MEMBER_REFUSAL.to_string())
        );

        // An empty verified set denies everyone — it does not fall back to
        // "not loaded yet".
        membership.publish(&AnchoredMembers::empty(None));
        assert_eq!(
            membership.admit(&member_hex, ""),
            Err(NOT_A_MEMBER_REFUSAL.to_string())
        );
    }

    #[tokio::test]
    async fn gate_answers_through_the_wire_trait() {
        let (_, member_hex) = key(0x23);
        let membership = SharedMembership::new();
        membership.publish(&AnchoredMembers {
            root: None,
            node_keys: BTreeSet::from([member_hex.clone()]),
            machine_keys: BTreeSet::new(),
        });
        let gate = MembersRegistrationGate::new(membership);
        let req = |node_key_hex: &'static str| RegistrationAdmission {
            node_key_hex,
            machine_key_hex: "bb",
            hostname: Some("peer-a"),
        };
        let leaked: &'static str = Box::leak(member_hex.into_boxed_str());
        assert!(gate.admit(req(leaked)).await.is_ok());
        assert!(gate.admit(req("ff")).await.is_err());
    }

    /// A stock device is named by its machine key, which is the only
    /// identity that survives the node-key rotation a refusal triggers.
    #[test]
    fn machine_key_admits_a_device_whose_node_key_rotates() {
        let (_, mkey) = key(0x51);
        let membership = SharedMembership::new();
        membership.publish(&AnchoredMembers {
            root: Some("r".into()),
            node_keys: BTreeSet::new(),
            machine_keys: BTreeSet::from([mkey.clone()]),
        });
        // Three successive registration attempts, each with a fresh node
        // key: all admitted, because the machine key is the same device.
        for fill in [0x60u8, 0x61, 0x62] {
            let (_, rotated) = key(fill);
            assert_eq!(membership.admit(&rotated, &mkey), Ok(()));
        }
        // Same node keys, a different machine ⇒ refused.
        let (_, other) = key(0x52);
        assert_eq!(
            membership.admit(&key(0x60).1, &other),
            Err(NOT_A_MEMBER_REFUSAL.to_string())
        );
        // An absent identity never matches an empty set entry.
        assert_eq!(
            membership.admit("", ""),
            Err(NOT_A_MEMBER_REFUSAL.to_string())
        );
    }

    /// `from_members` reads both identities off the anchored set, and a
    /// machine-key-only member contributes no node key.
    #[test]
    fn from_members_collects_both_identities() {
        let (wg_b64, wg_hex) = key(0x71);
        let mkey = "ab".repeat(32);
        let members = TailnetMembers::new_v1(
            7,
            "00".repeat(32),
            vec![
                Member {
                    wallet: "octStock".into(),
                    wg_pubkey_b64: String::new(),
                    machine_key_hex: mkey.clone(),
                    joined_epoch: 1,
                },
                Member {
                    wallet: "octOctravpn".into(),
                    wg_pubkey_b64: wg_b64,
                    machine_key_hex: String::new(),
                    joined_epoch: 2,
                },
            ],
            0,
            0,
        );
        members.validate().expect("valid set");
        let anchored = AnchoredMembers::from_members(None, &members).unwrap();
        assert_eq!(anchored.node_keys, BTreeSet::from([wg_hex.clone()]));
        assert_eq!(anchored.machine_keys, BTreeSet::from([mkey.clone()]));
        assert_eq!(anchored.len(), 2);
        assert!(anchored.admits(&wg_hex, ""));
        assert!(anchored.admits("", &mkey));
        assert!(!anchored.admits(&key(0x72).1, ""));
    }

    /// The filter and the eviction pass both match a machine-key member, so
    /// a stock device is reachable and is not evicted the moment it joins.
    #[test]
    fn machine_key_members_are_rendered_and_kept() {
        let (_, node_hex) = key(0x81);
        let mkey = "cd".repeat(32);
        let mut rec = machine(&node_hex, Ipv4Addr::new(100, 64, 0, 21));
        rec.machine_key_hex = mkey.clone();
        let mut registered = HashMap::new();
        registered.insert(node_hex, rec);
        let anchored = AnchoredMembers {
            root: Some("r".into()),
            node_keys: BTreeSet::new(),
            machine_keys: BTreeSet::from([mkey]),
        };
        let rendered = render_policy("octCircle", &anchored, &registered).unwrap();
        assert_eq!(rendered.matched, 1, "matched by machine key");
        assert!(non_member_registrations(&registered, &anchored).is_empty());
    }

    #[test]
    fn non_member_registrations_is_case_insensitive_and_leaves_members_alone() {
        let (_, member_hex) = key(0x31);
        let (_, stranger_hex) = key(0x32);
        let mut registered = HashMap::new();
        // Registered under mixed case, as a client may send it.
        registered.insert(
            member_hex.to_ascii_uppercase(),
            machine(&member_hex, Ipv4Addr::new(100, 64, 0, 1)),
        );
        registered.insert(
            stranger_hex.clone(),
            machine(&stranger_hex, Ipv4Addr::new(100, 64, 0, 2)),
        );
        let anchored = AnchoredMembers {
            root: Some("r".into()),
            node_keys: BTreeSet::from([member_hex]),
            machine_keys: BTreeSet::new(),
        };
        assert_eq!(
            non_member_registrations(&registered, &anchored),
            vec![stranger_hex]
        );
        // Everyone a member ⇒ nothing to evict.
        let all = AnchoredMembers {
            root: Some("r".into()),
            node_keys: registered.keys().map(|k| k.to_ascii_lowercase()).collect(),
            machine_keys: BTreeSet::new(),
        };
        assert!(non_member_registrations(&registered, &all).is_empty());
    }

    /// Eviction drops the live registration *and* the durable row, so the
    /// device leaves every peer's netmap and cannot be hydrated back at the
    /// next restart.
    #[tokio::test]
    async fn evict_non_members_deletes_from_registry_and_durable_store() {
        #[derive(Default)]
        struct RecordingStore {
            deleted: parking_lot::Mutex<Vec<String>>,
        }
        #[async_trait]
        impl MachineRegistrationStore for RecordingStore {
            async fn create_or_update_auth_key_registration(
                &self,
                record: MachineRecord,
                _policy: &octravpn_mesh::policy::PolicyStore,
                _auth_key_id: Option<i64>,
            ) -> std::result::Result<
                octravpn_mesh::tailscale_wire::PersistedMachineRegistration,
                String,
            > {
                Ok(
                    octravpn_mesh::tailscale_wire::PersistedMachineRegistration {
                        record,
                        replaced_node_key_hex: None,
                    },
                )
            }
            async fn delete_machine_registration(
                &self,
                node_key_hex: &str,
            ) -> std::result::Result<(), String> {
                self.deleted.lock().push(node_key_hex.to_string());
                Ok(())
            }
        }

        let (_, member_hex) = key(0x41);
        let (_, stranger_hex) = key(0x42);
        let registry = MachineRegistry::new();
        registry.upsert(
            member_hex.clone(),
            machine(&member_hex, Ipv4Addr::new(100, 64, 0, 5)),
        );
        registry.upsert(
            stranger_hex.clone(),
            machine(&stranger_hex, Ipv4Addr::new(100, 64, 0, 6)),
        );
        let store: Arc<dyn MachineRegistrationStore> = Arc::new(RecordingStore::default());
        let anchored = AnchoredMembers {
            root: Some("r".into()),
            node_keys: BTreeSet::from([member_hex.clone()]),
            machine_keys: BTreeSet::new(),
        };

        let dropped = evict_non_members(&registry, Some(&store), &anchored).await;
        assert_eq!(dropped, 1);
        assert!(registry.get(&member_hex).is_some(), "the member stays");
        assert!(
            registry.get(&stranger_hex).is_none(),
            "the stranger is gone"
        );

        // Idempotent: a second pass finds nothing left to drop.
        assert_eq!(
            evict_non_members(&registry, Some(&store), &anchored).await,
            0
        );
    }

    /// `enforce_registration = false` keeps the packet-filter-only posture:
    /// no gate is installed, so any key may still register.
    #[test]
    fn registration_gate_is_absent_when_enforcement_is_off() {
        fn sync(enforce: bool) -> MembersPolicySync {
            MembersPolicySync {
                chain: ChainHandle::Owned(Arc::new(ChainCtxV3::new(
                    octravpn_core::rpc::RpcClient::new("http://127.0.0.1:1/"),
                    octravpn_core::address::Address::from_display("octCircle"),
                    octravpn_core::sig::KeyPair::from_secret_bytes(&[7u8; 32]),
                ))),
                circle_id: "octCircle".into(),
                creds: SealedAssetCreds::new("pass"),
                period: Duration::from_secs(10),
                membership: SharedMembership::new(),
                enforce_registration: enforce,
            }
        }
        assert!(sync(false).registration_gate().is_none());
        assert!(sync(true).registration_gate().is_some());
    }

    #[test]
    fn plan_follows_epoch_and_registry_generation() {
        let mut s = SyncState::default();
        // Boot: nothing loaded ⇒ fetch + render.
        assert_eq!(
            s.plan(Some(10), 1),
            Plan {
                fetch: true,
                render: true
            }
        );
        s.anchored = Some(AnchoredMembers::empty(None));
        s.applied_raw = Some("x".into());
        // Same epoch, same registry ⇒ idle.
        assert_eq!(
            s.plan(Some(10), 1),
            Plan {
                fetch: false,
                render: false
            }
        );
        // Registry moved ⇒ render only.
        assert_eq!(
            s.plan(Some(10), 2),
            Plan {
                fetch: false,
                render: true
            }
        );
        // Epoch moved ⇒ fetch + render.
        assert_eq!(
            s.plan(Some(11), 2),
            Plan {
                fetch: true,
                render: true
            }
        );
        // Epoch unreadable ⇒ re-read anyway.
        assert_eq!(
            s.plan(None, 2),
            Plan {
                fetch: true,
                render: true
            }
        );
        // Fetch that never verified keeps re-fetching each tick.
        s.anchored = None;
        assert_eq!(
            s.plan(Some(11), 2),
            Plan {
                fetch: true,
                render: true
            }
        );
    }
}
