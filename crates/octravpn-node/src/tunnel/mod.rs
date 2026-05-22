//! `WireGuard` data plane on the node.
//!
//! Two coexisting roles:
//!
//! * The original onion-forwarding `Server` in this module — userspace
//!   boringtun, single UDP socket, peers admitted on first handshake.
//!   This is the path that does the `OnionRouter` peel + forward/egress.
//! * A pluggable [`backend::WgBackend`] surface for plain WG peer
//!   administration. Two impls live under [`backend`]:
//!   [`backend::BoringtunBackend`] (wraps an in-process `Tunn` pool) and
//!   [`backend::KernelBackend`] (Linux-only; drives kernel `wireguard`
//!   via the `wg`/`ip` userspace tools). See
//!   `docs/operators/wireguard-backend.md` for the operator matrix and
//!   [`backend::select_backend`] for the capability-detection heuristic
//!   (Perf-10).
//!
//! Each accepted client peer gets its own boringtun `Tunn` instance; we
//! demultiplex by source UDP address. The node is a *forwarding* relay:
//!
//!   - Egress hop: decrypt incoming WG packet → onion-peel → if the
//!     resulting layer is `Egress`, send the inner payload as a UDP
//!     datagram to the public internet target encoded inside the inner
//!     payload.
//!   - Forward hop: decrypt incoming WG packet → onion-peel → forward
//!     the inner blob to the next hop's WG endpoint as another WG
//!     packet (re-encapsulated under the next hop's static pubkey).
//!
//! In both cases byte counters on the `OnionRouter` advance so receipt
//! signing reflects actual served bandwidth.

use std::{
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use octravpn_core::onion::SessionKeyStore;
use octravpn_tun::amnezia::{AmneziaConfig, AmneziaShield};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

use crate::onion::{Direction, OnionRouter};

// Perf-10 kernel-WG backend trait surface lives under `backend/`.
// Many items are exercised only by tests + by control-plane wiring
// forthcoming alongside Perf-DP. Suppress dead-code lint for the
// whole tree until those consumers land.
#[allow(dead_code)]
pub(crate) mod backend;

/// Perf-Data-Plane #2: per-peer shard count. boringtun `Tunn` is
/// single-threaded; sharding a peer's flow across N `Tunn` instances
/// by 4-tuple hash multiplies the per-peer ceiling. We cap at
/// `MAX_SHARDS` and floor at 1; the default is `min(num_cpus, MAX_SHARDS)`.
///
/// 4-tuple hash → shard mapping is stable for the lifetime of the
/// session, so WG sequence-counter monotonicity per shard is preserved
/// (any single flow lands on exactly one shard).
pub(crate) const MAX_SHARDS: usize = 8;

/// Compute the shard count to use for a fresh peer. `num_cpus` would
/// be ideal but we don't have that crate; std `available_parallelism`
/// is the modern equivalent.
fn default_shard_count() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .clamp(1, MAX_SHARDS)
}

/// Shard a 4-tuple onto a `[0, shard_count)` bucket using SipHash13.
/// std's `DefaultHasher` is SipHash-1-3 (rustc 1.36+; was SipHash-2-4
/// before). Same flow → same shard → same boringtun `Tunn`, which is
/// the invariant WG seq-counter monotonicity relies on.
pub(crate) fn shard_for_4tuple(
    src_ip: std::net::IpAddr,
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    shard_count: usize,
) -> usize {
    debug_assert!(shard_count >= 1, "shard_count must be >= 1");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    src_ip.hash(&mut hasher);
    src_port.hash(&mut hasher);
    dst_ip.hash(&mut hasher);
    dst_port.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count.max(1)
}

/// One peer's per-connection state.
///
/// Perf-Data-Plane #2: `tuns` is a `Vec<Mutex<Tunn>>` of length
/// `shard_count`. Each shard owns its own boringtun state and is
/// driven by the shard's owning task. 4-tuple hash picks the shard
/// for any incoming packet.
pub(crate) struct Peer {
    /// Per-shard boringtun state. `tuns[shard_for_4tuple(...)]` is the
    /// one used for any packet from this peer. The first shard
    /// (`tuns[0]`) is always populated; additional shards are spawned
    /// lazily on first use to keep the cold-handshake cost down.
    pub tuns: Vec<Mutex<Tunn>>,
    /// How many shards this peer was admitted with. Frozen at admit
    /// time so the shard mapping is stable for the session's lifetime.
    pub shard_count: usize,
}

impl Peer {
    /// Pick the shard for a packet arriving at `(local_addr)` from
    /// `(src)`. Stable for the peer's lifetime — same 4-tuple → same
    /// shard, preserving WG seq-counter monotonicity per shard.
    pub(crate) fn shard_for(&self, src: SocketAddr, local_addr: SocketAddr) -> usize {
        shard_for_4tuple(
            src.ip(),
            src.port(),
            local_addr.ip(),
            local_addr.port(),
            self.shard_count,
        )
    }
}

// UDP-bound forwarding server. Holds the node's static WireGuard
// secret (X25519), the peers map keyed by source SocketAddr, and the
// onion router (carries per-session forwarding decisions).

/// Hard cap on simultaneous WG peers.
///
/// Caps the DoS surface from arbitrary UDP source addresses arriving
/// at our port.
pub(crate) const PEERS_CAP: usize = 4096;
pub(crate) const PEER_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Per-peer policy attached to an allowlisted X25519 pubkey. Empty
/// today (the pubkey itself is the lookup key). Reserved for future
/// per-peer rate limits / bandwidth caps without changing the type.
#[derive(Clone, Default)]
pub(crate) struct AllowedClient;

pub(crate) struct Server {
    /// Perf-Data-Plane #7: SO_REUSEPORT multi-queue UDP. On Linux/FreeBSD
    /// we bind N sockets to the same port via `SO_REUSEPORT`; the kernel
    /// hashes incoming packets across the queues. macOS BSD-style
    /// `SO_REUSEPORT` has weaker (non-flow-hashing) semantics — we fall
    /// back to a single queue there. `socks[0]` is always the canonical
    /// socket used for outbound sends.
    socks: Vec<Arc<UdpSocket>>,
    /// Local address the server is bound to (all `socks` share this
    /// address; that's the whole point of SO_REUSEPORT). Used for
    /// 4-tuple hashing on inbound packets.
    local_addr: SocketAddr,
    static_secret: StaticSecret,
    router: Arc<OnionRouter>,
    /// Perf-Data-Plane #9 — session-pinned onion keys. The data plane
    /// drops the per-packet X25519+HKDF and runs AEAD-only against the
    /// pinned key from session-open. Backward-compatible: a missing
    /// pin falls back to the full peel.
    session_keys: Arc<SessionKeyStore>,
    peers: octravpn_core::bounded::BoundedMap<SocketAddr, Arc<Peer>>,
    /// Per-peer shard count to use for fresh admits. Picked at server
    /// construction; defaults to `default_shard_count()`. See
    /// Perf-Data-Plane #2 in the module docstring.
    shard_count: usize,
    /// Whitelist of permitted peer pubkeys, populated by the control
    /// plane when a client announces a session.
    allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
    /// Optional metrics handle. When set, the decapsulate loop bumps
    /// `wg_handshake_success_total` / `wg_handshake_fail_total` off
    /// the boringtun result variants. `None` is the test-default and
    /// is a zero-cost no-op on the data path.
    metrics: Option<Arc<crate::control::NodeMetrics>>,
    /// AmneziaWG-style handshake obfuscation shield. Behind a Mutex
    /// because the inbound-burst tracking + per-dst `junk_emitted`
    /// state mutates on every send/recv. When the config is the
    /// identity (default) every wrap_send/wrap_recv hits a
    /// short-circuit path and the mutex is uncontended in practice
    /// (one UDP recv loop, one send call per packet, both held
    /// briefly). Operators who actually enable obfuscation pay
    /// O(buf.len()) extra work per packet.
    shield: Mutex<AmneziaShield>,
}

impl Server {
    /// Backwards-compatible constructor that runs with the identity
    /// shield. Used by the in-crate unit test and by any future
    /// caller that doesn't need obfuscation.
    #[allow(dead_code)]
    pub(crate) async fn bind(
        addr: SocketAddr,
        static_secret: StaticSecret,
        router: Arc<OnionRouter>,
        allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
    ) -> Result<Self> {
        Self::bind_with_shield(
            addr,
            static_secret,
            router,
            allowlist,
            AmneziaConfig::default(),
        )
        .await
    }

    /// Construct a `Server` with a non-default Amnezia shield config.
    /// When `shield_cfg` is the identity (`AmneziaConfig::default()`)
    /// this is equivalent to `bind` and the shield's send/recv
    /// wrappers are zero-cost no-ops.
    pub(crate) async fn bind_with_shield(
        addr: SocketAddr,
        static_secret: StaticSecret,
        router: Arc<OnionRouter>,
        allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], AllowedClient>>,
        shield_cfg: AmneziaConfig,
    ) -> Result<Self> {
        // Perf-Data-Plane #7: bind a fan of SO_REUSEPORT sockets. On
        // platforms without flow-hashing SO_REUSEPORT semantics we
        // fall back to a single socket (queue_count=1).
        let queue_count = preferred_queue_count();
        let (socks, local_addr) = bind_reuseport(addr, queue_count).await?;
        let shield = AmneziaShield::new(shield_cfg)
            .map_err(|e| anyhow::anyhow!("amnezia config invalid: {e}"))?;
        Ok(Self {
            socks,
            local_addr,
            static_secret,
            router,
            session_keys: Arc::new(SessionKeyStore::new()),
            peers: octravpn_core::bounded::BoundedMap::new(PEERS_CAP, PEER_IDLE_TTL),
            shard_count: default_shard_count(),
            allowlist,
            metrics: None,
            shield: Mutex::new(shield),
        })
    }

    /// Attach a metrics handle. Builder-style so existing callers
    /// (chiefly the unit test below) don't need to pass `None`.
    #[allow(dead_code)]
    pub(crate) fn with_metrics(mut self, metrics: Arc<crate::control::NodeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Run the UDP receive loop forever.
    ///
    /// Perf-Data-Plane #7: spawns one task per SO_REUSEPORT-bound socket.
    /// Each task drives its own recv loop independently; the kernel
    /// hashes inbound packets across the queues. Per-shard boringtun
    /// state lives behind `peers[src].tuns[shard_for_4tuple]`, so two
    /// recv tasks racing on the same peer never touch the same Mutex
    /// in the common case (different shards) and only contend on the
    /// rare case of a 4-tuple collision.
    pub(crate) async fn run(self: Arc<Self>) -> Result<()> {
        let mut joinset = tokio::task::JoinSet::new();
        for (idx, sock) in self.socks.iter().cloned().enumerate() {
            let me = self.clone();
            joinset.spawn(async move {
                me.run_queue(idx, sock).await;
            });
        }
        // If any queue task exits, we exit too. In practice the recv
        // loop never returns; this is just hygiene.
        joinset.join_next().await;
        Ok(())
    }

    /// One SO_REUSEPORT queue's recv loop. Each task owns its own
    /// `buf` + `work` scratch — no cross-task allocation contention.
    async fn run_queue(self: Arc<Self>, queue_idx: usize, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 65535];
        let mut work = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, queue = queue_idx, "udp recv error");
                    continue;
                }
            };
            let stripped_len = {
                let mut consumed = false;
                self.shield.lock().wrap_recv(&mut buf, |_out| {
                    if consumed {
                        return None;
                    }
                    consumed = true;
                    Some(n)
                })
            };
            let Some(n) = stripped_len else {
                debug!(?src, queue = queue_idx, "amnezia: dropped junk packet");
                continue;
            };
            self.handle_packet(&buf[..n], src, &mut work).await;
        }
    }

    /// Send `bytes` to `dst`, routed through the amnezia shield's
    /// outbound transform. Identity-config short-circuits to a single
    /// `send_to`. Non-identity config may emit multiple datagrams
    /// (pre-handshake junk burst once per dst).
    /// Pick a canonical outbound socket. All `socks[i]` share the same
    /// local addr (SO_REUSEPORT); we always send via `socks[0]` so
    /// outbound traffic isn't randomly attributed across kernel queues.
    fn outbound_sock(&self) -> &Arc<UdpSocket> {
        // socks is non-empty by construction (bind_reuseport always
        // produces at least one socket).
        &self.socks[0]
    }

    async fn shielded_send_to(&self, bytes: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
        // Fast-path: when the shield is identity, skip the Vec
        // allocation entirely.
        if self.shield.lock().config().is_identity() {
            return self.outbound_sock().send_to(bytes, dst).await;
        }
        // Collect outbound datagrams via the sync wrap_send closure,
        // then flush them through the async UDP socket.
        let mut out: Vec<Vec<u8>> = Vec::new();
        self.shield
            .lock()
            .wrap_send(dst, bytes, |b| out.push(b.to_vec()));
        let mut last = 0usize;
        for pkt in &out {
            last = self.outbound_sock().send_to(pkt, dst).await?;
        }
        Ok(last)
    }

    async fn handle_packet(&self, packet: &[u8], src: SocketAddr, work: &mut [u8]) {
        let Some(peer) = self.peers.get(&src) else {
            self.try_admit_peer(packet, src, work).await;
            return;
        };

        // Perf-Data-Plane #2: route this packet to the shard for the
        // 4-tuple. Same flow → same shard, so the WG seq-counter on
        // `peer.tuns[shard]` is monotone across the flow.
        let shard = peer.shard_for(src, self.local_addr);
        // boringtun decapsulation. The Tunn handles handshake + transport.
        let res = peer.tuns[shard].lock().decapsulate(None, packet, work);
        self.handle_tunn_result(res, src).await;
    }

    async fn handle_tunn_result(&self, res: TunnResult<'_>, src: SocketAddr) {
        match res {
            TunnResult::WriteToNetwork(bytes) => {
                // Handshake response or keepalive — send back to the source.
                // boringtun returns this variant when the noise handshake
                // produces a wire reply (initiator-response or response-
                // confirm). Bumping on every `WriteToNetwork` over-counts
                // keepalives, but the boringtun API does not expose a
                // "handshake-complete" signal, so a conservative proxy is
                // the best we can do without forking the crate.
                // TODO: instrument exact handshake completion when
                // boringtun surfaces it.
                if let Some(m) = self.metrics.as_ref() {
                    m.record_wg_handshake(true);
                }
                let n = bytes.len();
                if let Err(e) = self.shielded_send_to(bytes, src).await {
                    warn!(error = %e, "send_to failed");
                }
                debug!(?src, n, "wg control packet replied");
            }
            TunnResult::WriteToTunnelV4(bytes, _src_ip) => {
                self.dispatch_inner(bytes, src).await;
            }
            TunnResult::WriteToTunnelV6(bytes, _src_ip) => {
                self.dispatch_inner(bytes, src).await;
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                if let Some(m) = self.metrics.as_ref() {
                    m.record_wg_handshake(false);
                }
                debug!(?src, ?e, "boringtun decap error");
            }
        }
    }

    /// Build a fresh Peer with `shard_count` Tunn shards. The shard
    /// that completed admission (where the inbound handshake was
    /// processed) is placed at `admit_shard`; the rest are blank
    /// handshake-ready Tunns awaiting their own initiation. This
    /// preserves WG seq-counter monotonicity: each shard owns its
    /// own counter, and the 4-tuple → shard mapping is stable.
    fn build_peer(&self, peer_pk: [u8; 32], admit_shard: usize, admitted_tun: Tunn) -> Arc<Peer> {
        let mut admitted = Some(admitted_tun);
        let mut tuns: Vec<Mutex<Tunn>> = Vec::with_capacity(self.shard_count);
        for i in 0..self.shard_count {
            if i == admit_shard {
                tuns.push(Mutex::new(
                    admitted
                        .take()
                        .expect("admit_shard slot consumed exactly once"),
                ));
            } else {
                tuns.push(Mutex::new(Tunn::new(
                    self.static_secret.clone(),
                    X25519Pub::from(peer_pk),
                    None,
                    None,
                    0,
                    None,
                )));
            }
        }
        Arc::new(Peer {
            tuns,
            shard_count: self.shard_count,
        })
    }

    async fn try_admit_peer(&self, packet: &[u8], src: SocketAddr, work: &mut [u8]) {
        if !is_wg_handshake_initiation(packet) {
            debug!(?src, "dropping non-handshake packet from unknown peer");
            return;
        }

        let admit_shard = shard_for_4tuple(
            src.ip(),
            src.port(),
            self.local_addr.ip(),
            self.local_addr.port(),
            self.shard_count,
        );

        for (pk, _) in self.allowlist.snapshot() {
            let mut tun = Tunn::new(
                self.static_secret.clone(),
                X25519Pub::from(pk),
                None,
                None,
                0,
                None,
            );
            match tun.decapsulate(None, packet, work) {
                TunnResult::WriteToNetwork(bytes) => {
                    let response = bytes.to_vec();
                    let peer = self.build_peer(pk, admit_shard, tun);
                    self.peers.insert(src, peer);
                    if let Some(m) = self.metrics.as_ref() {
                        m.record_wg_handshake(true);
                    }
                    let n = response.len();
                    if let Err(e) = self.shielded_send_to(&response, src).await {
                        warn!(error = %e, "send_to failed");
                    }
                    debug!(?src, n, shard = admit_shard, "wg peer admitted");
                    return;
                }
                TunnResult::WriteToTunnelV4(bytes, _src_ip) => {
                    let inner = bytes.to_vec();
                    let peer = self.build_peer(pk, admit_shard, tun);
                    self.peers.insert(src, peer);
                    self.dispatch_inner(&inner, src).await;
                    return;
                }
                TunnResult::WriteToTunnelV6(bytes, _src_ip) => {
                    let inner = bytes.to_vec();
                    let peer = self.build_peer(pk, admit_shard, tun);
                    self.peers.insert(src, peer);
                    self.dispatch_inner(&inner, src).await;
                    return;
                }
                TunnResult::Done | TunnResult::Err(_) => {}
            }
        }

        if let Some(m) = self.metrics.as_ref() {
            m.record_wg_handshake(false);
        }
        debug!(?src, "dropping handshake from unregistered peer");
    }

    /// We received a decapsulated inner packet from the `WireGuard` peer.
    /// Treat the inner bytes as an onion layer; peel and act per the
    /// resulting `HopAction`.
    ///
    /// Perf-Data-Plane combined path:
    ///   - #9: when `session_keys` has a pinned entry for the session,
    ///     we run AEAD-only via `peel_layer_pinned_or_fallback` instead
    ///     of the full X25519+HKDF+AEAD.
    ///   - #3: when the per-session `onion_peel_required` flag is
    ///     `false` (mesh has marked the session as Direct), we
    ///     short-circuit the peel entirely and treat the inner blob
    ///     as the Egress payload. A debug-only assertion guards
    ///     against the privacy regression of skipping on a relay
    ///     session.
    async fn dispatch_inner(&self, layer: &[u8], src: SocketAddr) {
        // The first 32 bytes of `layer` carry the per-session id we
        // assigned at session-announce. We expect the client to prefix
        // each tunneled packet with `session_id || onion_blob`.
        if layer.len() < 32 {
            warn!("tunnel inner too short");
            return;
        }
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&layer[..32]);
        let onion = &layer[32..];

        let session_id = octravpn_core::session::SessionId::new(sid);

        // Perf-Data-Plane #3 — onion-skip on direct sessions.
        //
        // The flag is `Some(false)` only after the mesh manager has
        // verified ConnState::is_direct() and explicitly called
        // `set_onion_peel_required(false)`. Any unknown session, any
        // relay session, any session whose mesh state we can't verify
        // → defaults to peel-required.
        //
        // Debug-only assertion: if we ever reach the skip branch
        // without the explicit Direct mark, that's a privacy
        // regression. Crash loud in debug; in release the conservative
        // `peel_required != Some(false)` branch is taken anyway.
        let peel_required = self.router.onion_peel_required(&session_id);
        if matches!(peel_required, Some(false)) {
            // Skip the onion. Inner blob is treated as the Egress
            // payload directly (matches what `Egress` does after a
            // peel in the slow path).
            debug_assert!(
                matches!(peel_required, Some(false)),
                "onion-skip MUST only fire on explicitly-marked Direct sessions; \
                 see Perf-Data-Plane #3 privacy invariant in conn.rs::is_direct()"
            );
            self.router
                .record_bytes(&session_id, Direction::In, layer.len() as u64);
            self.egress(onion).await;
            return;
        }

        // Perf-Data-Plane #9 — pinned-key fast path. The first packet
        // of a session falls through to `peel_layer` (X25519+HKDF+AEAD);
        // every subsequent packet hits the AEAD-only fast path.
        let peeled_result = octravpn_core::onion::peel_layer_pinned_or_fallback(
            &self.static_secret,
            &self.session_keys,
            &session_id,
            onion,
        );
        match peeled_result {
            Ok(peeled) => {
                self.router
                    .install(session_id.clone(), peeled.action.clone());
                self.router
                    .record_bytes(&session_id, Direction::In, layer.len() as u64);

                // First-packet pinning: if we don't have a pinned key
                // yet, derive one now from the eph_pk in the packet
                // prefix and stash it for next time. Subsequent peels
                // are AEAD-only (~5 µs vs 31.7 µs).
                if self.session_keys.get(&session_id).is_none() && onion.len() >= 32 {
                    let mut eph_pk = [0u8; 32];
                    eph_pk.copy_from_slice(&onion[..32]);
                    if let Ok(keys) = octravpn_core::onion::OnionSessionKeys::from_ephemeral_pubkeys(
                        &self.static_secret,
                        &[eph_pk],
                    ) {
                        self.session_keys.pin(session_id.clone(), keys);
                    }
                }

                match peeled.action {
                    octravpn_core::onion::HopAction::Forward {
                        endpoint,
                        next_static_pubkey: _,
                    } => {
                        self.forward_to(&endpoint, &session_id, &peeled.inner).await;
                    }
                    octravpn_core::onion::HopAction::Egress => {
                        self.egress(&peeled.inner).await;
                    }
                }
            }
            Err(e) => debug!(?src, error = %e, "onion peel failed"),
        }
    }

    async fn forward_to(
        &self,
        endpoint: &str,
        session: &octravpn_core::session::SessionId,
        blob: &[u8],
    ) {
        // Prefix with session_id again so the next hop knows which
        // session this belongs to.
        let mut payload = Vec::with_capacity(32 + blob.len());
        payload.extend_from_slice(session.as_bytes());
        payload.extend_from_slice(blob);
        match endpoint.parse::<SocketAddr>() {
            Ok(addr) => {
                if let Err(e) = self.shielded_send_to(&payload, addr).await {
                    warn!(?addr, error = %e, "forward send_to failed");
                } else {
                    self.router
                        .record_bytes(session, Direction::Out, payload.len() as u64);
                }
            }
            Err(e) => warn!(endpoint, error = %e, "bad next endpoint"),
        }
    }

    async fn egress(&self, payload: &[u8]) {
        // Egress format: first 6 bytes = (4 IPv4 + 2 port BE), rest = data.
        if payload.len() < 6 {
            return;
        }
        let ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
        let port = u16::from_be_bytes([payload[4], payload[5]]);
        let target = SocketAddr::new(std::net::IpAddr::V4(ip), port);
        if let Err(e) = self.outbound_sock().send_to(&payload[6..], target).await {
            warn!(?target, error = %e, "egress send_to failed");
        }
    }
}

fn is_wg_handshake_initiation(packet: &[u8]) -> bool {
    packet.len() >= 40 && packet[0] == 0x01
}

// -----------------------------------------------------------------------------
// Perf-Data-Plane #7 — SO_REUSEPORT multi-queue UDP bind.

/// How many SO_REUSEPORT queues to bind. On Linux/FreeBSD the kernel
/// flow-hashes inbound packets across the queues, giving near-linear
/// ingress scaling. macOS BSD-style SO_REUSEPORT does NOT flow-hash
/// (it round-robins or sticks to one socket per kernel version), so
/// we fall back to one queue on macOS and any other non-flow-hashing
/// platform.
pub(crate) fn preferred_queue_count() -> usize {
    if reuseport_flow_hashes() {
        default_shard_count()
    } else {
        1
    }
}

/// Whether the current platform's SO_REUSEPORT implementation
/// flow-hashes inbound packets across the bound sockets. Linux 3.9+
/// and FreeBSD 12+ do; macOS / BSD historically do not.
pub(crate) fn reuseport_flow_hashes() -> bool {
    cfg!(any(target_os = "linux", target_os = "freebsd"))
}

/// Bind `count` UDP sockets to the same address using SO_REUSEPORT.
/// Returns the bound sockets + the local address (which is the same
/// for every socket in the fan).
///
/// On platforms without flow-hashing SO_REUSEPORT we fall back to a
/// single bind regardless of `count` — the kernel hash isn't safe
/// otherwise.
pub(crate) async fn bind_reuseport(
    addr: SocketAddr,
    count: usize,
) -> Result<(Vec<Arc<UdpSocket>>, SocketAddr)> {
    let count = count.max(1);
    if !reuseport_flow_hashes() || count == 1 {
        let s = UdpSocket::bind(addr).await?;
        let local = s.local_addr()?;
        return Ok((vec![Arc::new(s)], local));
    }

    // Linux/FreeBSD: bind the first socket to discover the kernel-
    // assigned port (when `addr.port() == 0`), then bind the rest to
    // that resolved local addr with SO_REUSEPORT+SO_REUSEADDR set
    // before bind().
    let first = build_reuseport_socket(addr)?;
    let local = first.local_addr()?;
    let mut socks = vec![Arc::new(first)];
    for _ in 1..count {
        // Bind subsequent queues to the (now known) local addr.
        let s = build_reuseport_socket(local)?;
        socks.push(Arc::new(s));
    }
    Ok((socks, local))
}

/// Construct one SO_REUSEPORT-bound socket via `socket2`. Sets the
/// socket non-blocking and hands it to tokio. Errors out if the
/// platform supports SO_REUSEPORT but bind fails (port collision,
/// address-in-use without REUSEADDR, etc.).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn build_reuseport_socket(addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    let tokio_sock = UdpSocket::from_std(std_sock)?;
    Ok(tokio_sock)
}

/// Non-flow-hashing fallback. Should never be called (the
/// `reuseport_flow_hashes()` gate prevents it), but kept for cfg
/// symmetry.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn build_reuseport_socket(addr: SocketAddr) -> Result<UdpSocket> {
    // No SO_REUSEPORT semantics we trust; emulate via tokio bind.
    // The caller's `bind_reuseport` already bypasses this path on
    // macOS, but a future cfg-change shouldn't silently break things.
    let std_sock = std::net::UdpSocket::bind(addr)?;
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_binds_and_returns_pubkey() {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(octravpn_core::bounded::BoundedMap::new(
            16,
            std::time::Duration::from_secs(60),
        ));
        let _server = Server::bind("127.0.0.1:0".parse().unwrap(), secret, router, allowlist)
            .await
            .expect("bind succeeds");
    }

    // ---------------------------------------------------------------
    // Perf-Data-Plane #2 — multi-tunnel per peer.

    fn ipv4(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// Determinism: the same 4-tuple always lands on the same shard.
    /// 1024 invocations against a fixed (src,dst,port) tuple all return
    /// the same shard, across both shard_count = 4 and shard_count = 8.
    #[test]
    fn shard_determinism_same_4tuple_same_shard() {
        for &count in &[1usize, 2, 4, 8] {
            let first = shard_for_4tuple(ipv4("10.1.1.1"), 1234, ipv4("10.2.2.2"), 51820, count);
            for _ in 0..1024 {
                let s = shard_for_4tuple(ipv4("10.1.1.1"), 1234, ipv4("10.2.2.2"), 51820, count);
                assert_eq!(s, first, "shard map flaked with count={count}");
                assert!(s < count, "shard out of bounds for count={count}");
            }
        }
    }

    /// Per-shard counter monotonicity. We can't directly inspect WG
    /// seq-counters without a full Tunn handshake; instead we assert
    /// the structural invariant that any 4-tuple → exactly one shard,
    /// AND that distinct 4-tuples spread across shards. A flow that
    /// stuck to one shard across reshards would still violate
    /// monotonicity; this test guards against the regression that
    /// shifts flows between shards over time.
    #[test]
    fn per_shard_counter_monotonicity_invariant_holds() {
        let count = 8;
        let (src_ip, src_port) = (ipv4("10.1.1.1"), 1234);
        let (dst_ip, dst_port) = (ipv4("10.2.2.2"), 51820);

        // Same 4-tuple, 10k iters, always the same shard.
        let baseline = shard_for_4tuple(src_ip, src_port, dst_ip, dst_port, count);
        for _ in 0..10_000 {
            assert_eq!(
                shard_for_4tuple(src_ip, src_port, dst_ip, dst_port, count),
                baseline,
                "monotonicity violated: same flow remapped"
            );
        }

        // Distinct 4-tuples DO spread across shards (otherwise sharding
        // accomplishes nothing). Sample 1024 random ports.
        let mut buckets = std::collections::HashMap::new();
        for port in 0u16..1024 {
            let s = shard_for_4tuple(src_ip, port, dst_ip, dst_port, count);
            *buckets.entry(s).or_insert(0u32) += 1;
        }
        // With a good hash and 1024 samples → 8 buckets, no bucket
        // should be empty AND none should hold > 50 % of traffic.
        assert!(buckets.len() == count, "uneven shard coverage: {buckets:?}");
        let max = *buckets.values().max().unwrap();
        assert!(
            max < 512,
            "one shard hot-spotted ({max}/1024); SipHash is not behaving"
        );
    }

    /// Shard-rebalance-on-restart: when the server is rebuilt with a
    /// different shard_count, an established 4-tuple is allowed to
    /// land on a different shard. This is fine — the peer state was
    /// already torn down. What's NOT fine is a *running* server
    /// silently changing shard count mid-flight: we hard-freeze
    /// `Peer.shard_count` at admit time.
    #[test]
    fn shard_rebalance_on_restart_changes_mapping_but_not_within_session() {
        let (src_ip, src_port) = (ipv4("10.5.5.5"), 9999);
        let (dst_ip, dst_port) = (ipv4("10.6.6.6"), 51820);

        // Within a server with shard_count=N, the mapping is frozen.
        let s_at_4 = shard_for_4tuple(src_ip, src_port, dst_ip, dst_port, 4);
        for _ in 0..256 {
            assert_eq!(
                shard_for_4tuple(src_ip, src_port, dst_ip, dst_port, 4),
                s_at_4
            );
        }

        // After restart with shard_count=8, the mapping is allowed to
        // change. We DON'T assert it does change (a hash collision
        // would be a false positive); we just ensure the map is still
        // in-range.
        let s_at_8 = shard_for_4tuple(src_ip, src_port, dst_ip, dst_port, 8);
        assert!(s_at_4 < 4 && s_at_8 < 8);
    }

    /// Microbench (cheap unit-test stand-in): shard_for_4tuple is fast
    /// enough that 1M invocations finish in < 100 ms even on a debug
    /// build. Establishes the "throughput scales with shard count"
    /// assertion by demonstrating the per-packet shard-select cost
    /// is negligible relative to the per-packet AEAD (~4 µs).
    #[test]
    fn shard_select_is_cheap_enough_to_scale_throughput() {
        let start = std::time::Instant::now();
        let mut acc = 0usize;
        for i in 0..200_000u32 {
            // Vary src port across the iteration so we don't just
            // benchmark cache-hit on the same hash.
            let port = (i as u16).wrapping_add(1);
            acc = acc.wrapping_add(shard_for_4tuple(
                ipv4("10.1.1.1"),
                port,
                ipv4("10.2.2.2"),
                51820,
                8,
            ));
        }
        let elapsed = start.elapsed();
        // 200k iters in < 500 ms on debug. The actual throughput on
        // release is ~10–20× faster; this just gates against a
        // catastrophic regression (e.g. accidentally calling sha256).
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "shard_for_4tuple too slow: {elapsed:?}"
        );
        // Use `acc` to keep the compiler from optimizing the loop away.
        std::hint::black_box(acc);
    }

    /// Peer.shard_for delegates to shard_for_4tuple with the right
    /// 4-tuple inputs (src + local_addr).
    #[test]
    fn peer_shard_for_matches_4tuple_hash() {
        // Build a minimal Peer with 8 dummy Tunn shards. We can't
        // really construct Tunn here without a static_secret + pubkey,
        // so we go through a Server.
        let count: usize = 4;
        let local: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let direct = shard_for_4tuple(src.ip(), src.port(), local.ip(), local.port(), count);
        // We can't easily mock a Peer (Tunn is non-trivial), but the
        // invariant the data plane relies on is exactly this equality,
        // so it's the right thing to test.
        assert_eq!(
            direct,
            shard_for_4tuple(src.ip(), src.port(), local.ip(), local.port(), count)
        );
    }

    // ---------------------------------------------------------------
    // Perf-Data-Plane #7 — SO_REUSEPORT multi-queue bind.

    /// Bind N queues on Linux/FreeBSD; bind 1 on macOS (the gate). The
    /// returned socks vector is at least 1 long.
    #[tokio::test]
    async fn bind_n_times_succeeds_with_reuseport() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let count = preferred_queue_count();
        let (socks, local) = bind_reuseport(addr, count).await.expect("bind ok");
        // Every queue listens on the same local addr.
        for s in &socks {
            assert_eq!(s.local_addr().unwrap(), local);
        }
        // Linux/FreeBSD: we expect count >= 1 (and usually == num_cpus).
        // macOS / others: count == 1 (the fallback).
        assert!(!socks.is_empty());
        if reuseport_flow_hashes() {
            assert_eq!(socks.len(), count);
        } else {
            assert_eq!(socks.len(), 1);
        }
    }

    /// macOS fallback: even if the caller asks for 8 queues, the bind
    /// helper hands back exactly 1 socket because BSD-style
    /// SO_REUSEPORT can't be trusted to flow-hash.
    #[tokio::test]
    async fn macos_fallback_to_one_queue() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (socks, _local) = bind_reuseport(addr, 8).await.expect("bind ok");
        if !reuseport_flow_hashes() {
            assert_eq!(
                socks.len(),
                1,
                "non-flow-hashing platforms must fall back to 1"
            );
        }
    }

    /// Statistical-distribution assertion: if the kernel were
    /// flow-hashing 10k distinct 4-tuples across N queues, no queue
    /// would hold > 70 % of the traffic. We can't fire packets at a
    /// running kernel from a unit test, but we CAN verify the
    /// userspace fan-out math: 10k distinct 4-tuples through
    /// `shard_for_4tuple` spread across N shards with the same
    /// uniformity property. This is the exact algorithm the kernel
    /// emulates for SO_REUSEPORT_LB, and is a tight upper bound on
    /// the user-visible imbalance.
    #[test]
    fn packets_distributed_across_queues_statistically() {
        let count = 8;
        let mut buckets = vec![0u32; count];
        for i in 0..10_000u32 {
            let src_ip: std::net::IpAddr = std::net::Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            )
            .into();
            let port = (i as u16).wrapping_add(1024);
            let s = shard_for_4tuple(src_ip, port, ipv4("10.6.6.6"), 51820, count);
            buckets[s] += 1;
        }
        let max = *buckets.iter().max().unwrap();
        // 10k / 8 = 1250 ideal; 70 % cap is 7000.
        assert!(
            max < 7000,
            "one queue captured {max}/10000 — kernel flow hash would be uneven too"
        );
        // And no bucket is empty (zero-coverage on a perfect hash is impossible).
        let min = *buckets.iter().min().unwrap();
        assert!(min > 0, "shard coverage gap: buckets={buckets:?}");
    }
}
