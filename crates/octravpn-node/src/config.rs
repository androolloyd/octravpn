//! Node configuration loader.
//!
//! TOML schema:
//!
//!   [chain]
//!   rpc_url = "..."
//!   program_addr = "oct..."          # OctraVPN program address (v1.1 or v2)
//!   validator_addr = "oct..."        # this node's Octra wallet address
//!   wallet_secret_path = "/keys/..." # used to sign transactions
//!   protocol_version = "v1.1"        # "v1.1" (default), "v2", or "v3" —
//!                                    # selects which registration flow runs
//!                                    # at boot.
//!                                    # v2 deploys a Circle, uploads sealed
//!                                    # policy, and calls register_circle on
//!                                    # the slim v2 registry. See
//!                                    # docs/v2-operator-flow.md.
//!                                    # v3 talks to the chain-minimal
//!                                    # `program/main-v3.aml`: the operator
//!                                    # commits a 32-byte (64-char hex)
//!                                    # state-root anchor that points at a
//!                                    # circle-resident `state-root.json`,
//!                                    # along with an ed25519 receipt
//!                                    # pubkey. No HFHE; no sealed policy
//!                                    # blob lives on the registry. See
//!                                    # `docs/v3-state-root-schema.md` and
//!                                    # `program/main-v3.aml`.
//!   chain_id = 1869832804             # u32 network id bound into every
//!                                    # signed receipt (v1.2). Defaults to
//!                                    # CHAIN_ID_DEVNET (0x6F637464); pick a
//!                                    # distinct value for mainnet (see
//!                                    # `octravpn_core::receipt::CHAIN_ID_*`).
//!   # v2-only: per-tailnet passphrase used to derive AES-GCM read keys for
//!   # sealed assets stored inside the operator circle. Operators receive
//!   # this from their tailnet owner at provisioning. Optional in v1.1.
//!   sealed_passphrase = "..."        # OR (preferred) set OCTRAVPN_SEALED_PASSPHRASE
//!                                    # — env takes precedence over this field so ops
//!                                    # can override without editing the TOML.
//!   # v2-only: where to cache the predicted/deployed circle id so the
//!   # operator doesn't re-derive on every restart. Default
//!   # "./state/circle.toml".
//!   circle_state_path = "./state/circle.toml"
//!
//!   [tunnel]
//!   public_endpoint = "1.2.3.4:51820"
//!   listen = "0.0.0.0:51820"
//!   wg_secret_path = "/keys/wg.key"  # master from which WG + receipt keys derive
//!
//!   [pricing]
//!   price_per_mb = 100               # raw OU per MB (v1.1)
//!   region = "eu-west"
//!   # v2-only: separate tariffs per traffic class. Falls back to
//!   # `price_per_mb` when missing.
//!   price_per_mb_shared = 100        # what the chain stamps on shared sessions
//!   price_per_mb_internal = 0        # intra-tailnet (often free)
//!
//!   [control]
//!   listen = "127.0.0.1:51821"      # set 0.0.0.0 explicitly when exposing it
//!
//!   [attestation]
//!   poll_interval_secs = 30          # how often to recheck operator stake

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct NodeConfig {
    pub chain: ChainCfg,
    pub tunnel: TunnelCfg,
    pub pricing: PricingCfg,
    #[serde(default)]
    pub control: ControlCfg,
    #[serde(default)]
    pub attestation: AttestationCfg,
    /// Task #231 historical-analytics indexer. Optional — when absent
    /// (the default) the indexer is not spawned. Purely observational;
    /// the audit log + receipt journal remain authoritative.
    #[serde(default)]
    pub analytics: AnalyticsCfg,
    /// Optional UDP-transport-plugin selection. Defaults to a direct
    /// pass-through (no obfuscation), preserving the today-behaviour of
    /// every existing deployed node. Operators opt into obfs4 via
    /// `[tun.transport]` — see `docs/operators/obfs4-bridge.md`.
    #[serde(default)]
    pub tun: TunCfg,
    /// `[pvac]` block — managed `octra-pvac-sidecar` subprocess for the
    /// HFHE path. Default disabled; operators opt in by setting
    /// `[pvac].enabled = true` and (optionally) overriding
    /// `binary_path`. When enabled but the binary is missing, the node
    /// logs a warning and continues without HFHE — boot does NOT fail.
    /// See [`crate::pvac::PvacClient`] for the API and the supervisor
    /// contract.
    #[serde(default)]
    pub pvac: PvacCfg,
}

/// `[pvac]` block. Off-by-default so existing deployments are
/// unaffected by the wiring. To enable, drop a:
///
/// ```toml
/// [pvac]
/// enabled = true
/// binary_path = "./pvac-sidecar/octra-pvac-sidecar"
/// ```
///
/// into `node.toml`. The remaining fields tune the supervisor + IPC
/// timeouts.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PvacCfg {
    /// Master toggle. `false` (the default) ⇒ the subprocess is never
    /// spawned and `Hub::pvac()` returns `None`.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the `octra-pvac-sidecar` binary. Default
    /// `"./pvac-sidecar/octra-pvac-sidecar"` so the in-repo build
    /// "just works" on a fresh checkout that ran `cd pvac-sidecar &&
    /// make`. Production operators should point this at an absolute
    /// path under `/usr/local/bin` or similar.
    #[serde(default = "default_pvac_binary_path")]
    pub binary_path: String,
    /// Initial back-off after a sidecar crash, in milliseconds. The
    /// supervisor doubles per consecutive crash up to 60s. Default 250.
    #[serde(default = "default_pvac_restart_backoff_ms")]
    pub restart_backoff_ms: u64,
    /// Per-request timeout in seconds. Returned as
    /// `PvacError::Timeout` if no response arrives. Default 30.
    #[serde(default = "default_pvac_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

impl Default for PvacCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            binary_path: default_pvac_binary_path(),
            restart_backoff_ms: default_pvac_restart_backoff_ms(),
            request_timeout_secs: default_pvac_request_timeout_secs(),
        }
    }
}

fn default_pvac_binary_path() -> String {
    "./pvac-sidecar/octra-pvac-sidecar".into()
}

const fn default_pvac_restart_backoff_ms() -> u64 {
    250
}

const fn default_pvac_request_timeout_secs() -> u64 {
    30
}

impl PvacCfg {
    /// Render to the runtime [`crate::pvac::PvacConfig`] used by
    /// `PvacClient::spawn`.
    pub(crate) fn to_runtime(&self) -> crate::pvac::PvacConfig {
        crate::pvac::PvacConfig {
            binary_path: std::path::PathBuf::from(&self.binary_path),
            restart_backoff: std::time::Duration::from_millis(self.restart_backoff_ms),
            request_timeout: std::time::Duration::from_secs(self.request_timeout_secs),
            env: Vec::new(),
        }
    }
}

/// `[tun]` block. Currently only carries the [`TransportCfg`] selector.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct TunCfg {
    /// `[tun.transport]` — see [`TransportCfg`].
    #[serde(default)]
    pub transport: TransportCfg,
}

/// `[tun.transport]` block. Pluggable-transport selector for the WG
/// data plane. Default is `direct` (pass-through UDP) to preserve
/// today-behaviour. `obfs4` wraps the WG datagram stream in
/// obfs4-modelled handshakes + framed ciphertext (see
/// `octravpn-obfs4`).
///
/// TOML example:
///
/// ```toml
/// [tun.transport]
/// kind = "obfs4"
///
/// [tun.transport.obfs4]
/// bridge_node_id  = "0102030405060708090a0b0c0d0e0f1011121314"
/// bridge_pubkey   = "abcd...ef"   # 64 hex chars
/// iat_mode        = 1             # 0 off, 1 uniform, 2 Pareto
/// ```
///
/// See `docs/operators/obfs4-bridge.md` for credential minting and
/// the operational runbook.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct TransportCfg {
    /// `"direct"` (default) or `"obfs4"`.
    #[serde(default)]
    pub kind: TransportKind,
    /// obfs4-specific parameters; required when `kind = "obfs4"`.
    #[serde(default)]
    pub obfs4: Option<Obfs4Cfg>,
}

/// Selector for the data-plane transport. `Direct` is the no-op
/// pass-through; `Obfs4` activates the obfs4-modelled wrapper.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TransportKind {
    /// Pass-through UDP. The default; preserves today-behaviour.
    #[default]
    Direct,
    /// obfs4-modelled wrapper. Activates `octravpn-obfs4`.
    Obfs4,
}

/// `[tun.transport.obfs4]` block. Required when `kind = "obfs4"`.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Obfs4Cfg {
    /// 20-byte bridge `node_id`, hex-encoded (40 hex chars).
    /// Distributed to authorised clients out of band. Required.
    pub bridge_node_id: String,
    /// 32-byte X25519 bridge identity pubkey, hex-encoded (64 hex
    /// chars). Public half of the long-term bridge keypair; the
    /// matching secret is held by the bridge operator. Required.
    pub bridge_pubkey: String,
    /// Bridge identity *secret*, hex-encoded (64 hex chars). Set only
    /// on the bridge node; clients leave this unset. The same secret
    /// must produce the configured `bridge_pubkey`; the bridge will
    /// refuse to handshake otherwise.
    #[serde(default)]
    pub bridge_identity_secret: Option<String>,
    /// IAT mode: 0 = off (default), 1 = uniform 0..25ms,
    /// 2 = Pareto-shaped 0..200ms. See `octravpn_obfs4::IatMode`.
    #[serde(default)]
    pub iat_mode: u8,
}

/// `[analytics]` block. Bearer-gated like `[control].metrics_token`:
/// the HTTP surface returns 503 unless `bearer_token` is set, so a
/// misconfigured operator gets a clear "endpoint disabled" rather
/// than an open Prometheus endpoint.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct AnalyticsCfg {
    /// Spawn the indexer in-process. Defaults to `false` so existing
    /// operators upgrade without surprise. Set `true` + supply
    /// `bearer_token` + `listen_addr` to enable.
    #[serde(default)]
    pub enabled: bool,
    /// HTTP listen for the indexer's `/metrics`, `/analytics/series`,
    /// `/analytics/health` endpoints. Defaults to `127.0.0.1:51823`
    /// — bound to loopback because the indexer is intended as an
    /// in-process side-car the local Prometheus scrapes.
    #[serde(default = "default_analytics_listen")]
    pub listen_addr: String,
    /// Bearer token gating `/metrics` and `/analytics/series`. `None`
    /// (the default) renders both endpoints 503 — set this for the
    /// indexer to serve. Pick a long random secret (≥32 bytes); the
    /// same value goes into your scrape config's
    /// `authorization.credentials` field.
    #[serde(default)]
    pub bearer_token: Option<String>,
}

fn default_analytics_listen() -> String {
    "127.0.0.1:51823".into()
}

/// Which on-chain program shape the operator is talking to.
///
/// `V1_1` is the existing operator-wallet-as-identity flow against
/// `program/main.aml`. `V2` is the Circle-native flow against
/// `program/main-v2.aml`: a circle is deployed, an encrypted policy
/// bundle is uploaded as a sealed asset, and `register_circle` is
/// called with `value = MIN_CIRCLE_STAKE` (atomic register+bond).
///
/// `V3` is the chain-minimal flow against `program/main-v3.aml`. The
/// circle's full policy / WG pubkey / region / member-count live in a
/// circle-resident `state-root.json`; only the 32-byte sha256 anchor of
/// that JSON (64-char hex) plus a base64 ed25519 receipt pubkey are
/// committed on chain via `register_circle(circle, state_root,
/// receipt_pubkey)`. v3 has no HFHE — settlement uses a sha256 hash
/// chain of `(prev_head || sha256(settle_blinding))`. See
/// `docs/v3-state-root-schema.md` and `crates/octravpn-core/src/v3_state_root.rs`.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProtocolVersion {
    #[serde(rename = "v1.1", alias = "v1")]
    V1_1,
    #[serde(rename = "v2")]
    V2,
    #[serde(rename = "v3")]
    V3,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::V1_1
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
    pub validator_addr: String,
    pub wallet_secret_path: String,
    /// Which AML program shape to talk to. Defaults to v1.1 so existing
    /// deployed operators keep working unchanged.
    #[serde(default)]
    pub protocol_version: ProtocolVersion,
    /// Network identifier bound into every signed receipt (v1.2 P1-5
    /// hardening). Operators on devnet leave this at the default
    /// (`CHAIN_ID_DEVNET`); mainnet operators set it to
    /// `CHAIN_ID_MAINNET` (a future config flag). Distinct chain ids
    /// prevent an attacker who mirrors a v1.1 program from devnet to
    /// mainnet from replaying receipts. See
    /// `octravpn_core::receipt::ReceiptContext` for the encoding.
    #[serde(default = "default_chain_id")]
    pub chain_id: u32,
    /// v2-only. Per-tailnet shared secret the operator gets at
    /// provisioning time; passed to `encrypt_sealed_bytes` as the
    /// passphrase for the AES-GCM read key.
    ///
    /// Precedence at resolve time (matches client `discover_v2`):
    ///   1. `OCTRAVPN_SEALED_PASSPHRASE` env var (preferred — ops can
    ///      override without editing TOML).
    ///   2. This field.
    ///
    /// Empty in both ⇒ error.
    #[serde(default)]
    pub sealed_passphrase: Option<String>,
    /// v2-only. Where to persist the predicted/deployed circle id so
    /// the operator doesn't re-derive on every restart. Defaults to
    /// `./state/circle.toml` next to the working directory.
    #[serde(default)]
    pub circle_state_path: Option<String>,
    /// Pin the TLS trust roots for `rpc_url` to these PEM bundle
    /// files. Defeats CA-compromise MITM on the chain endpoint
    /// (corporate proxy installing a rogue CA, malicious MDM,
    /// compromised public CA). Empty / unset → use the system trust
    /// store (default for back-compat). Each path must point at a
    /// PEM-encoded cert blob; bundle multiple certs (full chain to
    /// the issuer root) into one file. P0-2 from
    /// docs/v2-threat-model.md.
    #[serde(default)]
    pub pinned_root_paths: Option<Vec<String>>,
    /// v3-only. The `oct…` circle id this operator commits its
    /// `state-root.json` under. v3's `register_circle(circle,
    /// state_root, receipt_pubkey)` requires the circle address as
    /// input; unlike v2, v3 does not auto-derive it from a
    /// `deploy_circle` op_type at the same boot pass — operators
    /// pre-deploy (or reuse) their circle and configure the id here.
    /// Required when `protocol_version = "v3"`; ignored otherwise.
    #[serde(default)]
    pub circle_id: Option<String>,
    /// v3-only. Where to persist the v3 boot anchor + tx hashes so
    /// subsequent restarts can detect whether the circle is already
    /// registered without round-tripping the chain for every detail.
    /// Defaults to `./state/circle-v3.toml` next to the working
    /// directory.
    #[serde(default)]
    pub circle_v3_state_path: Option<String>,
    /// v3-only. Initial stake (in OU) submitted with the first
    /// `register_circle` call. Must clear the v3 program's
    /// `min_circle_stake` floor (default 100_000_000 OU). Defaults to
    /// `1_000_000_000` (mirrors v2's `MIN_CIRCLE_STAKE_DEFAULT`).
    #[serde(default)]
    pub v3_initial_stake: Option<u64>,
    /// P1-6 strict mode. When `true`, the operator daemon refuses to
    /// boot if any of the configured secret files
    /// (`wallet_secret_path`, `tunnel.wg_secret_path`) is plaintext on
    /// disk. The error message names the `octravpn-node seal-keys`
    /// subcommand. When `false` (the default, for back-compat with
    /// v1.1 / devnet harnesses), the daemon transparently reads either
    /// shape — sealed envelopes resolve via `OCTRAVPN_KEY_PASSPHRASE`
    /// and plaintext files are accepted as-is.
    #[serde(default)]
    pub require_sealed_keys: bool,
    /// v3-only. Optional URL pointing at a remote-attestation bundle
    /// the operator publishes for its host. When set, the URL is
    /// emitted in the operator's canonical `policy.json`
    /// (`OperatorPolicy::attestation_url`); when unset, the field is
    /// omitted from the canonical JSON (NOT serialised as `null`). The
    /// bundle's SHA-256 is committed separately via the state-root's
    /// `attestation_hash` once remote-attestation lands. Defaults to
    /// `None`; most devnet operators do not advertise attestation yet.
    #[serde(default)]
    pub attestation_url: Option<String>,
}

/// Default chain id when a config omits the field. Devnet today; will
/// flip to mainnet once the production v2 deploy lands. Operators must
/// override explicitly to opt into another network.
fn default_chain_id() -> u32 {
    octravpn_core::receipt::CHAIN_ID_DEVNET
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct TunnelCfg {
    pub public_endpoint: String,
    pub listen: String,
    pub wg_secret_path: String,
    /// Optional AmneziaWG-style obfuscation parameters. When omitted
    /// or `enabled = false`, the WG datapath runs unmodified
    /// (zero-overhead identity transform; stock-WG peers can still
    /// connect). When `enabled = true`, both peers MUST agree on
    /// every field of this block or the handshake will silently
    /// drop. See `docs/security/validator-hardening.md` § Layer 1.
    #[serde(default)]
    pub amnezia: AmneziaCfg,
}

/// `[tunnel.amnezia]` block. Maps 1:1 onto
/// `octravpn_tun::amnezia::AmneziaConfig` (the wire-layer struct);
/// kept separate here so the node config has a free `enabled`
/// toggle without forcing the wire-layer to carry one (the wire
/// layer's "disabled" state is just the identity config).
#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub(crate) struct AmneziaCfg {
    /// Master toggle. Defaults to `false` so existing deployments
    /// upgrade with zero change. Set to `true` and configure the
    /// other fields to actually obfuscate.
    #[serde(default)]
    pub enabled: bool,
    /// Pre-handshake junk packet count (0..=128).
    #[serde(default)]
    pub jc: u8,
    /// Junk packet min size (1..=1280).
    #[serde(default)]
    pub jmin: u16,
    /// Junk packet max size (1..=1280, >= jmin).
    #[serde(default)]
    pub jmax: u16,
    /// Random prefix bytes on outgoing handshake-init (0..=1280).
    #[serde(default)]
    pub s1: u16,
    /// Random prefix bytes on outgoing handshake-response (0..=1280).
    #[serde(default)]
    pub s2: u16,
    /// Replacement msg-type value for WG init (1 = stock, else 5..=2_147_483_647).
    #[serde(default = "amnezia_default_h1")]
    pub h1: u32,
    /// Replacement msg-type value for WG response (2 = stock, else 5..=2_147_483_647).
    #[serde(default = "amnezia_default_h2")]
    pub h2: u32,
    /// Replacement msg-type value for WG cookie (3 = stock, else 5..=2_147_483_647).
    #[serde(default = "amnezia_default_h3")]
    pub h3: u32,
    /// Replacement msg-type value for WG transport (4 = stock, else 5..=2_147_483_647).
    #[serde(default = "amnezia_default_h4")]
    pub h4: u32,
}

const fn amnezia_default_h1() -> u32 {
    1
}
const fn amnezia_default_h2() -> u32 {
    2
}
const fn amnezia_default_h3() -> u32 {
    3
}
const fn amnezia_default_h4() -> u32 {
    4
}

impl AmneziaCfg {
    /// Render to the wire-layer `AmneziaConfig`. When `enabled =
    /// false`, returns the identity config (so the shield is a
    /// zero-cost pass-through regardless of the other field values
    /// — defence in depth against config typos disabling the toggle
    /// but leaving stale h-values).
    pub(crate) fn to_wire(self) -> octravpn_tun::amnezia::AmneziaConfig {
        if !self.enabled {
            return octravpn_tun::amnezia::AmneziaConfig::default();
        }
        octravpn_tun::amnezia::AmneziaConfig {
            jc: self.jc,
            jmin: self.jmin,
            jmax: self.jmax,
            s1: self.s1,
            s2: self.s2,
            h1: self.h1,
            h2: self.h2,
            h3: self.h3,
            h4: self.h4,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PricingCfg {
    pub price_per_mb: u64,
    pub region: String,
    /// v2-only. Shared (public-internet exit) tariff. Falls back to
    /// `price_per_mb` if missing so v1 configs still parse.
    #[serde(default)]
    pub price_per_mb_shared: Option<u64>,
    /// v2-only. Internal (intra-tailnet) tariff. Default 0 — most
    /// tailnets don't bill internal traffic.
    #[serde(default)]
    pub price_per_mb_internal: Option<u64>,
}

impl PricingCfg {
    /// v2 shared tariff. Defaults to `price_per_mb` for back-compat.
    pub(crate) fn shared_price(&self) -> u64 {
        self.price_per_mb_shared.unwrap_or(self.price_per_mb)
    }

    /// v2 internal tariff. Defaults to 0 (intra-tailnet traffic free).
    pub(crate) fn internal_price(&self) -> u64 {
        self.price_per_mb_internal.unwrap_or(0)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ControlCfg {
    /// HTTP listen for the receipt control plane.
    #[serde(default = "default_control_listen")]
    pub listen: String,
    /// Directory where the audit log writes its daily JSONL files.
    /// Defaults to `./audit` next to the node's working directory.
    #[serde(default)]
    pub audit_dir: Option<String>,
    /// Bearer token gating the `/events` SSE endpoint. `None` (the
    /// default) hides the endpoint entirely (requests return 404
    /// rather than 401 so external scanners can't tell it exists).
    /// Set to a long random string when you want to expose the
    /// stream to a trusted local monitor. v2 hardening fix — the
    /// endpoint used to broadcast every session_id ↔ client_wg_pubkey
    /// mapping + per-session bytes_used to any HTTP client; see
    /// docs/v2-threat-model.md P0-1 and docs/v2-rust-leak-audit.md.
    #[serde(default)]
    pub events_token: Option<String>,
    /// Bearer token gating the `/metrics` Prometheus endpoint.
    /// `None` (the default) refuses scrapes with 503 — operators must
    /// set this for the endpoint to serve. Set the same value in
    /// `deploy/observability/prometheus.yml`'s `authorization:` block
    /// (and any Alertmanager scrape).
    ///
    /// Pick a random ≥32-byte secret (e.g. `openssl rand -hex 32`).
    /// Rotation is operator-driven; restart the node after changing.
    #[serde(default)]
    pub metrics_token: Option<String>,
    /// P1-8/9 persistent receipt-seq journal. The node consults this
    /// file before signing any receipt and refuses to sign at any seq
    /// that does not strictly exceed the on-disk floor. After a
    /// daemon restart the journal is re-loaded so an attacker cannot
    /// force the node to double-sign at a seq it previously committed
    /// to. `None` (the default) resolves to `./state/receipts.bin`
    /// next to the working directory. Move this to a host-private
    /// path (`/var/lib/octravpn/receipts.bin`) for production
    /// operators. Threat-model ref: docs/v2-threat-model.md §3 P1-8 +
    /// P1-9.
    #[serde(default)]
    pub receipt_journal_path: Option<String>,
    /// Bearer token gating the `POST /admin/preauth` endpoint (the
    /// preauth-key minter the Tailscale-interop harness probes for).
    /// `None` (the default) hides the endpoint entirely (any request
    /// returns 404, matching the `/events` design) so a curious
    /// scanner can't tell whether the surface exists. The
    /// `OCTRAVPN_ADMIN_TOKEN` environment variable, if set, is used
    /// as a fallback when this field is unset — handy for ephemeral
    /// docker containers that load the token from a compose secret
    /// rather than persisting it in the rendered `node.toml`.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// Directory to persist the Tailscale-wire Noise long-term static
    /// key (and any future wire-protocol state). Defaults to
    /// `./state/tailscale-wire`. The `noise_static.key` file inside is
    /// 32 raw bytes mode-0600; it must survive across restarts so the
    /// node's `mkey:` identity doesn't churn.
    /// See `docs/tailscale-interop-blocker.md` and
    /// `crates/octravpn-mesh/src/tailscale_wire/noise.rs`.
    #[serde(default)]
    pub tailscale_wire_state_dir: Option<String>,
    /// Tailnet identifier used by `tailscale_wire`'s IP allocator. All
    /// machines registering against this control plane share one
    /// tailnet (the interop test only has two). Defaults to
    /// `"octravpn-interop"` so the harness "just works"; production
    /// operators should set this to a long stable string.
    #[serde(default)]
    pub tailscale_tailnet_id: Option<String>,
}

impl Default for ControlCfg {
    fn default() -> Self {
        Self {
            listen: default_control_listen(),
            audit_dir: None,
            events_token: None,
            metrics_token: None,
            receipt_journal_path: None,
            admin_token: None,
            tailscale_wire_state_dir: None,
            tailscale_tailnet_id: None,
        }
    }
}

fn default_control_listen() -> String {
    "127.0.0.1:51821".into()
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AttestationCfg {
    /// How often to verify that the configured wallet is still an
    /// Octra protocol validator. Long enough that we don't hammer the
    /// chain RPC; short enough that operators see a jail event surface
    /// in /health within ~one minute. Default 30s.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

impl Default for AttestationCfg {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_poll_interval(),
        }
    }
}

fn default_poll_interval() -> u64 {
    30
}

impl NodeConfig {
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read config: {}", path.as_ref().display()))?;
        let cfg: Self = ::toml::from_str(&raw).context("parse node config TOML")?;
        Ok(cfg)
    }
}
