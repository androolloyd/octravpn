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

use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// Audit-2 CFG-2 / Audit-3 H-6 fix.
///
/// `redact_opt_secret` is the canonical `Debug` placeholder for every
/// `Option<SecretString>` field on the node-config types. We render
/// `None` as the literal `"None"` (so operators can still see whether a
/// secret is configured) and `Some(_)` as the literal `"<redacted>"`
/// (never the bytes — not even the length, since the length alone is
/// enough to fingerprint bearer-token shapes like 32-byte hex). The
/// trace-redaction unit test in this module pins this exact wording.
// `&Option<T>` (rather than `Option<&T>`) is deliberate: the callers
// thread this through Debug impls that already hold `&Option<SecretString>`
// on the parent struct's `&self`, so re-borrowing would just add noise.
#[allow(clippy::ref_option)]
fn redact_opt_secret(f: &mut fmt::Formatter<'_>, v: &Option<SecretString>) -> fmt::Result {
    match v {
        None => f.write_str("None"),
        Some(_) => f.write_str("Some(<redacted>)"),
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// HFHE-2: optional path to the on-disk envelope holding the
    /// operator's circle PVAC pubkey blob (`hfhe_v1|<base64>`).
    /// When `enabled = true` AND both `circle_pubkey_path` and
    /// `circle_secret_path` resolve to readable files at boot, the
    /// receipt-signing path homomorphically encrypts `bytes_used`
    /// and `net` under this pubkey and attaches the ciphertext to
    /// each emitted receipt. When either path is unset OR the file
    /// does not exist, the shadow blob is `None` on the wire — so
    /// receipts remain wire-compatible with pre-HFHE-2 operators.
    #[serde(default)]
    pub circle_pubkey_path: Option<String>,
    /// HFHE-2: optional path to the on-disk envelope holding the
    /// matching circle PVAC secret key (`hfhe_v1|<base64>`). Loaded
    /// once at boot when both this and `circle_pubkey_path`
    /// resolve. The secret never leaves the operator process.
    #[serde(default)]
    pub circle_secret_path: Option<String>,
}

impl Default for PvacCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            binary_path: default_pvac_binary_path(),
            restart_backoff_ms: default_pvac_restart_backoff_ms(),
            request_timeout_secs: default_pvac_request_timeout_secs(),
            circle_pubkey_path: None,
            circle_secret_path: None,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: wrapped in `secrecy::SecretString`
    /// so any accidental `tracing::debug!(?cfg)` prints `<redacted>`
    /// rather than the 64-char hex secret. Access via
    /// [`Obfs4Cfg::bridge_identity_secret_expose`].
    #[serde(default)]
    pub bridge_identity_secret: Option<SecretString>,
    /// IAT mode: 0 = off (default), 1 = uniform 0..25ms,
    /// 2 = Pareto-shaped 0..200ms. See `octravpn_obfs4::IatMode`.
    #[serde(default)]
    pub iat_mode: u8,
}

impl Obfs4Cfg {
    /// Expose the bridge-identity secret for the obfs4 handshake.
    /// Returns `None` on client-side configs (no secret set). The
    /// caller MUST NOT log or otherwise persist the returned &str.
    pub(crate) fn bridge_identity_secret_expose(&self) -> Option<&str> {
        self.bridge_identity_secret
            .as_ref()
            .map(ExposeSecret::expose_secret)
    }
}

impl fmt::Debug for Obfs4Cfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Obfs4Cfg")
            .field("bridge_node_id", &self.bridge_node_id)
            .field("bridge_pubkey", &self.bridge_pubkey)
            .field(
                "bridge_identity_secret",
                &format_args!(
                    "{}",
                    if self.bridge_identity_secret.is_none() {
                        "None"
                    } else {
                        "Some(<redacted>)"
                    }
                ),
            )
            .field("iat_mode", &self.iat_mode)
            .finish()
    }
}

/// `[analytics]` block. Bearer-gated like `[control].metrics_token`:
/// the HTTP surface returns 503 unless `bearer_token` is set, so a
/// misconfigured operator gets a clear "endpoint disabled" rather
/// than an open Prometheus endpoint.
#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
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
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: wrapped in `secrecy::SecretString`
    /// so any accidental `tracing::debug!(?cfg)` prints `<redacted>`.
    /// Use [`AnalyticsCfg::bearer_token_string`] to materialise the
    /// `Option<String>` the analytics HTTP layer requires.
    #[serde(default)]
    pub bearer_token: Option<SecretString>,
}

impl AnalyticsCfg {
    /// Materialise the bearer token as `Option<String>` for the
    /// analytics HTTP state constructor. The returned `String` is the
    /// expose-point — callers should hand it directly into
    /// `octravpn_analytics::HttpState::new` (which immediately wraps it
    /// in `Arc<str>` for constant-time comparison) and never log it.
    pub(crate) fn bearer_token_string(&self) -> Option<String> {
        self.bearer_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
    }
}

impl fmt::Debug for AnalyticsCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("AnalyticsCfg");
        s.field("enabled", &self.enabled)
            .field("listen_addr", &self.listen_addr);
        struct R<'a>(&'a Option<SecretString>);
        impl fmt::Debug for R<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                redact_opt_secret(f, self.0)
            }
        }
        s.field("bearer_token", &R(&self.bearer_token)).finish()
    }
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

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: wrapped in `secrecy::SecretString`
    /// so the master tailnet passphrase never appears in
    /// `tracing::debug!(?cfg)` output. Access via
    /// [`ChainCfg::sealed_passphrase_expose`] (still returns the same
    /// `Option<&str>` the consumers in `hub::boot::resolve_sealed_passphrase`
    /// expect).
    #[serde(default)]
    pub sealed_passphrase: Option<SecretString>,
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

impl ChainCfg {
    /// Expose the per-tailnet sealed-asset passphrase. Returns the same
    /// `Option<&str>` shape that `Option<String>::as_deref` used to
    /// return, so the v2 boot / attestation / cli/circle consumers stay
    /// 1-line changes. The caller MUST NOT log the result.
    pub(crate) fn sealed_passphrase_expose(&self) -> Option<&str> {
        self.sealed_passphrase
            .as_ref()
            .map(ExposeSecret::expose_secret)
    }
}

impl fmt::Debug for ChainCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("ChainCfg");
        s.field("rpc_url", &self.rpc_url)
            .field("program_addr", &self.program_addr)
            .field("validator_addr", &self.validator_addr)
            .field("wallet_secret_path", &self.wallet_secret_path)
            .field("protocol_version", &self.protocol_version)
            .field("chain_id", &self.chain_id);
        struct R<'a>(&'a Option<SecretString>);
        impl fmt::Debug for R<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                redact_opt_secret(f, self.0)
            }
        }
        s.field("sealed_passphrase", &R(&self.sealed_passphrase))
            .field("circle_state_path", &self.circle_state_path)
            .field("pinned_root_paths", &self.pinned_root_paths)
            .field("circle_id", &self.circle_id)
            .field("circle_v3_state_path", &self.circle_v3_state_path)
            .field("v3_initial_stake", &self.v3_initial_stake)
            .field("require_sealed_keys", &self.require_sealed_keys)
            .field("attestation_url", &self.attestation_url)
            .finish()
    }
}

/// Default chain id when a config omits the field. Devnet today; will
/// flip to mainnet once the production v2 deploy lands. Operators must
/// override explicitly to opt into another network.
fn default_chain_id() -> u32 {
    octravpn_core::receipt::CHAIN_ID_DEVNET
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: wrapped in `secrecy::SecretString`
    /// so `tracing::debug!(?cfg)` prints `<redacted>`. Use
    /// [`ControlCfg::events_token_string`] for the `Option<String>` the
    /// downstream control-plane state-setter expects.
    #[serde(default)]
    pub events_token: Option<SecretString>,
    /// Bearer token gating the `/metrics` Prometheus endpoint.
    /// `None` (the default) refuses scrapes with 503 — operators must
    /// set this for the endpoint to serve. Set the same value in
    /// `deploy/observability/prometheus.yml`'s `authorization:` block
    /// (and any Alertmanager scrape).
    ///
    /// Pick a random ≥32-byte secret (e.g. `openssl rand -hex 32`).
    /// Rotation is operator-driven; restart the node after changing.
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: `secrecy::SecretString`-wrapped.
    /// Use [`ControlCfg::metrics_token_string`].
    #[serde(default)]
    pub metrics_token: Option<SecretString>,
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
    ///
    /// Audit-2 CFG-2 / Audit-3 H-6: `secrecy::SecretString`-wrapped.
    /// Use [`ControlCfg::admin_token_string`] to materialise the
    /// `Option<String>` `hub::spawn` hands to `ControlState`.
    #[serde(default)]
    pub admin_token: Option<SecretString>,
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

impl ControlCfg {
    /// Materialise the events SSE bearer token. Wrap in `String` (not
    /// `&str`) so the consumer in `hub::spawn` can hand it directly to
    /// `ControlState::with_events_token` — same `Option<String>` shape
    /// the pre-secrecy code passed.
    pub(crate) fn events_token_string(&self) -> Option<String> {
        self.events_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
    }
    /// Materialise the `/metrics` bearer token (same contract as
    /// [`Self::events_token_string`]).
    pub(crate) fn metrics_token_string(&self) -> Option<String> {
        self.metrics_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
    }
    /// Materialise the admin bearer token (same contract as
    /// [`Self::events_token_string`]).
    pub(crate) fn admin_token_string(&self) -> Option<String> {
        self.admin_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
    }
}

impl fmt::Debug for ControlCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct R<'a>(&'a Option<SecretString>);
        impl fmt::Debug for R<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                redact_opt_secret(f, self.0)
            }
        }
        f.debug_struct("ControlCfg")
            .field("listen", &self.listen)
            .field("audit_dir", &self.audit_dir)
            .field("events_token", &R(&self.events_token))
            .field("metrics_token", &R(&self.metrics_token))
            .field("receipt_journal_path", &self.receipt_journal_path)
            .field("admin_token", &R(&self.admin_token))
            .field(
                "tailscale_wire_state_dir",
                &self.tailscale_wire_state_dir,
            )
            .field("tailscale_tailnet_id", &self.tailscale_tailnet_id)
            .finish()
    }
}

fn default_control_listen() -> String {
    "127.0.0.1:51821".into()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid TOML — every required-by-the-loader field present
    /// and nothing else. Sub-tests prepend a typo'd top-level / nested
    /// key to this baseline and assert the parse fails with a useful
    /// message.
    const MIN_TOML: &str = r#"
[chain]
rpc_url = "https://example/test"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "/tmp/wallet.key"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "/tmp/wg.key"

[pricing]
price_per_mb = 100
region = "eu-west"
"#;

    /// Sanity: the baseline parses cleanly. If this regresses every
    /// typo test below is meaningless.
    #[test]
    fn baseline_parses() {
        let cfg: NodeConfig = ::toml::from_str(MIN_TOML).expect("baseline TOML must parse");
        assert_eq!(cfg.pricing.price_per_mb, 100);
    }

    /// Audit-2 CFG-1: typo on a top-level key (`pricng` vs `pricing`)
    /// MUST be rejected, naming the unknown field. Without
    /// `deny_unknown_fields` the typo'd block was silently dropped and
    /// the loader fell back to whatever defaults existed (none here ⇒
    /// would have errored on the missing required `pricing.region` —
    /// but only after the typo'd block was already discarded).
    #[test]
    fn unknown_top_level_block_is_rejected() {
        let bad = format!("{MIN_TOML}\n[pricng]\nprice_per_mb = 9999\n");
        let err = ::toml::from_str::<NodeConfig>(&bad).expect_err("typo'd block must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("pricng") || msg.contains("unknown"),
            "error should name the bad field, got: {msg}"
        );
    }

    /// Audit-2 CFG-1: typo on a `[chain]` sub-field
    /// (`progrm_addr` vs `program_addr`) MUST be rejected.
    #[test]
    fn unknown_chain_field_is_rejected() {
        let bad = MIN_TOML.replace("program_addr =", "progrm_addr =");
        let err = ::toml::from_str::<NodeConfig>(&bad).expect_err("typo'd field must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("progrm_addr") || msg.contains("unknown") || msg.contains("missing"),
            "error should name the bad field, got: {msg}"
        );
    }

    /// Audit-2 CFG-1: typo on a `[control]` security-critical key
    /// (`metric_token` vs `metrics_token`) MUST be rejected. This is
    /// the canonical scanner-facing impact: pre-fix, the typo
    /// resulted in a silent 503 with no diagnostic; post-fix the node
    /// refuses to boot.
    #[test]
    fn unknown_control_token_field_is_rejected() {
        let bad = format!("{MIN_TOML}\n[control]\nmetric_token = \"abc\"\n");
        let err = ::toml::from_str::<NodeConfig>(&bad)
            .expect_err("typo'd bearer-token key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("metric_token") || msg.contains("unknown"),
            "error should name the bad field, got: {msg}"
        );
    }

    /// Audit-2 CFG-1: typo on an `[analytics]` key
    /// (`bearer` vs `bearer_token`) MUST be rejected.
    #[test]
    fn unknown_analytics_field_is_rejected() {
        let bad = format!("{MIN_TOML}\n[analytics]\nbearer = \"abc\"\n");
        let err = ::toml::from_str::<NodeConfig>(&bad).expect_err("typo'd analytics key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("bearer") || msg.contains("unknown"),
            "error should name the bad field, got: {msg}"
        );
    }

    /// Audit-2 CFG-1: typo on a `[tun.transport.obfs4]` key
    /// (`bridge_identity_secrt` vs `bridge_identity_secret`) MUST be
    /// rejected. Plain-string typos in security-critical hex blobs
    /// were the audit's most-cited risk class.
    #[test]
    fn unknown_obfs4_field_is_rejected() {
        let bad = format!(
            "{MIN_TOML}\n[tun.transport]\nkind = \"obfs4\"\n\
             [tun.transport.obfs4]\n\
             bridge_node_id = \"0102030405060708090a0b0c0d0e0f1011121314\"\n\
             bridge_pubkey  = \"abcd000000000000000000000000000000000000000000000000000000000000\"\n\
             bridge_identity_secrt = \"deadbeef\"\n"
        );
        let err = ::toml::from_str::<NodeConfig>(&bad).expect_err("typo'd obfs4 key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("bridge_identity_secrt") || msg.contains("unknown"),
            "error should name the bad field, got: {msg}"
        );
    }

    /// Audit-3 H-6 / Audit-2 CFG-2: trace-redaction property.
    ///
    /// Populate every secret field with a sentinel value that's easy to
    /// grep for; render the config through `{:?}` (mirrors
    /// `tracing::debug!(?cfg)`); assert none of the secret bytes leak.
    #[test]
    fn debug_format_does_not_leak_secret_bytes() {
        const SENTINEL_PASSPHRASE: &str = "TRIPWIRE_PASSPHRASE_AAAAAAAAAAAAAA";
        const SENTINEL_ADMIN: &str = "TRIPWIRE_ADMIN_TOKEN_BBBBBBBBBBBBBB";
        const SENTINEL_METRICS: &str = "TRIPWIRE_METRICS_TOKEN_CCCCCCCCCCCC";
        const SENTINEL_EVENTS: &str = "TRIPWIRE_EVENTS_TOKEN_DDDDDDDDDDDDD";
        const SENTINEL_ANALYTICS: &str = "TRIPWIRE_ANALYTICS_BEARER_EEEEEEEE";
        const SENTINEL_OBFS4: &str = "TRIPWIRE_OBFS4_SECRET_FFFFFFFFFFFF";

        let toml_str = format!(
            r#"
[chain]
rpc_url = "https://example/test"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "/tmp/wallet.key"
sealed_passphrase = "{SENTINEL_PASSPHRASE}"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "/tmp/wg.key"

[pricing]
price_per_mb = 100
region = "eu-west"

[control]
admin_token = "{SENTINEL_ADMIN}"
metrics_token = "{SENTINEL_METRICS}"
events_token = "{SENTINEL_EVENTS}"

[analytics]
enabled = true
bearer_token = "{SENTINEL_ANALYTICS}"

[tun.transport]
kind = "obfs4"

[tun.transport.obfs4]
bridge_node_id  = "0102030405060708090a0b0c0d0e0f1011121314"
bridge_pubkey   = "abcd000000000000000000000000000000000000000000000000000000000000"
bridge_identity_secret = "{SENTINEL_OBFS4}"
iat_mode = 1
"#
        );
        let cfg: NodeConfig =
            ::toml::from_str(&toml_str).expect("trace-redaction fixture must parse");
        let rendered = format!("{cfg:?}");
        // Every sentinel string MUST be absent. If any of these
        // assertions fires the redacting Debug impl regressed.
        for needle in [
            SENTINEL_PASSPHRASE,
            SENTINEL_ADMIN,
            SENTINEL_METRICS,
            SENTINEL_EVENTS,
            SENTINEL_ANALYTICS,
            SENTINEL_OBFS4,
        ] {
            assert!(
                !rendered.contains(needle),
                "leak: {needle:?} appeared in Debug output:\n{rendered}"
            );
        }
        // Positive control: the redaction sentinel IS present (so the
        // assertion above isn't "vacuously true" because we used
        // `{:?}` on the wrong value).
        assert!(
            rendered.contains("<redacted>"),
            "expected '<redacted>' marker in Debug output, got:\n{rendered}"
        );
    }

    /// Audit-3 H-6 / Audit-2 CFG-2: same property but through
    /// `tracing::debug!(?cfg)` — a tracing subscriber capture, since
    /// the audit specifically names this macro. Belt-and-braces vs.
    /// the bare `format!("{:?}")` check above.
    #[test]
    fn tracing_debug_does_not_leak_secret_bytes() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        const SENTINEL: &str = "TRACINGTRIPWIRE_PASSPHRASE_GGGGGGG";

        let toml_str = format!(
            r#"
[chain]
rpc_url = "https://example/test"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "/tmp/wallet.key"
sealed_passphrase = "{SENTINEL}"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "/tmp/wg.key"

[pricing]
price_per_mb = 100
region = "eu-west"
"#
        );
        let cfg: NodeConfig = ::toml::from_str(&toml_str).expect("fixture must parse");

        #[derive(Clone, Default)]
        struct CapWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CapWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for CapWriter {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
        let writer = CapWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(?cfg, "config-dump");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).expect("utf8");
        assert!(
            !out.contains(SENTINEL),
            "tracing::debug!(?cfg) leaked the sealed_passphrase sentinel:\n{out}"
        );
    }
}
