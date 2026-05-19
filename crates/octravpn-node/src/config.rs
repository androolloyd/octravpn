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
//!   listen = "0.0.0.0:51821"
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
}

impl Default for ControlCfg {
    fn default() -> Self {
        Self {
            listen: default_control_listen(),
            audit_dir: None,
            events_token: None,
            receipt_journal_path: None,
        }
    }
}

fn default_control_listen() -> String {
    "0.0.0.0:51821".into()
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
