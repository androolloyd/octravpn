//! Node configuration loader.
//!
//! TOML schema:
//!
//!   [chain]
//!   rpc_url = "..."
//!   program_addr = "oct..."          # OctraVPN program address (v1.1 or v2)
//!   validator_addr = "oct..."        # this node's Octra wallet address
//!   wallet_secret_path = "/keys/..." # used to sign transactions
//!   protocol_version = "v1.1"        # "v1.1" (default) or "v2" — selects
//!                                    # which registration flow runs at boot.
//!                                    # v2 deploys a Circle, uploads sealed
//!                                    # policy, and calls register_circle on
//!                                    # the slim v2 registry. See
//!                                    # docs/v2-operator-flow.md.
//!   chain_id = 1869832804             # u32 network id bound into every
//!                                    # signed receipt (v1.2). Defaults to
//!                                    # CHAIN_ID_DEVNET (0x6F637464); pick a
//!                                    # distinct value for mainnet (see
//!                                    # `octravpn_core::receipt::CHAIN_ID_*`).
//!   # v2-only: per-tailnet passphrase used to derive AES-GCM read keys for
//!   # sealed assets stored inside the operator circle. Operators receive
//!   # this from their tailnet owner at provisioning. Optional in v1.1.
//!   sealed_passphrase = "..."        # OR set OCTRAVPN_SEALED_PASSPHRASE env
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
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProtocolVersion {
    #[serde(rename = "v1.1", alias = "v1")]
    V1_1,
    #[serde(rename = "v2")]
    V2,
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
    /// passphrase for the AES-GCM read key. Empty/absent falls back to
    /// the `OCTRAVPN_SEALED_PASSPHRASE` env var.
    #[serde(default)]
    pub sealed_passphrase: Option<String>,
    /// v2-only. Where to persist the predicted/deployed circle id so
    /// the operator doesn't re-derive on every restart. Defaults to
    /// `./state/circle.toml` next to the working directory.
    #[serde(default)]
    pub circle_state_path: Option<String>,
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
}

impl Default for ControlCfg {
    fn default() -> Self {
        Self {
            listen: default_control_listen(),
            audit_dir: None,
            events_token: None,
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
