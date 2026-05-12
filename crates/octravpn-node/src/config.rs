//! Node configuration loader.
//!
//! TOML schema:
//!
//!   [chain]
//!   rpc_url = "..."
//!   program_addr = "oct..."          # OctraVPN program address
//!   validator_addr = "oct..."        # this node's Octra validator address
//!   wallet_secret_path = "/keys/..." # used to sign transactions
//!
//!   [tunnel]
//!   public_endpoint = "1.2.3.4:51820"
//!   listen = "0.0.0.0:51820"
//!   wg_secret_path = "/keys/wg.key"  # master from which WG + receipt keys derive
//!
//!   [pricing]
//!   price_per_mb = 100               # raw OU per MB
//!   region = "eu-west"
//!
//!   [control]
//!   listen = "0.0.0.0:51821"
//!
//!   [attestation]
//!   poll_interval_secs = 30          # how often to recheck Octra-validator status

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

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
    pub validator_addr: String,
    pub wallet_secret_path: String,
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
}

impl Default for ControlCfg {
    fn default() -> Self {
        Self {
            listen: default_control_listen(),
            audit_dir: None,
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
