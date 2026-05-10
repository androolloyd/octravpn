//! Node configuration loader.
//!
//! TOML schema (see node.example.toml in the repo root):
//!
//!   [chain]
//!   rpc_url = "..."
//!   program_addr = "oct..."          # OctraVPN program
//!   validator_addr = "oct..."        # this validator's address
//!   wallet_secret_path = "/keys/..." # used to sign attestations
//!
//!   [tunnel]
//!   public_endpoint = "1.2.3.4:51820"
//!   listen = "0.0.0.0:51820"
//!   wg_secret_path = "/keys/wg.key"
//!
//!   [pricing]
//!   price_per_mb = 100               # raw OU per MB
//!   region = "eu-west"
//!
//!   [fhe]
//!   secret_path = "/keys/fhe.sk"     # FHE secret used to decrypt earnings
//!   pubkey_path = "/keys/fhe.pk"     # FHE pubkey published on chain

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub chain: ChainCfg,
    pub tunnel: TunnelCfg,
    pub pricing: PricingCfg,
    #[serde(default)]
    pub control: ControlCfg,
    #[serde(default)]
    pub attestation: AttestationCfg,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
    pub validator_addr: String,
    pub wallet_secret_path: String,
    /// Optional: minimum bond to attach at registration. Defaults to the
    /// program's `min_bond` if absent.
    #[serde(default)]
    pub initial_bond: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TunnelCfg {
    pub public_endpoint: String,
    pub listen: String,
    pub wg_secret_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PricingCfg {
    pub price_per_mb: u64,
    pub region: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ControlCfg {
    /// HTTP listen for the receipt control plane.
    #[serde(default = "default_control_listen")]
    pub listen: String,
}

impl Default for ControlCfg {
    fn default() -> Self {
        Self { listen: default_control_listen() }
    }
}

fn default_control_listen() -> String {
    "0.0.0.0:51821".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct AttestationCfg {
    /// Refresh attestation every N epochs. Default 5.
    #[serde(default = "default_refresh")]
    pub refresh_every_epochs: u64,
    /// Soft margin: refresh before this many epochs of grace remain.
    #[serde(default = "default_margin")]
    pub safety_margin_epochs: u64,
}

impl Default for AttestationCfg {
    fn default() -> Self {
        Self {
            refresh_every_epochs: default_refresh(),
            safety_margin_epochs: default_margin(),
        }
    }
}

fn default_refresh() -> u64 {
    5
}
fn default_margin() -> u64 {
    2
}

impl NodeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read config: {}", path.as_ref().display()))?;
        let cfg: NodeConfig =
            ::toml::from_str(&raw).context("parse node config TOML")?;
        Ok(cfg)
    }
}
