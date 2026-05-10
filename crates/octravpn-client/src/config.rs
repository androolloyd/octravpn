use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub chain: ChainCfg,
    pub wallet: WalletCfg,
    #[serde(default)]
    pub tunnel: TunnelCfg,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WalletCfg {
    pub addr: String,
    pub secret_path: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TunnelCfg {
    /// Local listen address for the userspace WireGuard client. The
    /// system-level network plumbing (TUN device or SOCKS proxy bridge)
    /// is OS-specific; v1 prints the WG endpoint info so a user can
    /// configure their OS WG client manually if they prefer.
    #[serde(default = "default_listen")]
    pub local_listen: String,
}

fn default_listen() -> String {
    "127.0.0.1:51821".into()
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let cfg: ClientConfig =
            toml::from_str(&raw).context("parse client config TOML")?;
        Ok(cfg)
    }
}
