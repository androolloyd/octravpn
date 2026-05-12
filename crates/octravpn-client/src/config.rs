use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ClientConfig {
    pub chain: ChainCfg,
    pub wallet: WalletCfg,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct WalletCfg {
    pub addr: String,
    pub secret_path: String,
}

impl ClientConfig {
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let cfg: Self = toml::from_str(&raw).context("parse client config TOML")?;
        Ok(cfg)
    }
}
