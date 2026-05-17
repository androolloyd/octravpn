use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ClientConfig {
    pub chain: ChainCfg,
    pub wallet: WalletCfg,
    /// v2 substrate options. Optional so older configs keep loading.
    #[serde(default)]
    pub v2: V2Cfg,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ChainCfg {
    pub rpc_url: String,
    pub program_addr: String,
    /// Wire protocol version this client speaks to the chain program.
    /// Accepted values: `"v1.1"` (default; current main-net) and `"v2"`
    /// (circle-native; reads sealed policy from authorized circles).
    /// Picking v2 changes only the discovery + `open_session` shape;
    /// the v1.1 path is preserved unchanged.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    /// Network identifier the client expects the operator to bind into
    /// receipts (v1.2 P1-5 hardening). Must match the operator's
    /// `node.toml` `[chain].chain_id`; mismatch means the client will
    /// reject the proposed receipt as cross-chain. Defaults to
    /// `CHAIN_ID_DEVNET` (devnet); pick the matching mainnet magic
    /// when operators move.
    #[serde(default = "default_chain_id")]
    pub chain_id: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct WalletCfg {
    pub addr: String,
    pub secret_path: String,
}

/// v2-specific config. Sealed-policy passphrase + cache options.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct V2Cfg {
    /// Shared tailnet passphrase used to decrypt sealed circle assets
    /// (`/policy.json`). Comes from the tailnet owner out-of-band.
    /// Precedence: `OCTRAVPN_SEALED_PASSPHRASE` env var > this field >
    /// interactive prompt. Optional in the TOML so secrets don't have
    /// to live on disk.
    #[serde(default)]
    pub sealed_passphrase: Option<String>,
    /// Sealed-key id matching the operator's `cast circle put-encrypted
    /// --key-id`. Default `"default"`.
    #[serde(default = "default_key_id")]
    pub key_id: String,
    /// Directory for cached decrypted policy bundles. Falls back to
    /// `<config-dir>/state/policies/` when empty.
    #[serde(default)]
    pub cache_dir: String,
}

fn default_protocol_version() -> String {
    "v1.1".into()
}

fn default_key_id() -> String {
    "default".into()
}

/// Default chain id when the client config omits the field. Mirrors the
/// node default so a same-host devnet pair just works without explicit
/// configuration. Operators on a different network must override both
/// sides in lockstep.
fn default_chain_id() -> u32 {
    octravpn_core::receipt::CHAIN_ID_DEVNET
}

impl ClientConfig {
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let cfg: Self = toml::from_str(&raw).context("parse client config TOML")?;
        Ok(cfg)
    }

    /// Returns `true` when the config selects the v2 (circle-native)
    /// wire shape. Default is `false` (v1.1).
    pub(crate) fn is_v2(&self) -> bool {
        let v = self.chain.protocol_version.to_ascii_lowercase();
        v == "v2" || v == "2"
    }
}
