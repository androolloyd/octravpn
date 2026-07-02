//! Client-side configuration.
//!
//! The TOML is split into three top-level tables — `[chain]` for the
//! RPC + program target, `[wallet]` for the operator's identity, and
//! one optional table per substrate flavor (`[v2]` for the circle-native
//! sealed-policy flow, `[v3]` for the chain-minimal circle-resident
//! state-root flow). The substrate the client speaks is selected by
//! `[chain].protocol_version`:
//!
//! ```toml
//! [chain]
//! protocol_version = "v3"   # one of: "v1.1" (default) | "v2" | "v3"
//! ```
//!
//! The string is decoded into [`ProtocolVersion`] via
//! [`ClientConfig::protocol_version`]; the raw string is kept on
//! `ChainCfg` so the v1.1 / v2 paths can continue reading
//! `cfg.chain.protocol_version` unchanged.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Wire-protocol selector — typed enum mirror of `[chain].protocol_version`.
///
/// `V1_1` is the legacy operator-wallet-as-identity flow against
/// `program/main.aml`. `V2` is the circle-native flow against
/// `program/main-v2.aml`. `V3` is the chain-minimal, circle-resident
/// flow against `program/main-v3.aml` (deployed on devnet at
/// `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`). Mirrors the
/// node-side `octravpn-node::config::ProtocolVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolVersion {
    V1_1,
    V2,
    V3,
}

impl ProtocolVersion {
    /// Parse the on-disk `[chain].protocol_version` string. Case-
    /// insensitive; defaults to `V1_1` when the field is empty.
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "v1" | "v1.1" => Ok(Self::V1_1),
            "v2" | "2" => Ok(Self::V2),
            "v3" | "3" => Ok(Self::V3),
            other => Err(anyhow::anyhow!(
                "unknown [chain].protocol_version '{other}' (expected v1.1|v2|v3)"
            )),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ClientConfig {
    pub chain: ChainCfg,
    pub wallet: WalletCfg,
    /// v2 substrate options. Optional so older configs keep loading.
    #[serde(default)]
    pub v2: V2Cfg,
    /// v3 substrate options. Optional so older configs keep loading.
    #[serde(default)]
    pub v3: V3Cfg,
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
    /// Pin the TLS trust roots for `rpc_url` to these PEM bundle files.
    /// Empty / unset → use the system trust store (default). When set,
    /// every chain RPC call must terminate at a cert signed by one of
    /// the supplied roots, even if the OS trust store would otherwise
    /// accept a different chain. Defeats CA-compromise MITM — a
    /// corporate proxy installing a rogue CA, a malicious MDM, etc.
    /// P0-2 from docs/v2-threat-model.md.
    #[serde(default)]
    pub pinned_root_paths: Option<Vec<String>>,
    /// Network identifier the client expects the operator to bind into
    /// receipts (P1-5 hardening). Must match the operator's
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

/// v3-specific config. The v3 chain surface stores only an anchor
/// (sha256 of canonical `state-root.json`) + a receipt pubkey; the
/// full policy / WG pubkey / region / member-count live in the
/// operator's circle as a sealed asset. The client only needs to
/// know which `(tailnet_id, circle_id)` to bind to — everything else
/// is fetched + validated from chain at session-open time.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct V3Cfg {
    /// `oct…` address of the desired operator circle. The circle's
    /// `state-root.json` anchor must already be registered on chain
    /// via `register_circle`. Empty / unset → `connect-v3` aborts
    /// with a helpful error.
    #[serde(default)]
    pub circle_id: String,
    /// On-chain tailnet id the client is a member of. The v3 program
    /// publishes a `members_root` anchor for this id; until the real
    /// Merkle proof verifier ships (191 follow-up) the client just
    /// logs the on-chain root and trusts membership.
    #[serde(default)]
    pub tailnet_id: u64,
    /// Override path to the wallet secret used for v3 session txs.
    /// Falls back to `[wallet].secret_path` when unset.
    #[serde(default)]
    pub wallet_key_path: Option<String>,
    /// Cap on the credit (raw OU) the client is willing to spend on
    /// a single session. Passed to `open_session(..., max_pay)`. v3
    /// has no separate session-class tariff; defaults to 1500 to
    /// match `docker/devnet/v3-smoke.sh`.
    #[serde(default = "default_v3_max_pay")]
    pub max_pay: u64,
    /// v4 relay-settlement client caller path. Defaults disabled so
    /// v3 `settle_confirm` remains settlement-of-record until the
    /// client explicitly opts in.
    #[serde(default)]
    pub relay: V3RelayCfg,
}

fn default_v3_max_pay() -> u64 {
    1_500
}

/// `[v3.relay]` — optional v4 relay-settlement arm path.
#[derive(Debug, Deserialize, Clone, Copy)]
pub(crate) struct V3RelayCfg {
    /// Master toggle. `false` by default.
    #[serde(default)]
    pub enabled: bool,
    /// Epochs the operator has to reveal the receipt preimage before
    /// the client can call `relay_refund`.
    #[serde(default = "default_relay_expiry_epochs")]
    pub relay_expiry_epochs: u64,
}

impl Default for V3RelayCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_expiry_epochs: default_relay_expiry_epochs(),
        }
    }
}

fn default_relay_expiry_epochs() -> u64 {
    octravpn_core::v3_calls::RELAY_EXPIRY_DEFAULT_EPOCHS
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

    /// Returns `true` when the config selects the v3 (chain-minimal,
    /// circle-resident) wire shape. Default is `false` (v1.1).
    #[allow(dead_code)] // referenced from v3_runner only.
    pub(crate) fn is_v3(&self) -> bool {
        matches!(self.protocol_version(), Ok(ProtocolVersion::V3))
    }

    /// Typed accessor for `[chain].protocol_version`. Returns an error
    /// when the on-disk string is not one of the supported variants —
    /// callers that don't care about v3 just keep reading
    /// `cfg.chain.protocol_version` directly.
    pub(crate) fn protocol_version(&self) -> Result<ProtocolVersion> {
        ProtocolVersion::parse(&self.chain.protocol_version)
    }
}
