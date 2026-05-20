//! Identity-and-key surfacing: the `info` subcommand stdout dump plus
//! the small derivation helper that lifts the stealth view-pubkey out
//! of the wallet secret.
//!
//! Grow this file with new "who am I" diagnostics. A new diagnostic
//! that talks to the *network* (live receipts, peer state) is not an
//! identity concern — give it its own submodule.

use crate::{
    chain_v2::CircleState,
    chain_v3,
    config::ProtocolVersion,
    v3_boot,
};
use x25519_dalek::PublicKey as X25519Pub;

use super::Hub;

impl Hub {
    pub(crate) fn print_identity(&self) {
        println!("validator addr   = {}", self.chain.validator_addr.display());
        println!("program addr     = {}", self.chain.program_addr.display());
        println!(
            "wallet pubkey    = {}",
            hex::encode(self.chain.wallet.public.0)
        );
        println!("wg pubkey        = {}", hex::encode(self.wg_kp.public.0));
        println!(
            "wg x25519 pub    = {}",
            hex::encode(X25519Pub::from(&self.wg_static_secret).to_bytes())
        );
        println!("view pubkey      = {}", hex::encode(self.view_pubkey));
        println!("public endpoint  = {}", self.cfg.tunnel.public_endpoint);
        println!(
            "protocol version = {}",
            match self.cfg.chain.protocol_version {
                ProtocolVersion::V1_1 => "v1.1",
                ProtocolVersion::V2 => "v2 (Circle-native)",
                ProtocolVersion::V3 => "v3 (chain-minimal, circle-resident)",
            }
        );
        if self.cfg.chain.protocol_version == ProtocolVersion::V3 {
            if let Some(cid) = self.cfg.chain.circle_id.as_deref() {
                println!("v3 circle id     = {cid}");
            } else {
                println!("v3 circle id     = <missing — set [chain].circle_id in node.toml>");
            }
            let p = v3_boot::v3_state_path(&self.cfg);
            match chain_v3::CircleV3State::load(&p) {
                Ok(Some(state)) => {
                    if !state.last_anchor_hex.is_empty() {
                        println!("v3 last anchor   = {}", state.last_anchor_hex);
                    }
                    if !state.register_tx_hash.is_empty() {
                        println!("v3 register tx   = {}", state.register_tx_hash);
                    }
                    if !state.last_update_tx_hash.is_empty() {
                        println!("v3 last update tx= {}", state.last_update_tx_hash);
                    }
                }
                Ok(None) => {
                    println!("v3 boot state    = <not yet computed; run `octravpn-node register`>");
                }
                Err(e) => {
                    println!("v3 boot state    = <error reading {}: {e}>", p.display());
                }
            }
        }
        if self.cfg.chain.protocol_version == ProtocolVersion::V2 {
            // Predict what `register_endpoint` would produce, given the
            // current chain state. Best-effort: if the chain is
            // unreachable, just print the cache.
            let state_path = self.circle_state_path();
            match CircleState::load(&state_path) {
                Ok(Some(state)) => {
                    println!("v2 circle id     = {}", state.circle_id);
                    println!("v2 deploy nonce  = {}", state.deploy_nonce);
                    if !state.deploy_tx_hash.is_empty() {
                        println!("v2 deploy tx     = {}", state.deploy_tx_hash);
                    }
                    if !state.policy_tx_hash.is_empty() {
                        println!("v2 policy tx     = {}", state.policy_tx_hash);
                    }
                    if !state.register_tx_hash.is_empty() {
                        println!("v2 register tx   = {}", state.register_tx_hash);
                    }
                }
                Ok(None) => {
                    println!("v2 circle id     = <not yet derived; run `octravpn-node register`>");
                }
                Err(e) => {
                    println!(
                        "v2 circle state  = <error reading {}: {e}>",
                        state_path.display()
                    );
                }
            }
        }
    }
}

/// Derive the operator's stealth view-pubkey from the on-disk wallet
/// secret.
///
/// The view PUBLIC key is `view_secret · G_x25519`, where
/// `view_secret` is HKDF'd from the wallet SECRET. Deriving from the
/// public key would let anyone with the on-chain address recompute
/// stealth tags — see `octravpn_core::stealth` module docs.
pub(super) fn wallet_view_pubkey(wallet_secret: &[u8; 32]) -> [u8; 32] {
    octravpn_core::stealth::view_pubkey_from_wallet(wallet_secret)
}
