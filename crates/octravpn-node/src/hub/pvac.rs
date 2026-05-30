//! PVAC-adjacent boundary helpers: `build_shadow_signer` (HFHE-2
//! shadow blob), `build_receipt_context` (P1-5 deployment binding for
//! signed receipts), and `build_policy_bundle` (v2 sealed-asset
//! plaintext).
//!
//! All three are small struct constructors hand-fed by the hub. If a
//! "build" helper grows >100 LOC or starts owning real state, lift it
//! into its own crate-level module under `crates/octravpn-node/src/`
//! rather than expanding this file.

use octravpn_core::address::Address;
use std::sync::Arc;
use tracing::{info, warn};
use x25519_dalek::PublicKey as X25519Pub;

use super::Hub;
use crate::{
    chain_v2::{CircleState, PolicyBundle},
    config::ProtocolVersion,
};

impl Hub {
    /// HFHE-2: build the optional [`crate::control::ShadowSigner`]
    /// from `(self.pvac, cfg.pvac.circle_pubkey_path,
    /// cfg.pvac.circle_secret_path)`. Returns `None` when any
    /// component is missing — that's the no-shadow path. A
    /// read failure on either key file is logged + treated as
    /// `None` so a missing-key situation degrades gracefully
    /// rather than blowing up boot.
    pub(super) fn build_shadow_signer(&self) -> Option<Arc<crate::control::ShadowSigner>> {
        let pvac = self.pvac.as_ref()?.clone();
        let pk_path = self.cfg.pvac.circle_pubkey_path.as_deref()?;
        let sk_path = self.cfg.pvac.circle_secret_path.as_deref()?;
        let pk = match std::fs::read_to_string(pk_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                warn!(error = %e, path = %pk_path, "circle pubkey unreadable; shadow blob disabled");
                return None;
            }
        };
        let sk = match std::fs::read_to_string(sk_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                warn!(error = %e, path = %sk_path, "circle secret unreadable; shadow blob disabled");
                return None;
            }
        };
        if !pk.starts_with("hfhe_v1|") || !sk.starts_with("hfhe_v1|") {
            warn!("circle key files do not have hfhe_v1| prefix; shadow blob disabled");
            return None;
        }
        info!("HFHE-2 shadow signer enabled (circle keys loaded)");
        Some(Arc::new(crate::control::ShadowSigner {
            pvac,
            circle_pk: pk,
            circle_sk: sk,
        }))
    }

    /// Build the deployment-domain receipt context that gets bound into
    /// every signed receipt. v1.2 P1-5 hardening: a receipt is now
    /// non-replayable across programs, chains, and circles.
    ///
    /// v1.1 operators leave `circle_id = None`. v2 operators that have
    /// completed `register_endpoint_v2` will have a `state/circle.toml`
    /// on disk; we read it best-effort and populate `circle_id =
    /// Some(addr)` from it. If the circle file is missing (operator
    /// hasn't called `register` yet) we fall back to `None` — the
    /// startup path will rewrite the context as soon as the deploy
    /// completes (operators always run `register` before serving
    /// traffic).
    pub(super) fn build_receipt_context(&self) -> octravpn_core::receipt::ReceiptContext {
        let chain_id = self.cfg.chain.chain_id;
        let program_addr = self.chain.program_addr.clone();
        match self.cfg.chain.protocol_version {
            ProtocolVersion::V1_1 => {
                octravpn_core::receipt::ReceiptContext::v1_1(program_addr, chain_id)
            }
            ProtocolVersion::V2 => {
                let circle_id = match CircleState::load(&self.circle_state_path()) {
                    Ok(Some(s)) if !s.circle_id.is_empty() => {
                        Some(Address::from_display(&s.circle_id))
                    }
                    _ => None,
                };
                octravpn_core::receipt::ReceiptContext {
                    program_addr,
                    chain_id,
                    circle_id,
                }
            }
            ProtocolVersion::V3 => {
                // v3 receipt context binds the operator's configured
                // circle (the same one anchored on-chain via
                // register_circle). Fall back to None if the operator
                // hasn't filled it in yet — register_endpoint will
                // fail-fast at the next boot.
                let circle_id = self
                    .cfg
                    .chain
                    .circle_id
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(Address::from_display);
                octravpn_core::receipt::ReceiptContext {
                    program_addr,
                    chain_id,
                    circle_id,
                }
            }
        }
    }

    /// Assemble the v2 policy bundle from the live operator config.
    /// Clients fetch + decrypt this to learn endpoint + WG pubkey +
    /// tariffs without the data being readable on-chain.
    pub(super) fn build_policy_bundle(&self) -> PolicyBundle {
        let wg_pub_x25519 = X25519Pub::from(&self.wg_static_secret).to_bytes();
        PolicyBundle {
            endpoint: self.cfg.tunnel.public_endpoint.clone(),
            wg_pubkey_hex: hex::encode(wg_pub_x25519),
            region: self.cfg.pricing.region.clone(),
            price_per_mb_shared: self.cfg.pricing.shared_price(),
            price_per_mb_internal: self.cfg.pricing.internal_price(),
            attestation_ts: octravpn_core::util::now_unix_secs(),
            receipt_pubkey_b64: octravpn_core::b64::encode(self.wg_kp.public.0),
            hfhe_pubkey: self.hfhe_pubkey_placeholder(),
            schema_version: 1,
        }
    }
}
