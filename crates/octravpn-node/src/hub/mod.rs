//! Central node coordinator. Owns the chain client, control-plane HTTP
//! server, receipt store, onion router, and tunnel server, and exposes
//! the high-level operations the `main` binary calls into.
//!
//! # Module layout
//!
//! `hub.rs` was previously a single ~1500-line file that every new
//! subsystem appended to at boot. It is now a directory module. The
//! split is **structural only** — `Hub`, `Hub::new`, `Hub::pvac`,
//! `Hub::open_audit_log`, and every `pub(crate)` op reached from
//! `main.rs` are identical to the pre-split form.
//!
//! ```text
//!   hub/
//!   ├── mod.rs        struct Hub + the four primary lifecycle methods
//!   ├── boot.rs       Hub::new internals (key load + chain ctx +
//!   │                 journal + allowlist + metrics + PVAC spawn)
//!   ├── identity.rs   print_identity + wallet_view_pubkey
//!   ├── pvac.rs       build_shadow_signer + build_receipt_context +
//!   │                 build_policy_bundle (boundary helpers)
//!   ├── attestation.rs register_endpoint variants, bond/unbond/settle,
//!   │                 claim_earnings, validator-health loop, hfhe
//!   │                 placeholders, local accumulator
//!   └── spawn.rs      spawn_tunnel + spawn_control_plane (the
//!                     historically god-sized closures)
//! ```
//!
//! To add a new subsystem, see `SUBSYSTEM_CHECKLIST.md` next to this
//! file — five canonical touch points (config, hub field, spawn fn,
//! route mount, audit emit). Cross-module reaches use `super::` or
//! `crate::hub::sub::*`, never absolute paths.

use std::sync::Arc;

use anyhow::Result;
use octravpn_core::sig::KeyPair;
use x25519_dalek::StaticSecret;

use crate::{
    chain::ChainCtx, chain_v2::ChainCtxV2, chain_v3::ChainCtxV3, config::NodeConfig,
    onion::OnionRouter,
};

mod attestation;
mod boot;
mod identity;
mod pvac;
mod relay;
mod spawn;

pub(crate) struct Hub {
    pub cfg: NodeConfig,
    pub chain: ChainCtx,
    /// v2 chain context. Always constructed (the wallet secret + RPC
    /// endpoint are the same as v1.1), but only USED when
    /// `cfg.chain.protocol_version == V2`. Holds the v2 program
    /// address + a duplicate of the wallet keypair derived from the
    /// same secret-on-disk so both flows can sign independently
    /// without sharing state.
    pub chain_v2: ChainCtxV2,
    /// v3 chain context. Same RPC + program address as v1.1 / v2 (the
    /// chain is the same Octra chain; only the AML on the configured
    /// `program_addr` differs across versions). Constructed
    /// unconditionally so identity / diagnostic subcommands have it
    /// available, but only consulted when
    /// `cfg.chain.protocol_version == V3`.
    pub chain_v3: ChainCtxV3,
    pub wg_kp: Arc<KeyPair>,
    pub wg_static_secret: StaticSecret,
    pub view_pubkey: [u8; 32],
    pub router: Arc<OnionRouter>,
    /// Pubkeys whitelisted via control-plane `announce`. The tunnel
    /// server consults this map before instantiating a `Tunn` for an
    /// arriving UDP source.
    pub allowlist: Arc<octravpn_core::bounded::BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
    /// Shared metrics surface — both the attestation loop and the
    /// control plane write to this so /health reports real freshness.
    pub metrics: Arc<crate::control::NodeMetrics>,
    /// P1-8/9 persistent receipt journal. Opened once at boot so a
    /// bad path (permission denied, magic-mismatch on an existing
    /// file) fails-fast rather than at the first receipt request.
    /// Shared with the control plane via an Arc — every `get_state`
    /// call consults this before signing.
    pub receipt_journal: Arc<octravpn_core::receipt_journal::ReceiptJournal>,
    /// v4 relay-settlement receipt vault. Stores variable-length
    /// `SignedReceipt` JSON blobs posted back by clients, independently
    /// of the fixed-width receipt journal above.
    pub receipt_vault: Arc<octravpn_core::receipt_vault::ReceiptVault>,
    /// Managed `octra-pvac-sidecar` subprocess for the HFHE path.
    /// `Some` iff `cfg.pvac.enabled = true` AND
    /// `PvacClient::spawn` succeeded at boot. If the operator enabled
    /// `[pvac]` but the binary path doesn't resolve, this is `None`
    /// and the node continues without HFHE — boot does NOT fail. See
    /// `Hub::pvac` for the surfacing accessor used by the v3 settle
    /// path and the headscale bridge.
    #[allow(dead_code)]
    // consumed by v3_calls + headscale_bridge once HFHE rewires off placeholders
    pub pvac: Option<Arc<crate::pvac::PvacClient>>,
    /// Perf-10: pluggable WireGuard peer-administration backend.
    /// Chosen at boot via [`crate::tunnel::backend::select_backend`].
    /// `auto` (default) picks boringtun because the onion-peel data
    /// plane binds the listen port. `kernel` requires Linux + the
    /// `wireguard` kernel module + `CAP_NET_ADMIN`. See
    /// `docs/operators/wireguard-backend.md`.
    #[allow(dead_code)] // consumed by future control-plane peer admin
    pub wg_backend: Arc<dyn crate::tunnel::backend::WgBackend>,
    /// Diagnostic record of which backend was chosen and why. Surfaced
    /// in `/health` so operators can verify the pick without re-reading
    /// the boot logs.
    #[allow(dead_code)]
    pub wg_backend_selection: crate::tunnel::backend::BackendSelection,
}

impl Hub {
    /// Construct the hub from a parsed node config. See
    /// [`boot::build_hub`] for the layered boot sequence (key load →
    /// chain ctx → journal → metrics → optional PVAC).
    pub(crate) async fn new(cfg: NodeConfig) -> Result<Self> {
        boot::build_hub(cfg).await
    }

    /// Accessor for the managed PVAC sidecar. Returns `None` when the
    /// operator has not enabled the `[pvac]` block, or when the
    /// subprocess failed to spawn at boot. Callers in the v3 settle
    /// path and `octravpn-mesh::headscale_bridge` consult this before
    /// touching the HFHE path.
    #[allow(dead_code)] // surface for v3 settle + headscale_bridge consumers (forthcoming)
    pub(crate) fn pvac(&self) -> Option<&Arc<crate::pvac::PvacClient>> {
        self.pvac.as_ref()
    }

    /// Open the audit log configured for this hub (or return `None`
    /// if no `audit_dir` is set). Used by the `verify-audit-log`
    /// subcommand to access the HMAC key for offline verification.
    pub(crate) fn open_audit_log(&self) -> Option<crate::audit::AuditLog> {
        let dir = self.cfg.control.audit_dir.as_ref()?;
        crate::audit::AuditLog::open(dir).ok()
    }
}
