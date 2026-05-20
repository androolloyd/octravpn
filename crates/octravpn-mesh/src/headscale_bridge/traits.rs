//! Wire-bridge trait impls.
//!
//! Bridge between OctraVPN's mesh-side types
//! ([`super::preauth::PreauthMinter`], [`crate::ip_alloc::TailnetIpAllocator`])
//! and the headscale-rs Tailscale wire-protocol layer
//! (`headscale_api::tailscale_wire::{PreauthRedeemer, IpAllocator}`).
//!
//! As of 2026-05-19 the Tailscale wire-protocol implementation lives in
//! `headscale-api::tailscale_wire`. The wire layer parameterises on two
//! small traits (`PreauthRedeemer`, `IpAllocator`) so headscale-rs can
//! stay free of OctraVPN-specific policy. This module is the only place
//! those traits meet OctraVPN's mesh-side types.

use std::net::Ipv4Addr;

use async_trait::async_trait;
use headscale_api::tailscale_wire::{
    AllocError, IpAllocator, PreauthRedeemer, RedeemError as WireRedeemError,
};

use crate::ip_alloc::TailnetIpAllocator;

use super::preauth::{PreauthMinter, RedeemError};

/// Adapter: wrap a `PreauthMinter` so it can be handed to
/// `headscale_api::tailscale_wire::WireState.preauth` as an
/// `Arc<dyn PreauthRedeemer>`.
#[async_trait]
impl PreauthRedeemer for PreauthMinter {
    async fn redeem(
        &self,
        key: &str,
    ) -> Result<headscale_api::tailscale_wire::RedeemOk, WireRedeemError> {
        // Synchronous redeem under the hood; the async signature is for
        // future-proofing on the wire side. We translate OctraVPN's
        // RedeemError into the wire crate's identical-shape enum.
        //
        // Upstream `PreauthRedeemer::redeem` returns a `RedeemOk` carrying
        // the bound user plus optional ephemeral/tags flags (#239+). We
        // only know the user here — the wire crate's
        // `From<String> for RedeemOk` builds the rest with empty defaults.
        match Self::redeem(self, key) {
            Ok(user) => Ok(user.into()),
            Err(RedeemError::Unknown) => Err(WireRedeemError::Unknown),
            Err(RedeemError::Expired) => Err(WireRedeemError::Expired),
        }
    }
}

/// Adapter: wrap a `TailnetIpAllocator` so it can be handed to
/// `headscale_api::tailscale_wire::WireState.ip_allocator` as an
/// `Arc<dyn IpAllocator>`.
impl IpAllocator for TailnetIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        // OctraVPN's allocator is infallible (deterministic hash into
        // CGNAT /10), so the bridge never produces an `AllocError`.
        Ok(Self::allocate(self, node_key_hex))
    }
}
