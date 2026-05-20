//! HTTP control plane between client and exit node.
//!
//! Endpoints:
//!
//!   POST /session            — client announces a session, declaring its
//!                               session pubkey to the exit node.
//!   GET  /session/{id}       — returns the exit's current view of the
//!                               session: bytes_served, last seq, and an
//!                               *exit-only* signed proposal of the next
//!                               receipt the client can countersign.
//!
//! Settlement: the client calls GET, takes the proposed receipt, signs it
//! with its session key, and submits the dual-signed payload to chain.

use serde::{Deserialize, Serialize};

use crate::{
    receipt::Receipt,
    session::SessionId,
    sig::{PublicKey, Signature},
};

pub fn path_state(session_id: &SessionId) -> String {
    format!("/session/{}", session_id.to_hex())
}

/// Convention: WG endpoint is `host:51820`; HTTP control plane lives at
/// the same host on port 51821. Centralized here so client + node never
/// disagree on the convention.
pub const CONTROL_PORT: u16 = 51821;

pub fn base_url_for(wg_endpoint: &str) -> String {
    let host = wg_endpoint.rsplit_once(':').map_or(wg_endpoint, |(h, _)| h);
    format!("http://{host}:{CONTROL_PORT}")
}

/// Full URL for the per-session state endpoint on a node.
pub fn session_state_url(wg_endpoint: &str, session_id: &SessionId) -> String {
    format!("{}{}", base_url_for(wg_endpoint), path_state(session_id))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceSessionRequest {
    pub session_id: SessionId,
    /// Ephemeral session pubkey the client signs receipts with.
    pub client_pubkey: PublicKey,
    /// X25519 static pubkey the client uses for the WG handshake against
    /// the entry hop. Without this the entry hop can't construct a
    /// valid `Tunn` peer state and the WG handshake never completes.
    pub client_wg_pubkey: [u8; 32],
    /// Chain transaction hash that emitted the `SessionOpened` event
    /// for `session_id`.
    pub open_tx_hash: String,
    /// Signature over the announce envelope using `client_pubkey`.
    pub client_sig: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceSessionResponse {
    pub accepted: bool,
    pub node_pubkey: PublicKey,
}

/// Build the deterministic payload clients sign when announcing a
/// chain-opened session to an exit node.
pub fn announce_signing_payload(
    session_id: &SessionId,
    client_pubkey: &PublicKey,
    client_wg_pubkey: &[u8; 32],
    open_tx_hash: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + 32 + 32 + 32 + 4 + open_tx_hash.len());
    out.extend_from_slice(b"octravpn:announce:v1");
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(&client_pubkey.0);
    out.extend_from_slice(client_wg_pubkey);
    out.extend_from_slice(&(open_tx_hash.len() as u32).to_be_bytes());
    out.extend_from_slice(open_tx_hash.as_bytes());
    out
}

/// Exit-side view of a session, including the exit's signed receipt
/// proposal. The client takes the (Receipt, node_sig) pair and adds its
/// own signature at settlement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStateResponse {
    pub bytes_served: u64,
    pub last_seq: u64,
    pub proposed: Option<ProposedReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposedReceipt {
    pub receipt: Receipt,
    pub node_pubkey: PublicKey,
    pub node_sig: Signature,
    /// HFHE-2 shadow blob (encrypted `bytes_used`). Optional;
    /// `None` when the operator's PVAC sidecar is disabled or the
    /// circle pubkey is unloaded. Wire-compatible with pre-HFHE-2
    /// receipts via `#[serde(default, skip_serializing_if=...)]`.
    /// See `octravpn_core::receipt::SignedReceipt` for the full
    /// shadow-blob contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_bytes_used: Option<String>,
    /// HFHE-2 shadow blob (encrypted `net = bytes_used * price`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_net: Option<String>,
    /// HFHE-2 zero-proof (`zkzp_v2|<b64>`) — optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pvac_zero_proof: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_consistent() {
        let id = SessionId::new([1u8; 32]);
        assert!(path_state(&id).ends_with(&id.to_hex()));
    }
}
