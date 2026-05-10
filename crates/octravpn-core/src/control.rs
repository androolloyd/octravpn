//! HTTP control plane between client and exit node.
//!
//! For each session, the exit node exposes a small JSON-over-HTTP API
//! that the client uses to:
//!
//!   - announce a session (POST /session)
//!   - submit signed receipts (POST /session/{id}/receipt)
//!   - request the latest dual-signed receipt at settlement (GET ditto)
//!
//! We define request/response types here so the client and node share a
//! single canonical schema. The actual HTTP server lives in the node
//! crate; the client uses `reqwest` against the schema.

use serde::{Deserialize, Serialize};

use crate::{
    receipt::{Receipt, SignedReceipt},
    session::SessionId,
    sig::{PublicKey, Signature},
};

/// Path constants. Kept here so client + server can't drift.
pub const PATH_SESSION: &str = "/session";

pub fn path_receipt(session_id: &SessionId) -> String {
    format!("/session/{}/receipt", session_id.to_hex())
}

pub fn path_state(session_id: &SessionId) -> String {
    format!("/session/{}", session_id.to_hex())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceSessionRequest {
    pub session_id: SessionId,
    pub client_pubkey: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceSessionResponse {
    pub accepted: bool,
    pub node_pubkey: PublicKey,
}

/// Client-side half of a receipt: the client signs `Receipt` first; the
/// node co-signs and stores. The control-plane ingest endpoint takes
/// the client side and returns the dual-signed result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitReceiptRequest {
    pub receipt: Receipt,
    pub client_pubkey: PublicKey,
    pub client_sig: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitReceiptResponse {
    pub signed: SignedReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStateResponse {
    pub last_seq: u64,
    pub bytes_served: u64,
    pub latest: Option<SignedReceipt>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_consistent() {
        let id = SessionId([1u8; 32]);
        assert!(path_receipt(&id).contains(&id.to_hex()));
        assert!(path_state(&id).ends_with(&id.to_hex()));
    }
}
