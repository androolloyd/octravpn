//! `GET /session/:id` — the receipt-signing path. Reads `bytes_used`
//! from the onion router, atomically bumps the persistent
//! receipt-journal floor (P1-8/9), then signs. A crash between
//! journal-write and signature drops the proposal; the client retries.
//! When [`super::super::state::ShadowSigner`] is attached, the response
//! is amended with HFHE-2 shadow ciphertexts + zero-proof; without the
//! sidecar, the JSON wire shape stays byte-identical to pre-HFHE-2.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use octravpn_core::{
    control::{PostReceiptResponse, ProposedReceipt, SessionStateResponse},
    receipt::{Receipt, ReceiptError, SignedReceipt},
    receipt_vault::ReceiptVaultError,
    session::SessionId,
};

use super::ApiError;
use crate::control::state::ControlState;

/// HFHE-2: derive a per-receipt encryption seed (64-char hex) from
/// the (session_id_hex, seq) tuple. Deterministic — the auditor
/// who knows `(session_id, seq, circle_pk, circle_sk)` can
/// recompute the ciphertext byte-for-byte.
///
/// The label `octravpn-shadow-v1|` pins the domain so this seed
/// space never collides with any other use of `sha256(session_id
/// || seq)`.
pub(crate) fn shadow_seed_for(session_id_hex: &str, seq: u64) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"octravpn-shadow-v1|");
    h.update(session_id_hex.as_bytes());
    h.update(b"|");
    h.update(seq.to_be_bytes());
    hex::encode(h.finalize())
}

/// HFHE-2: split a parent shadow seed into a per-field subseed.
/// Cheap (one sha256). The label distinguishes `enc_bytes_used`
/// vs `enc_net` so the two ciphertexts on a single receipt are
/// never encrypted under the same randomness.
pub(crate) fn shadow_subseed(parent_hex: &str, label: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(parent_hex.as_bytes());
    h.update(b"|");
    h.update(label);
    hex::encode(h.finalize())
}

pub(crate) async fn get_state(
    State(s): State<Arc<ControlState>>,
    Path(id_hex): Path<String>,
) -> impl IntoResponse {
    s.metrics
        .state_lookups_total
        .fetch_add(1, Ordering::Relaxed);

    let Some(id) = SessionId::from_hex(&id_hex) else {
        return (StatusCode::BAD_REQUEST, Json(ApiError::new("bad id"))).into_response();
    };

    let bytes = s.router.bytes(&id).map_or(0, |(i, o)| i + o);

    let Some(entry) = s.sessions.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(ApiError::new("not announced"))).into_response();
    };

    // P1-8/9: consult the persistent journal floor BEFORE choosing a
    // seq. After a restart `entry.last_seq` resets to 0; but the
    // journal preserves the highest seq we ever signed for this
    // session. Pick a seq that is strictly greater than BOTH the
    // in-memory tracker and the persistent floor, then atomically
    // record it via `bump` (fsync inside) — only sign after the journal
    // is durable. A crash between the journal write and the signature
    // means we lose this proposal; the client retries with no harm.
    let journal_floor = s.receipt_journal.floor(&id);
    let next_seq = std::cmp::max(entry.last_seq, journal_floor) + 1;
    if let Err(e) = s.receipt_journal.bump(&id, next_seq) {
        // The only failure mode is `SeqNotMonotonic`, which would
        // mean another writer raced us. With the BoundedMap holding
        // per-session state in-process this should never trigger;
        // surface it loudly if it does so the operator notices the
        // race condition.
        tracing::warn!(error = %e, session = %id_hex, "receipt journal bump rejected; refusing to sign");
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new(
                "receipt seq floor violation; refusing to sign",
            )),
        )
            .into_response();
    }
    // Persist the in-memory tracker too so successive lookups within
    // this same boot pass advance monotonically. The journal alone
    // would also do this, but keeping the in-memory mirror saves a
    // disk read on every receipt fetch — the lock is held by `bump`
    // for the disk write, but `floor()` is a cheap mutex read.
    s.sessions.modify(&id, |cs| {
        cs.last_seq = next_seq;
    });

    let blind = entry.last_blind;
    let r = Receipt {
        context: (*s.receipt_context).clone(),
        session_id: id,
        seq: next_seq,
        bytes_used: bytes,
        blind,
    };
    let payload = r.signing_payload();
    let node_sig = s.node_kp.sign(&payload);
    s.metrics
        .receipts_signed_total
        .fetch_add(1, Ordering::Relaxed);
    // Fan out to SSE subscribers. Mirrors the metrics increment above —
    // any time we sign a receipt proposal, an observer downstream
    // (audit relay, settlement bot) gets a real-time notification.
    // Capture the scalar fields up front: `r` is moved into the
    // `ProposedReceipt` below, and `id` was already consumed by the
    // `Receipt` constructor, so we use the original `id_hex` path
    // parameter (which `SessionId::from_hex` already validated) as the
    // session identifier in the event.
    let event_seq = r.seq;
    let event_bytes = r.bytes_used;

    // HFHE-2 shadow-blob emission. Perf-4: pre-batching this path took
    // ~900 µs/receipt (3× separate IPC round-trips into the sidecar:
    // 2× encrypt_const @ ~200 µs + 1× make_zero_proof @ ~500 µs). After
    // batching it's a single `receipt_shadow` round-trip — same libpvac
    // math under the hood, ~400-500 µs less wire chatter per receipt.
    // The no-shadow path still skips it entirely. The deterministic
    // per-field seeds derived from `(session_id, seq)` are unchanged,
    // so the two ciphertexts stay byte-identical to what the legacy
    // three-call wiring produced — an auditor recomputing the blob
    // from plaintext + sk sees the same bytes. The zero-proof is
    // randomized internally (Bulletproofs pull fresh blinding per
    // call); the chain's verify-zero check is happy with any valid
    // proof under the same `(ct, amount, blinding)` triple. We do NOT
    // retry on sidecar transient errors; a failure emits the receipt
    // WITHOUT the shadow blob and logs a warning. The chain doesn't
    // verify the blob today — a missing blob is a soft degrade, not a
    // hard fail.
    let (enc_bytes_used, enc_net, pvac_zero_proof) = match s.shadow_signer.as_ref() {
        None => (None, None, None),
        Some(signer) => {
            let net = event_bytes.saturating_mul(s.shadow_price_per_byte);
            let seed = shadow_seed_for(&id_hex, event_seq);
            let seed_b = shadow_subseed(&seed, b"bytes");
            let seed_n = shadow_subseed(&seed, b"net");
            let blinding_b64 = octravpn_core::b64::encode(blind.as_bytes());
            match signer
                .pvac
                .receipt_shadow(
                    &signer.circle_pk,
                    &signer.circle_sk,
                    event_bytes,
                    net,
                    &seed_b,
                    &seed_n,
                    &blinding_b64,
                )
                .await
            {
                Ok(out) => (
                    Some(out.enc_bytes_used),
                    Some(out.enc_net),
                    Some(out.zero_proof),
                ),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "shadow receipt_shadow failed; emitting receipt without shadow blob",
                    );
                    (None, None, None)
                }
            }
        }
    };

    let proposed = ProposedReceipt {
        receipt: r,
        node_pubkey: s.node_kp.public,
        node_sig,
        enc_bytes_used,
        enc_net,
        pvac_zero_proof,
    };
    // Only build the SSE payload (a String + JSON map) when something is
    // actually subscribed — with no `/events` clients connected (the
    // common case) `publish` would allocate and immediately drop it.
    if s.events.receiver_count() > 0 {
        s.events.publish(crate::events::Event {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "receipt_signed".to_string(),
            payload: serde_json::json!({
                "session_id": id_hex.clone(),
                "seq": event_seq,
                "bytes_used": event_bytes,
            }),
        });
    }
    // Persist a structured audit row so `audit verify`'s cross-check
    // sees a `(session_id, seq)` pair for every signed receipt. The
    // SSE event above is in-process and ephemeral; the audit row is
    // durable and HMAC-chained, which is what the operator's
    // forensics path actually consults.
    if let Some(audit) = &s.audit {
        if let Err(e) = audit
            .record_receipt_signed(id_hex.clone(), event_seq, event_bytes)
            .await
        {
            tracing::warn!(error = %e, "audit log receipt_signed write failed");
        }
    }

    Json(SessionStateResponse {
        bytes_served: bytes,
        last_seq: entry.last_seq,
        proposed: Some(proposed),
    })
    .into_response()
}

pub(crate) async fn post_receipt(
    State(s): State<Arc<ControlState>>,
    Path(id_hex): Path<String>,
    Json(sr): Json<SignedReceipt>,
) -> impl IntoResponse {
    let Some(id) = SessionId::from_hex(&id_hex) else {
        return (StatusCode::BAD_REQUEST, Json(ApiError::new("bad id"))).into_response();
    };

    if let Err(e) = sr.verify() {
        let status = match e {
            ReceiptError::BadClientSig | ReceiptError::BadNodeSig => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        };
        return (status, Json(ApiError::new("bad receipt signature"))).into_response();
    }

    if sr.receipt.context != *s.receipt_context {
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new("receipt context mismatch")),
        )
            .into_response();
    }

    if sr.receipt.session_id.as_bytes() != id.as_bytes() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("receipt session id mismatch")),
        )
            .into_response();
    }

    if sr.node_pubkey != s.node_kp.public {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("receipt not signed by this node")),
        )
            .into_response();
    }

    let vault_floor = s.receipt_vault.current_seq(&id).unwrap_or(0);
    if sr.receipt.seq < vault_floor {
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new("receipt seq below vault floor")),
        )
            .into_response();
    }
    let journal_floor = s.receipt_journal.floor(&id);
    if sr.receipt.seq < journal_floor {
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new("receipt seq below journal floor")),
        )
            .into_response();
    }

    let settlement_hash = sr.settlement_hash();
    if let Err(e) = s.receipt_vault.put(&id, &sr) {
        tracing::warn!(error = %e, session = %id_hex, "receipt vault write failed");
        let status = match e {
            ReceiptVaultError::SeqRegressed { .. } => StatusCode::CONFLICT,
            ReceiptVaultError::SessionMismatch { .. } => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, Json(ApiError::new("receipt vault write failed"))).into_response();
    }

    if s.events.receiver_count() > 0 {
        s.events.publish(crate::events::Event {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "receipt_countersigned".to_string(),
            payload: serde_json::json!({
                "session_id": id_hex.clone(),
                "seq": sr.receipt.seq,
                "bytes_used": sr.receipt.bytes_used,
                "settlement_hash": settlement_hash.clone(),
            }),
        });
    }
    if let Some(audit) = &s.audit {
        let rec = crate::audit::AuditRecord {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "receipt_countersigned",
            source: None,
            session_id: Some(id_hex),
            extra: serde_json::json!({
                "seq": sr.receipt.seq,
                "bytes_used": sr.receipt.bytes_used,
                "settlement_hash": settlement_hash.clone(),
            }),
        };
        if let Err(e) = audit.write_async(rec).await {
            tracing::warn!(error = %e, "audit log receipt_countersigned write failed");
        }
    }

    Json(PostReceiptResponse {
        accepted: true,
        settlement_hash,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::handlers::session::announce;
    use crate::control::handlers::session::tests::signed_announce;
    use crate::control::metrics::NodeMetrics;
    use crate::control::state::ControlState;
    use crate::onion::OnionRouter;
    use octravpn_core::{
        bounded::BoundedMap,
        sig::{verify, KeyPair},
    };

    /// Helper for the journal-wiring tests: take the JSON body off a
    /// `Response` and deserialize it as a `SessionStateResponse`.
    /// Skips the empty-body 404 case by panicking — callers must only
    /// pass it a body that's expected to contain JSON.
    async fn parse_state(resp: axum::response::Response) -> SessionStateResponse {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "body = {body:?}");
        serde_json::from_slice::<SessionStateResponse>(&body).unwrap()
    }

    async fn parse_post_receipt(resp: axum::response::Response) -> PostReceiptResponse {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "body = {body:?}");
        serde_json::from_slice::<PostReceiptResponse>(&body).unwrap()
    }

    async fn status_and_body(resp: axum::response::Response) -> (StatusCode, String) {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn post_receipt_vaults_dual_signed_receipt_and_echoes_hash() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([0x77u8; 32]);
        let receipt = Receipt::new(
            (*state.receipt_context).clone(),
            id.clone(),
            1,
            4096,
            octravpn_core::session::Blind::new([0x88; 32]),
        );
        let signed = SignedReceipt::build(receipt, &client_kp, node_kp.as_ref());
        let want_hash = signed.settlement_hash();

        let resp = post_receipt(
            State(state.clone()),
            Path(id.to_hex()),
            Json(signed.clone()),
        )
        .await
        .into_response();
        let body = parse_post_receipt(resp).await;

        assert!(body.accepted);
        assert_eq!(body.settlement_hash, want_hash);
        assert_eq!(body.settlement_hash.len(), 64);
        assert_eq!(state.receipt_vault.get(&id), Some(signed));
    }

    #[tokio::test]
    async fn post_receipt_rejects_lower_seq_replay_and_keeps_latest() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([0x78u8; 32]);
        let latest = SignedReceipt::build(
            Receipt::new(
                (*state.receipt_context).clone(),
                id.clone(),
                5,
                5_000,
                octravpn_core::session::Blind::new([0x89; 32]),
            ),
            &client_kp,
            node_kp.as_ref(),
        );
        let latest_hash = latest.settlement_hash();
        parse_post_receipt(
            post_receipt(
                State(state.clone()),
                Path(id.to_hex()),
                Json(latest.clone()),
            )
            .await
            .into_response(),
        )
        .await;

        let replay = SignedReceipt::build(
            Receipt::new(
                (*state.receipt_context).clone(),
                id.clone(),
                4,
                9_999,
                octravpn_core::session::Blind::new([0x89; 32]),
            ),
            &client_kp,
            node_kp.as_ref(),
        );
        let (status, body) = status_and_body(
            post_receipt(State(state.clone()), Path(id.to_hex()), Json(replay))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT, "body = {body}");
        assert!(body.contains("receipt seq below vault floor"));
        let kept = state.receipt_vault.get(&id).unwrap();
        assert_eq!(kept.receipt.seq, 5);
        assert_eq!(kept.receipt.bytes_used, 5_000);
        assert_eq!(kept.settlement_hash(), latest_hash);
    }

    // Gap marker: v4 handback currently documents equal-seq POSTs as
    // idempotent retries, but a strict "cannot be re-accepted" guard
    // would need to reject this second request before any settlement
    // worker could treat the same receipt as fresh work.
    #[tokio::test]
    #[ignore = "current POST/vault path accepts equal-seq receipt handback as idempotent"]
    async fn post_receipt_rejects_equal_seq_replay_before_second_acceptance() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([0x79u8; 32]);
        let signed = SignedReceipt::build(
            Receipt::new(
                (*state.receipt_context).clone(),
                id.clone(),
                1,
                4_096,
                octravpn_core::session::Blind::new([0x8A; 32]),
            ),
            &client_kp,
            node_kp.as_ref(),
        );
        parse_post_receipt(
            post_receipt(
                State(state.clone()),
                Path(id.to_hex()),
                Json(signed.clone()),
            )
            .await
            .into_response(),
        )
        .await;

        let (status, body) = status_and_body(
            post_receipt(State(state), Path(id.to_hex()), Json(signed))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT, "body = {body}");
    }

    #[tokio::test]
    async fn post_receipt_rejects_swapped_node_signer_even_with_valid_dual_sig() {
        let node_kp = Arc::new(KeyPair::generate());
        let rogue_node_kp = KeyPair::generate();
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([0x7Au8; 32]);
        let forged = SignedReceipt::build(
            Receipt::new(
                (*state.receipt_context).clone(),
                id.clone(),
                1,
                4_096,
                octravpn_core::session::Blind::new([0x8B; 32]),
            ),
            &client_kp,
            &rogue_node_kp,
        );
        forged
            .verify()
            .expect("sanity: internally dual-signed by the swapped node key");
        assert_ne!(forged.node_pubkey, node_kp.public);

        let (status, body) = status_and_body(
            post_receipt(State(state.clone()), Path(id.to_hex()), Json(forged))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "body = {body}");
        assert!(body.contains("receipt not signed by this node"));
        assert!(state.receipt_vault.get(&id).is_none());
    }

    #[tokio::test]
    async fn post_receipt_rejects_cross_session_path_replay_before_vaulting() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let signed_id = SessionId::new([0x7Bu8; 32]);
        let path_id = SessionId::new([0x7Cu8; 32]);
        let signed = SignedReceipt::build(
            Receipt::new(
                (*state.receipt_context).clone(),
                signed_id.clone(),
                1,
                4_096,
                octravpn_core::session::Blind::new([0x8C; 32]),
            ),
            &client_kp,
            node_kp.as_ref(),
        );
        signed.verify().unwrap();

        let (status, body) = status_and_body(
            post_receipt(State(state.clone()), Path(path_id.to_hex()), Json(signed))
                .await
                .into_response(),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body = {body}");
        assert!(body.contains("receipt session id mismatch"));
        assert!(state.receipt_vault.get(&path_id).is_none());
        assert!(state.receipt_vault.get(&signed_id).is_none());
    }

    /// P1-8/9: a fresh session starts at journal floor 0; the first
    /// `/session/:id` returns a receipt at seq=1.
    #[tokio::test]
    async fn get_state_fresh_session_starts_at_seq_one() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x01u8; 32]);

        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;

        let resp = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        let sr = parse_state(resp).await;
        let proposed = sr.proposed.expect("proposal present");
        assert_eq!(proposed.receipt.seq, 1);
        assert_eq!(state.receipt_journal.floor(&id), 1);
    }

    /// P1-8/9 core: after the node has signed up to seq=K, an attacker
    /// who drops the in-memory state (BoundedMap reset → `last_seq=0`)
    /// MUST NOT be able to coax the node into signing a fresh seq=1.
    /// We simulate the in-memory reset by clearing the session entry
    /// out of `sessions` and re-announcing it. With the persistent
    /// journal in play, the next sign jumps to seq=K+1 (not seq=1).
    #[tokio::test]
    async fn get_state_restart_replay_rejected() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        // Use a real on-disk journal so the drop+reload simulates a
        // process restart.
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let journal =
            Arc::new(octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap());
        let metrics = Arc::new(NodeMetrics::default());
        metrics
            .started_at_unix
            .store(octravpn_core::util::now_unix_secs(), Ordering::Relaxed);
        // Tests bind a fixed v1.1 receipt context (test chain id) — the
        // hub builds the real one from node.toml at startup.
        let test_ctx = Arc::new(octravpn_core::receipt::ReceiptContext::v1_1(
            octravpn_core::address::Address::from_pubkey(&[0u8; 32]),
            octravpn_core::receipt::CHAIN_ID_TEST,
        ));
        let state = Arc::new(
            ControlState::with_metrics(
                node_kp.clone(),
                router.clone(),
                allowlist.clone(),
                metrics.clone(),
                test_ctx.clone(),
                journal,
            )
            .with_events_token(None),
        );
        let id = SessionId::new([0xABu8; 32]);

        // Sign three receipts (seq 1, 2, 3).
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        for expected_seq in 1..=3_u64 {
            let resp = get_state(State(state.clone()), Path(id.to_hex()))
                .await
                .into_response();
            let sr = parse_state(resp).await;
            assert_eq!(sr.proposed.unwrap().receipt.seq, expected_seq);
        }
        assert_eq!(state.receipt_journal.floor(&id), 3);

        // Simulate restart: drop the entire ControlState (and its
        // in-memory BoundedMap of sessions), then reopen the journal
        // from disk into a fresh state.
        drop(state);
        let journal2 =
            Arc::new(octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap());
        assert_eq!(
            journal2.floor(&id),
            3,
            "journal must persist across restart"
        );
        let state2 = Arc::new(
            ControlState::with_metrics(node_kp, router, allowlist, metrics, test_ctx, journal2)
                .with_events_token(None),
        );
        // The session has to be re-announced (announce inserts an
        // in-memory entry with last_seq=0). This is precisely the
        // scenario that used to let an attacker double-sign.
        announce(
            State(state2.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        // get_state must skip past the journal floor to seq=4, NOT
        // sign a fresh seq=1.
        let resp = get_state(State(state2.clone()), Path(id.to_hex()))
            .await
            .into_response();
        let sr = parse_state(resp).await;
        let proposed = sr.proposed.unwrap();
        assert_eq!(
            proposed.receipt.seq, 4,
            "post-restart seq must skip past the persistent floor"
        );
        assert_eq!(state2.receipt_journal.floor(&id), 4);
        // And the signature still verifies under the same node pubkey.
        let payload = proposed.receipt.signing_payload();
        verify(&proposed.node_pubkey, &payload, &proposed.node_sig).unwrap();
    }

    /// `get_state` after a fresh announce bumps both
    /// `state_lookups_total` and `receipts_signed_total` — confirms
    /// the pre-existing counters still fire after the audit-emission
    /// addition didn't reorder anything.
    #[tokio::test]
    async fn get_state_bumps_both_lookup_and_sign_counters() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x55u8; 32]);
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        let lookups_before = state.metrics.state_lookups_total.load(Ordering::Relaxed);
        let signed_before = state.metrics.receipts_signed_total.load(Ordering::Relaxed);
        let _ = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        assert_eq!(
            state.metrics.state_lookups_total.load(Ordering::Relaxed),
            lookups_before + 1
        );
        assert_eq!(
            state.metrics.receipts_signed_total.load(Ordering::Relaxed),
            signed_before + 1
        );
    }

    /// `get_state` emits a `receipt_signed` audit row carrying the
    /// freshly signed `(session_id, seq, bytes_used)` tuple. The
    /// HMAC-chained file is inspected via `AuditLog::verify_file`
    /// and then the raw lines are parsed to confirm the new entry's
    /// `extra.seq` matches the receipt's seq.
    #[tokio::test]
    async fn get_state_emits_receipt_signed_audit_row() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let dir = tempfile::tempdir().unwrap();
        let audit = crate::audit::AuditLog::open(dir.path()).unwrap();
        let state = Arc::new(ControlState::new(node_kp, router, allowlist).with_audit(audit));
        let id = SessionId::new([0x66u8; 32]);
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        let _ = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        // Drain to disk: the audit write is fired via
        // tokio::task::spawn_blocking; yield until the file has the
        // expected line count.
        for _ in 0..50 {
            let files: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                .map(|e| e.path())
                .collect();
            if let Some(p) = files.first() {
                let body = std::fs::read_to_string(p).unwrap();
                if body.lines().count() >= 2 {
                    // 2 lines = 1 announce + 1 receipt_signed.
                    assert!(body.contains("receipt_signed"));
                    assert!(body.contains("\\\"seq\\\":1"));
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("audit log never observed the receipt_signed row");
    }

    /// P1-8/9: the journal file is durable across the
    /// `ReceiptJournal::open` lifecycle — what the test above
    /// implicitly relies on, called out explicitly here. Bumping then
    /// reopening produces the same floor.
    #[tokio::test]
    async fn journal_file_is_durable_across_open() {
        use octravpn_core::receipt_journal::ReceiptJournal;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        let sess = SessionId::new([0x12u8; 32]);

        let j1 = ReceiptJournal::open(&path).unwrap();
        j1.bump(&sess, 99).unwrap();
        drop(j1);

        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&sess), 99);
    }

    // ====================================================================
    // HFHE-2 shadow-blob tests (control-plane integration).
    // ====================================================================

    #[test]
    fn shadow_seed_for_is_deterministic_per_session_and_seq() {
        let a = shadow_seed_for("abcd", 1);
        let b = shadow_seed_for("abcd", 1);
        let c = shadow_seed_for("abcd", 2);
        let d = shadow_seed_for("abce", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn shadow_subseed_differs_per_label() {
        let parent = shadow_seed_for("abcd", 7);
        let s1 = shadow_subseed(&parent, b"bytes");
        let s2 = shadow_subseed(&parent, b"net");
        let s1_again = shadow_subseed(&parent, b"bytes");
        assert_eq!(s1, s1_again);
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 64);
    }

    /// JSON serialisation of a `ProposedReceipt` with no shadow
    /// data does NOT mention the three new field names — the wire
    /// stays byte-identical to pre-HFHE-2 receipts.
    #[test]
    fn proposed_receipt_no_shadow_json_omits_fields() {
        let kp_n = KeyPair::generate();
        let r = octravpn_core::receipt::Receipt::new(
            octravpn_core::receipt::ReceiptContext::v1_1(
                octravpn_core::address::Address::from_pubkey(&[0u8; 32]),
                octravpn_core::receipt::CHAIN_ID_TEST,
            ),
            SessionId::new([1u8; 32]),
            1,
            100,
            octravpn_core::session::Blind::new([0u8; 32]),
        );
        let sig = kp_n.sign(&r.signing_payload());
        let p = octravpn_core::control::ProposedReceipt {
            receipt: r,
            node_pubkey: kp_n.public,
            node_sig: sig,
            enc_bytes_used: None,
            enc_net: None,
            pvac_zero_proof: None,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(!j.contains("enc_bytes_used"), "wire: {j}");
        assert!(!j.contains("enc_net"));
        assert!(!j.contains("pvac_zero_proof"));
    }
}
