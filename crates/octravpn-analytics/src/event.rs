//! Analytics-only event mirror.
//!
//! `AnalyticsEvent` is a closed enum the indexer consumes — it is
//! **not** the on-disk audit record. The audit log's `AuditRecord` has
//! `kind: &'static str`, which means the schema is stringly-typed and
//! evolves additively. The indexer wants a typed view so it can match
//! on the kind without worrying about typos.
//!
//! The conversion from raw audit JSON to `AnalyticsEvent` lives in
//! [`AnalyticsEvent::from_audit_record_json`]. Unknown kinds collapse
//! to `AnalyticsEvent::Other { kind }` so we can count "total events
//! ingested" without needing a node-side recompile when a new audit
//! kind appears.
//!
//! ## Why not just deserialize the audit record verbatim?
//!
//! Two reasons:
//!
//! 1. The audit module is `pub(crate)` in `octravpn-node`, so this
//!    crate can't import the `AuditRecord` type directly.
//! 2. The task spec (#231) explicitly forbids modifying the audit
//!    enum schema; the mirror lets us add analytics-only fields later
//!    without churning the on-disk format.
//!
//! ## Bytes-settled accounting
//!
//! `ReceiptSigned.bytes_used` is the per-receipt high-watermark of
//! bytes consumed in a session — it is **monotonic** within a session
//! id, so naively summing every `bytes_used` over-counts. The indexer
//! tracks `(session_id, last_bytes_used)` to fold each receipt into a
//! *delta* before bumping the `bytes_settled` counter. See
//! `IndexerState::ingest`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One audit-log event projected into the analytics domain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnalyticsEvent {
    /// A new session was announced / opened on the control plane.
    SessionOpen { ts_unix: u64, session_id: String },
    /// A session was evicted (idle sweep) or otherwise closed.
    SessionClose { ts_unix: u64, session_id: String },
    /// `settle_claim` was dispatched on chain.
    SettleClaim {
        ts_unix: u64,
        session_id: Option<String>,
        bytes_used: u64,
    },
    /// A receipt was signed by this node.
    ReceiptSigned {
        ts_unix: u64,
        session_id: String,
        seq: u64,
        bytes_used: u64,
    },
    /// A Tailscale-bridge preauth key was minted.
    PreauthMinted { ts_unix: u64 },
    /// A Tailscale-bridge preauth key was redeemed.
    PreauthRedeemed { ts_unix: u64 },
    /// `slash_double_sign` was dispatched on chain.
    SlashDoubleSign { ts_unix: u64 },
    /// A validator-health ping landed (any sub-kind: ping/ok/fail).
    ValidatorHealthPing { ts_unix: u64 },
    /// Anything we don't know how to count — counted in
    /// `events_total{kind="other"}` for ops sanity.
    Other { ts_unix: u64, kind: String },
}

impl AnalyticsEvent {
    /// Unix timestamp of the event.
    #[must_use]
    pub fn ts_unix(&self) -> u64 {
        match self {
            Self::SessionOpen { ts_unix, .. }
            | Self::SessionClose { ts_unix, .. }
            | Self::SettleClaim { ts_unix, .. }
            | Self::ReceiptSigned { ts_unix, .. }
            | Self::PreauthMinted { ts_unix }
            | Self::PreauthRedeemed { ts_unix }
            | Self::SlashDoubleSign { ts_unix }
            | Self::ValidatorHealthPing { ts_unix }
            | Self::Other { ts_unix, .. } => *ts_unix,
        }
    }

    /// Convert a canonical audit `record_json` (the inner string inside
    /// the chained envelope) into an `AnalyticsEvent`. Returns `None`
    /// if the JSON doesn't look like an `AuditRecord` (no `kind`
    /// field).
    ///
    /// The kind-string -> variant mapping is intentionally lenient:
    /// any kind starting with `validator_health` rolls into
    /// `ValidatorHealthPing` so we don't need to enumerate every
    /// sub-event the node may emit in the future.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_audit_record_json(json: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(json).ok()?;
        let ts_unix = v.get("ts_unix").and_then(Value::as_u64)?;
        let kind = v.get("kind").and_then(Value::as_str)?;
        let session_id = v
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let extra = v.get("extra");
        let extra_u64 =
            |k: &str| extra.and_then(|e| e.get(k)).and_then(Value::as_u64);

        let ev = match kind {
            // Audit emits "announce" today for session announcements;
            // task spec also requests "session_open". We accept both.
            "announce" | "session_open" | "session_announced" => Self::SessionOpen {
                ts_unix,
                session_id: session_id.unwrap_or_default(),
            },
            "session_close" => Self::SessionClose {
                ts_unix,
                session_id: session_id.unwrap_or_default(),
            },
            "settle_claim" => Self::SettleClaim {
                ts_unix,
                session_id,
                bytes_used: extra_u64("bytes_used").unwrap_or(0),
            },
            "receipt_signed" => Self::ReceiptSigned {
                ts_unix,
                session_id: session_id.unwrap_or_default(),
                seq: extra_u64("seq").unwrap_or(0),
                bytes_used: extra_u64("bytes_used").unwrap_or(0),
            },
            "preauth_mint" | "preauth_minted" => Self::PreauthMinted { ts_unix },
            "preauth_redeem" | "preauth_redeemed" => Self::PreauthRedeemed { ts_unix },
            "slash_double_sign" => Self::SlashDoubleSign { ts_unix },
            k if k.starts_with("validator_health") => Self::ValidatorHealthPing { ts_unix },
            k => Self::Other {
                ts_unix,
                kind: k.to_string(),
            },
        };
        Some(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_kinds_to_typed_variants() {
        let j = r#"{"ts_unix":100,"kind":"receipt_signed","session_id":"abc","extra":{"seq":7,"bytes_used":1024}}"#;
        let ev = AnalyticsEvent::from_audit_record_json(j).unwrap();
        assert!(matches!(
            ev,
            AnalyticsEvent::ReceiptSigned { ts_unix: 100, seq: 7, bytes_used: 1024, ref session_id }
                if session_id == "abc"
        ));
    }

    #[test]
    fn announce_maps_to_session_open() {
        let j = r#"{"ts_unix":50,"kind":"announce","session_id":"s1","extra":null}"#;
        match AnalyticsEvent::from_audit_record_json(j).unwrap() {
            AnalyticsEvent::SessionOpen { ts_unix, session_id } => {
                assert_eq!(ts_unix, 50);
                assert_eq!(session_id, "s1");
            }
            other => panic!("expected SessionOpen, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_falls_back_to_other() {
        let j = r#"{"ts_unix":1,"kind":"some_future_event","session_id":null,"extra":null}"#;
        match AnalyticsEvent::from_audit_record_json(j).unwrap() {
            AnalyticsEvent::Other { kind, .. } => assert_eq!(kind, "some_future_event"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn validator_health_prefix_is_lenient() {
        for k in &["validator_health", "validator_health_ok", "validator_health_fail"] {
            let j = format!(
                r#"{{"ts_unix":1,"kind":"{k}","session_id":null,"extra":null}}"#
            );
            assert!(matches!(
                AnalyticsEvent::from_audit_record_json(&j).unwrap(),
                AnalyticsEvent::ValidatorHealthPing { .. }
            ));
        }
    }

    #[test]
    fn missing_required_fields_returns_none() {
        // No `kind`.
        let j = r#"{"ts_unix":1}"#;
        assert!(AnalyticsEvent::from_audit_record_json(j).is_none());
        // No `ts_unix`.
        let j = r#"{"kind":"announce"}"#;
        assert!(AnalyticsEvent::from_audit_record_json(j).is_none());
    }
}
