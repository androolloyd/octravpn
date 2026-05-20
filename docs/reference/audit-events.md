<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# Audit-event kinds

Every audit-event `kind` the `octravpn-node` daemon emits to the HMAC-
chained NDJSON log at `audit/audit-YYYY-MM-DD.jsonl` (see
[state-files.md § Audit log](./state-files.md#audit-log)).

## Record envelope

Every line in the audit log decodes to:

```jsonc
{
  "ts_unix":   <u64>,                  // seconds since epoch
  "kind":      "<string>",             // see table below
  "session_id":"<hex64>" | null,       // optional; populated for session-scoped events
  "extra":     { … } | null,           // kind-specific payload
  "prev_hash": "<hex64>",              // HMAC of the previous record
  "hmac":      "<hex64>"               // HMAC over prev_hash || serialized_record
}
```

The HMAC is `HMAC_SHA256(audit_key, prev_hash || record_json)`. Verifier
reference: `crates/octravpn-node/src/audit.rs::AuditLog::verify_file`.

## Kind catalogue

The table below lists every kind the daemon currently writes, the
emitting source location, the Prometheus metric (if any) it bumps, the
analytics-indexer variant it maps to, and the Grafana panel the
operator tour points at.

| kind | Emitted by | Metric bumped | Analytics variant | Notes |
|---|---|---|---|---|
| `announce` | `control/handlers/session.rs:90`, `cli_ops.rs` | `octravpn_announces_total` | `SessionOpen` | Backwards-compat name; new code prefers `session_announced`. |
| `session_announced` | `control/handlers/session.rs:81` | `octravpn_announces_total` | `SessionOpen` | The structured replacement for `announce`. |
| `session_open` | (alias; daemon emits `announce`) | — | `SessionOpen` | Accepted by indexer for forward-compat. |
| `session_close` | session-eviction path (idle sweeper) | `octravpn_session_closes_total` | `SessionClose` | Bumped when a session is evicted by the idle sweep. |
| `receipt_signed` | `audit.rs:461`, `control/handlers/receipt.rs:211`, `cli_ops.rs` | `octravpn_receipts_signed_total` | `ReceiptSigned` | Every node-signed receipt. `extra.seq`, `extra.bytes_used` populated. |
| `settle_claim` | `chain.rs:235`, `cli/bond.rs` | `octravpn_session_opens_total` (via callsite) | `SettleClaim` | `extra.bytes_used` populated. |
| `preauth_mint` | `mesh_ops.rs`, `headscale_bridge/preauth.rs` | `octravpn_preauth_mints_total` | `PreauthMinted` | Older spelling; current code emits `preauth_minted` too. |
| `preauth_minted` | same | `octravpn_preauth_mints_total` | `PreauthMinted` | New spelling. |
| `preauth_redeem` | `headscale_bridge/preauth.rs` | `octravpn_preauth_redemptions_total` | `PreauthRedeemed` | Old spelling. |
| `preauth_redeemed` | same | `octravpn_preauth_redemptions_total` | `PreauthRedeemed` | New spelling. |
| `slash_double_sign` | `chain.rs` slash path, `commands/slash.rs` (client) | `octravpn_slash_double_sign_total` | `SlashDoubleSign` | One of the loudest events to alert on. |
| `validator_health_ok` | `hub/attestation.rs` | `octravpn_last_attestation_unix` (gauge) | `ValidatorHealthPing` | Periodic poll; gauge updated. |
| `validator_health_fail` | `hub/attestation.rs` | — | `ValidatorHealthPing` | Failed poll. Indexer rolls every `validator_health*` prefix into one variant. |
| `validator_health_ping` | `hub/attestation.rs` | — | `ValidatorHealthPing` | Pre-poll trace. |
| `lag` | `control/handlers/events.rs:39` | — | `Other` | SSE event-stream backpressure marker. |
| `journal_floor` | `audit_cli.rs:383` | — | `Other` | Synthetic kind emitted by `receipt-verify`'s output (NOT the daemon's audit log). |
| `before` / `after` / `after_overflow` / `spam` | `events.rs:89, 98, 134, 157` | — | `Other` | SSE rate-limit / overflow markers. |
| `get_state` | `audit.rs:727` test path | — | `Other` | Emitted by `GET /session/:id`; analytics ignores. |

**Analytics indexer roll-up.** The indexer's
`AnalyticsEvent::from_audit_record_json`
(`crates/octravpn-analytics/src/event.rs:99`) maps the strings above into
its typed enum. Any unrecognised `kind` collapses to
`AnalyticsEvent::Other { kind }` so the indexer can count it under
`events_total{kind="other"}` without a recompile.

**Validator-health prefix matching.** Any kind starting with
`validator_health` matches the `ValidatorHealthPing` variant — operators
can add `validator_health_<whatever>` sub-events without touching the
analytics crate.

---

## Per-kind details

### `announce` / `session_announced`

* **Trigger.** `POST /session/announce` on the control plane —
  `crates/octravpn-node/src/control/handlers/session.rs:71-99`.
* **JSON shape (extra).** `null` (the session id is in `session_id`).
* **Metric.** `octravpn_announces_total`.
* **Grafana panel.** Operator tour §observability — "Sessions
  announced".
* **Verifier impact.** Triggers `IndexerState::ingest` to count a
  `SessionOpen` in `sessions_opened`.

### `receipt_signed`

* **Trigger.** Every successful receipt signature — the node consults
  `receipts.bin`, increments the seq monotonically, and emits this
  event before returning the signed bytes. Source `audit.rs:461`,
  `control/handlers/receipt.rs:211`.
* **`extra`.** `{ seq: u64, bytes_used: u64 }`.
* **Metric.** `octravpn_receipts_signed_total`.
* **Analytics.** `ReceiptSigned { ts_unix, session_id, seq, bytes_used }`.
  The indexer folds `bytes_used` as a *delta* per session id (it is a
  monotonic high-watermark; naive summing over-counts).

### `settle_claim`

* **Trigger.** `settle_claim` tx submission — `chain.rs:235` (v1/v2),
  `v3_calls.rs:714` (v3).
* **`extra`.** `{ bytes_used: u64 }`.
* **Operator significance.** This is the equivocation surface. If two
  `settle_claim` events appear for the same `session_id` with different
  `bytes_used`, the chain will slash. The local receipt journal
  prevents this across restarts, but operators who edit `state/receipts.bin`
  by hand can lose this protection.

### `preauth_mint` / `preauth_redeem`

* **Trigger.** Tailscale-bridge preauth key lifecycle —
  `crates/octravpn-mesh/src/headscale_bridge/preauth.rs`. Mint events
  fire when `mesh mint-preauth` or the embedded headscale
  `preauthkeys create` succeeds. Redeem events fire when a node
  registers with a previously-minted key.
* **`extra`.** None today. Future work may add `{ user, ttl, reusable }`.
* **Metrics.** `octravpn_preauth_mints_total` (counter),
  `octravpn_preauth_redemptions_total` (counter).
* **Alerting.** A spike in redeems with no matching mints suggests
  preauth-key reuse outside the supervised mint surface — operator
  should rotate immediately.

### `slash_double_sign`

* **Trigger.** Caller submitted `slash_double_sign(circle, …)` —
  `crates/octravpn-client/src/commands/slash.rs:324` for client-initiated
  submissions, `v3_calls.rs:595` for the v3 builder.
* **`extra`.** None (the evidence blob is too large for the audit log;
  it's stored separately).
* **Metric.** `octravpn_slash_double_sign_total`.
* **Alerting.** **Page-the-operator** event. Either someone else slashed
  this node (loss of bond), or this node slashed someone else (10%
  bounty earned). Either way, page.

### `validator_health_ok` / `validator_health_fail`

* **Trigger.** Periodic poll loop in `hub/attestation.rs`. Interval is
  `[attestation].poll_interval_secs` (default 30s).
* **`extra`.** `{ "addr": "oct…", "is_validator": bool }`.
* **Metric (ok).** `octravpn_last_attestation_unix` gauge updated.
* **Metric (fail).** No counter; alert on
  `time() - octravpn_last_attestation_unix > 120s` instead.

### `lag` / `before` / `after` / `after_overflow` / `spam`

These are SSE rate-limit observability markers — see
`crates/octravpn-node/src/events.rs:89-160`. They mainly help debug
fast-emitting clients on the `/events` stream. The analytics indexer
ignores them.

### `journal_floor`

A synthetic kind emitted to **stdout** by `octravpn-node receipt-verify`
(`audit_cli.rs:383`) — NOT to the audit log. Documented here because it
shows up in operator-facing JSON output and analysts may grep for it.

---

## Adding a new kind

1. Pick a snake_case string. Prefer the `<noun>_<verb>` shape
   (`session_close`, `preauth_minted`).
2. Emit via `AuditLog::write` with the kind, optional `session_id`,
   and `extra` payload.
3. Add a row to the table in this file and the `from_audit_record_json`
   match arm in `crates/octravpn-analytics/src/event.rs` (or leave it
   to roll up into `Other` for now).
4. Add a Prometheus counter in
   `crates/octravpn-node/src/control/metrics.rs` if the kind warrants a
   dashboard panel; bump it in the emit site.

The schema is intentionally additive — older verifiers parse unknown
kinds fine because the chain HMAC is over the verbatim JSON record.

---

## Cross-references

* Verifier subcommands: [`audit verify` / `audit replay` / `audit-tail` / `receipt-verify`](./cli-octravpn-node.md#audit).
* On-disk file format: [state-files.md § Audit log](./state-files.md#audit-log).
* Prometheus metric definitions: [metrics.md](./metrics.md).
* Analytics indexer code: `crates/octravpn-analytics/src/`.
* Audit-log API: `crates/octravpn-node/src/audit.rs`.
