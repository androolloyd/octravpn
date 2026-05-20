<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# Prometheus metrics

Every metric the OctraVPN daemons expose. Two endpoints, two metric
namespaces:

| Endpoint | Source | Namespace | Surface |
|---|---|---|---|
| `GET /metrics` on `[control].listen` | `crates/octravpn-node/src/control/handlers/metrics.rs` | `octravpn_*` | The core operator daemon counters. Bearer-gated by `[control].metrics_token`. |
| `GET /metrics` on `[analytics].listen_addr` | `crates/octravpn-analytics/src/http.rs` | `octravpn_analytics_*` | The #231 historical indexer. Bearer-gated by `[analytics].bearer_token`. |
| `GET /analytics/series` on `[analytics].listen_addr` | same | (JSON, not Prom-text) | Time-series query surface. |

Both endpoints return 503 when the bearer token is unset (clear
"endpoint disabled" rather than open exposure).

---

## Core daemon metrics (`/metrics` on the control plane)

Source: `control/handlers/metrics.rs:47-129`. All counters/gauges are
`std::sync::atomic::AtomicU64` inside
`crate::control::metrics::NodeMetrics`; the handler is a single
`format!` over the snapshot.

| Metric | Type | Labels | Bumped by | Healthy range | Alert template |
|---|---|---|---|---|---|
| `octravpn_announces_total` | counter | none | `POST /session/announce` (`control/handlers/session.rs:91`) | Steady; should track expected session opens | `rate(octravpn_announces_total[5m]) == 0` for >30m on a busy node |
| `octravpn_state_lookups_total` | counter | none | `GET /session/:id` | Steady | — |
| `octravpn_receipts_signed_total` | counter | none | `POST /session/:id/receipt` (`control/handlers/receipt.rs`) | Should track announces × (avg seq) | `rate(octravpn_receipts_signed_total[5m]) == 0` when announces > 0 |
| `octravpn_bytes_served_total` | counter | none | Onion forwarding path (`onion.rs:23`) | Throughput-dependent | — |
| `octravpn_active_sessions` | gauge | none | `len(sessions)` snapshot | < `session_capacity` | `octravpn_active_sessions / on() octravpn_session_capacity > 0.9` |
| `octravpn_last_attestation_unix` | gauge | none | Attestation poll loop (`hub/attestation.rs`) | Now − this < 2 × `[attestation].poll_interval_secs` | `time() - octravpn_last_attestation_unix > 120` |
| `octravpn_uptime_seconds` | counter | none | Derived from `started_at_unix` at scrape time | Monotonic, resets on restart | spike of resets ⇒ daemon flapping |
| `octravpn_slash_double_sign_total` | counter | none | `slash_double_sign` tx dispatched (`chain.rs`, `commands/slash.rs`) | **0** under normal operation | `increase(octravpn_slash_double_sign_total[1h]) > 0` — **PAGE** |
| `octravpn_preauth_mints_total` | counter | none | `PreauthMinter::mint` | Tracks join cadence | — |
| `octravpn_preauth_redemptions_total` | counter | none | `PreauthMinter::redeem` success | Tracks join cadence | — |
| `octravpn_rpc_requests_total` | counter | none | Every `RpcClient::call` | Steady | — |
| `octravpn_rpc_errors_total` | counter | none | RPC failure path | ratio `errors/requests < 0.01` | `rate(octravpn_rpc_errors_total[5m]) / rate(octravpn_rpc_requests_total[5m]) > 0.05` |
| `octravpn_wg_handshake_success_total` | counter | none | WG datapath completion | Steady | — |
| `octravpn_wg_handshake_fail_total` | counter | none | WG decapsulation error | ratio fail/(fail+success) < 0.1 | `rate(octravpn_wg_handshake_fail_total[5m]) > 1` |
| `octravpn_session_opens_total` | counter | none | `POST /session` accepted | Tracks `announces_total` | — |
| `octravpn_session_closes_total` | counter | none | Idle sweeper eviction | Approximately equals opens minus active | — |
| `octravpn_session_no_shows_total` | counter | none | Sessions ended without a client countersign | Low; spike ⇒ network or client issue | `increase(octravpn_session_no_shows_total[5m]) > 5` |
| `octravpn_tailnet_member_count` | gauge | none | Tailscale-wire bridge member list size | Equals roster size | — |
| `octravpn_ip_allocator_used` | gauge | none | CGNAT allocator counter | < capacity | `octravpn_ip_allocator_used / octravpn_ip_allocator_capacity > 0.9` |
| `octravpn_ip_allocator_capacity` | gauge | none | Static host-range capacity | Constant per build | — |
| `octravpn_started_at_unix` | gauge | none | Set once at boot | Constant per process lifetime | resets indicate restarts |

**Total core metrics: 21.**

Source pin test: `metrics::tests::metrics_handler_emits_every_new_field`
(`control/handlers/metrics.rs:202-241`) verifies every line above
appears in the rendered body.

---

## Analytics indexer metrics (`/metrics` on the analytics plane)

Source: `crates/octravpn-analytics/src/http.rs:121-160`. Names follow
`octravpn_analytics_<event_kind>` for time-windowed counters.

### Process-level

| Metric | Type | Labels | Bumped by |
|---|---|---|---|
| `octravpn_analytics_events_total` | counter | none | Every ingested audit record. |
| `octravpn_analytics_last_event_unix` | gauge | none | `ts_unix` of most-recent ingested event. |

### Per-kind, per-window

For each event kind below, the indexer exposes a Prometheus counter
labelled with `window` (`1m`, `5m`, `1h`, `1d`). Source constants in
`crates/octravpn-analytics/src/indexer.rs:35-44`:

| Metric (`{window=…}`) | Constant | Source audit kind(s) |
|---|---|---|
| `octravpn_analytics_sessions_opened` | `SESSIONS_OPENED` | `announce`, `session_announced`, `session_open` |
| `octravpn_analytics_sessions_closed` | `SESSIONS_CLOSED` | `session_close` |
| `octravpn_analytics_settle_claims` | `SETTLE_CLAIMS` | `settle_claim` |
| `octravpn_analytics_receipts_signed` | `RECEIPTS_SIGNED` | `receipt_signed` |
| `octravpn_analytics_preauth_minted` | `PREAUTH_MINTED` | `preauth_mint`, `preauth_minted` |
| `octravpn_analytics_preauth_redeemed` | `PREAUTH_REDEEMED` | `preauth_redeem`, `preauth_redeemed` |
| `octravpn_analytics_slash_double_sign` | `SLASH_DOUBLE_SIGN` | `slash_double_sign` |
| `octravpn_analytics_validator_health_pings` | `VALIDATOR_HEALTH_PINGS` | any kind starting `validator_health` |
| `octravpn_analytics_bytes_settled` | `BYTES_SETTLED` | sum of `receipt_signed.bytes_used` deltas |
| `octravpn_analytics_events_other` | `EVENTS_OTHER` | any unknown `kind` (catch-all) |

Total analytics metrics: **2 process + 10 kinds × 4 windows = 42 series**.

### `/analytics/series` JSON

```
GET /analytics/series?metric=<name>&bucket=<1m|5m|1h|1d>&from=<unix>&to=<unix>
```

Returns:

```json
{
  "metric":  "sessions_opened",
  "bucket":  "1m",
  "series":  [ {"t": <unix>, "v": <u64>}, … ]
}
```

`from` / `to` are optional; default is "the bucket's retention horizon".

### `/analytics/health`

Always returns 200 with `{ "ok": true, "last_event_unix": …,
"events_total": … }`. No bearer required.

---

## Recommended alert rules

```yaml
groups:
- name: octravpn-operator
  rules:
  - alert: SlashDoubleSign
    expr: increase(octravpn_slash_double_sign_total[10m]) > 0
    for: 0m
    labels: { severity: page }
    annotations:
      summary: "slash_double_sign tx dispatched (this node or another)"

  - alert: AttestationStale
    expr: time() - octravpn_last_attestation_unix > 120
    for: 5m
    labels: { severity: warn }
    annotations:
      summary: "validator-attestation poll older than 2m"

  - alert: HighRpcErrorRate
    expr: rate(octravpn_rpc_errors_total[5m]) / clamp_min(rate(octravpn_rpc_requests_total[5m]), 1) > 0.05
    for: 10m

  - alert: SessionNoShowSpike
    expr: increase(octravpn_session_no_shows_total[5m]) > 5
    for: 5m

  - alert: IpAllocatorPressure
    expr: octravpn_ip_allocator_used / octravpn_ip_allocator_capacity > 0.9
    for: 30m
    labels: { severity: warn }

  - alert: AnalyticsIndexerLag
    expr: time() - octravpn_analytics_last_event_unix > 300
    for: 10m
```

The reference `prometheus.yml` ships at
`deploy/observability/prometheus.yml`; the bearer for both endpoints
goes in the `authorization.credentials` field of each scrape job.

---

## Grafana panels

Each panel below targets one or more of the metrics above. Panel JSON
lives in `deploy/observability/grafana/` (if present):

| Panel | Metric(s) | Purpose |
|---|---|---|
| "Sessions in flight" | `octravpn_active_sessions` | Operating-state at-a-glance. |
| "Throughput" | `rate(octravpn_bytes_served_total[1m])` | Bytes/s. |
| "RPC error rate" | `rate(octravpn_rpc_errors_total[5m]) / rate(octravpn_rpc_requests_total[5m])` | Chain health. |
| "Receipt seq velocity" | `rate(octravpn_receipts_signed_total[1m])` | Activity per session. |
| "Preauth flow" | `rate(octravpn_preauth_mints_total[5m])`, `…_redemptions_total` | Join cadence. |
| "Slash watchdog" | `octravpn_slash_double_sign_total` | One panel that's red when non-zero. |
| "Analytics window" | `octravpn_analytics_sessions_opened{window="1d"}`, `bytes_settled{window="1d"}` | Day-over-day operator income. |

---

## Counter / gauge implementation notes

* Counters and gauges are `AtomicU64` (`std::sync::atomic`) loaded with
  `Ordering::Relaxed` at scrape time. There is no histogram (yet) —
  every "rate" the dashboard shows is computed Prometheus-side.
* The handler holds no lock during the snapshot, so the metric values
  may be slightly inconsistent across fields (e.g. `session_opens_total`
  vs `active_sessions`). Sub-second skew is expected and not a bug.
* Restart resets every counter to 0 except for the `started_at_unix`
  gauge, which is the canonical "process started at" reference for
  `octravpn_uptime_seconds`.

---

## Adding a new metric

1. Add an `AtomicU64` field to `NodeMetrics` in
   `crates/octravpn-node/src/control/metrics.rs`.
2. Bump it at the emit site.
3. Add the `# HELP` / `# TYPE` / value lines to the `format!` in
   `control/handlers/metrics.rs::metrics`.
4. Add a `text.contains(needle)` assertion in
   `metrics_handler_emits_every_new_field` so the pin test prevents
   silent drops.
5. Add a row to the core-daemon table above.

For analytics-side metrics, add a constant to
`crates/octravpn-analytics/src/indexer.rs` and a counter to
`IndexerState`; the HTTP handler renders all four windows automatically.

---

## Cross-references

* Audit-event kinds the analytics indexer maps to metric counters:
  [audit-events.md](./audit-events.md).
* Bearer-token config: [config.md § `[control]`](./config.md#control--http-control-plane--audit)
  and [config.md § `[analytics]`](./config.md#analytics--historical-analytics-indexer-231).
* Operator observability tour: `docs/observability.md`.
