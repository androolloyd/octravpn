# Operator dashboards + alerting

The Grafana panels referenced from [`tour-operator.md`](tour-operator.md)
steps 9, 10, and the day-90 ops checklist. This doc covers what each
panel shows, what a healthy reading looks like, and how to wire the
alertmanager rules behind them.

## Where the JSON lives

Shipped in the observability pack at
[`deploy/observability/`](../../deploy/observability/):

| File | Dashboard |
| --- | --- |
| `grafana/octravpn-overview.json` | OctraVPN — Overview (fleet view) |
| `grafana/octravpn-tailnet.json` | OctraVPN — Tailnet (per-tailnet placeholder, mostly TODO) |
| `grafana/dashboards/octravpn-analytics.json` | OctraVPN Analytics (historical, #231 indexer) |
| `grafana/provisioning/dashboards/octravpn.yml` | Folder provisioner |
| `grafana/provisioning/datasources/prometheus.yml` | Prometheus datasource provisioner |

Plus the scrape + alerts config:

| File | Purpose |
| --- | --- |
| `prometheus.yml` | Scrape config — `octravpn-nodes` job |
| `targets.json` + `targets.json.example` | File-discovery target list |
| `alerts.yml` | Alertmanager rules |
| `alertmanager.yml` | Local-test Alertmanager config |
| `docker-compose.yml` | Standalone stack for local validation |

## Quick start

From the repo root:

```bash
docker compose -f deploy/observability/docker-compose.yml up
```

That stands up Prometheus (`:9090`), Grafana (`:3000`, default
admin/admin), and Alertmanager (`:9093`). With a node running on the
same host on default ports, the `OctraVPN — Overview` dashboard
populates within ~30s.

To add more nodes, edit `targets.json` — Prometheus re-reads it every
30s, no restart needed.

For an existing Prometheus deployment, merge the
`scrape_configs.octravpn-nodes` block from `prometheus.yml` into yours
and import the dashboard JSONs via the Grafana UI (Dashboards → Import).
Detailed integration steps:
[`deploy/observability/README.md`](../../deploy/observability/README.md).

---

## OctraVPN — Overview

Fleet-level operator dashboard. Every panel maps to a counter or gauge
in [`crates/octravpn-node/src/control/metrics.rs::NodeMetrics`](../../crates/octravpn-node/src/control/metrics.rs).

### Row: Sessions

- **Active sessions (fleet)** — `sum(octravpn_active_sessions)`.
  Stat panel. Per-node hard cap is `CONTROL_SESSIONS_CAP = 10000`;
  idle sessions evict at `CONTROL_SESSION_TTL = 1h`.
  *Healthy*: roughly steady or growing with traffic. *Bad*: > 9000 on
  any single node — see `OctravpnSessionMapNearCap` below.
- **Session announces /s** — `rate(octravpn_announces_total[5m])`.
  Time series. Spikes track campaign / client-side restart bursts.
- **Session state lookups /s** —
  `rate(octravpn_state_lookups_total[5m])`. Time series. The
  control-plane equivalent of a "ping" — should track session count.

### Row: Settlement

- **Receipts signed /s** —
  `rate(octravpn_receipts_signed_total[5m])`. Time series.
  *Healthy*: rate proportional to bytes served. *Bad*: bytes climbing
  but receipts flat — `OctravpnReceiptSigningStalled` fires.
- **Cumulative bytes served (fleet)** —
  `sum(octravpn_bytes_served_total)`. Counter total. Used for capacity
  planning, not alerting.
- **Session no-shows /s** — rate of session expiries without
  `settle_confirm` — proxies for client UX issues if non-zero.
- **TODO panel** — `audit log fsync vs flush latency`. Requires a
  histogram serializer the hand-rolled `/metrics` doesn't carry yet.
  Left as a placeholder so the migration TODO surfaces in the panel
  catalog.

### Row: Peer connectivity

- **WireGuard handshakes /s (success vs fail)** —
  `rate(octravpn_wg_handshake_success_total[5m])` vs
  `rate(octravpn_wg_handshake_fail_total[5m])`. Failures > 0.1/s fire
  `OctravpnWgHandshakeFailures`.
- **Session opens / closes /s** — open/close pair. *Healthy*: closes
  ≈ opens over any 1h window. A persistent gap means sessions are
  hitting `CONTROL_SESSION_TTL` and evicting instead of closing
  cleanly — usually a client-side issue.

### Row: ACL / Auth

- **Preauth mints & redemptions /s** —
  `rate(octravpn_preauth_mints_total[5m])` vs
  `rate(octravpn_preauth_redemptions_total[5m])`. *Healthy*: mints
  precede redemptions with the policy's TTL gap. *Bad*: mints >>
  redemptions sustained — fires `OctravpnPreauthMintsBurst`. Either
  legitimate batch onboarding or `OCTRAVPN_ADMIN_TOKEN` compromise.
- **Slash events (lifetime)** — `octravpn_slash_double_sign_total`
  counter. *Healthy*: zero forever. *Critical*: any non-zero value
  fires `OctravpnSlashEvent`. The
  [`tour-operator.md` §equivocation recovery](tour-operator.md#equivocation--slash-detection--bond-loss--recovery)
  procedure starts here.

### Row: Resource

- **Chain RPC requests & error rate** —
  `rate(octravpn_rpc_requests_total[5m])` vs
  `rate(octravpn_rpc_errors_total[5m])`. *Healthy*: error rate < 5%.
  Above 5% sustained 5m fires `OctravpnRPCErrorRate`.
- **TODO panel** — RPC body size + latency histograms. Same blocker as
  the audit fsync histogram.

### Row: Health

- **Time since last attestation** —
  `time() - octravpn_last_attestation_unix`. Stat panel,
  threshold-coloured. *Healthy*: < 60s. *Warning*: > 300s fires
  `OctravpnAttestationStale`; `/health` returns 503 at the same
  threshold.
- **Process uptime** — `octravpn_uptime_seconds`. Restart detection
  fires at uptime < 5m (`OctravpnNodeRestarted` info severity).
- **Nodes up** — `sum(up{job="octravpn-nodes"})`. Cluster-wide
  liveness from Prometheus's synthetic `up` metric. Drop fires
  `OctravpnNodeDown` after 2m.
- **Last attestation unix (per node)** — per-instance breakdown of
  the time-since-attestation; useful for catching a single-node lag.

---

## OctraVPN Analytics (historical)

Fed by the in-process #231 analytics indexer
([`crates/octravpn-analytics/`](../../crates/octravpn-analytics/)),
spawned when `[analytics].enabled = true` in `node.toml`. The indexer
walks the audit log into tumbling-bucket counters and exposes them as
Prometheus metrics labelled with `window`
(`5m` / `1h` / `1d`).

| Panel | Metric | Healthy reading |
| --- | --- | --- |
| Sessions opened /s (5m window) | `rate(octravpn_analytics_sessions_opened{window="5m"}[5m])` | Tracks announce rate from the Overview |
| Settle claims /s (5m window) | `rate(octravpn_analytics_claims_settled{window="5m"}[5m])` | Should lag opens by ~session length |
| Receipts signed /s (5m window) | `rate(octravpn_analytics_receipts_signed{window="5m"}[5m])` | Mirrors `octravpn_receipts_signed_total` rate |
| Treasury bytes (1d window total) | `octravpn_analytics_treasury_bytes{window="1d"}` | Trends downward as treasury drains |
| Preauth churn (mint − redeem, 5m window) | `octravpn_analytics_preauth_churn{window="5m"}` | Near-zero except during onboarding |
| Slash events (1d window) | `octravpn_analytics_slash_events{window="1d"}` | Zero forever |

The retention policy is encoded in
[`crates/octravpn-analytics/src/bucket.rs`](../../crates/octravpn-analytics/src/bucket.rs)
— briefly: 5m buckets retained for 24h, 1h for 30d, 1d indefinitely.

Direct JSON access for scripting (the dashboards use the Prometheus
counters, but the JSON is more compact for cron):

```bash
curl -sS "http://localhost:51823/analytics/series?metric=sessions_opened&bucket=5m"
curl -sS "http://localhost:51823/analytics/series?metric=treasury_bytes&bucket=1d"
```

Health probe (unauthenticated, suitable for external load balancers):

```bash
curl -sS http://localhost:51823/analytics/health
```

If `first_break` in the health JSON is non-null, the indexer hit a
chain-verify error in the audit log — escalate per
[`troubleshooting.md` §audit log won't verify](troubleshooting.md#audit-log-wont-verify).

---

## Setting up alertmanager rules

The shipped ruleset is [`deploy/observability/alerts.yml`](../../deploy/observability/alerts.yml).
It defines three groups:

### `octravpn-node-health`

- **`OctravpnNodeDown`** — `up{job="octravpn-nodes"} == 0` for 2m.
  *Severity: critical.* Page immediately.
- **`OctravpnAttestationStale`** — `time() - octravpn_last_attestation_unix > 300`
  for 1m. *Severity: warning.* Same threshold as `/health` 503 — fire
  before load balancers start failing scheduled probes.
- **`OctravpnNodeRestarted`** — `octravpn_uptime_seconds < 300`.
  *Severity: info.* Surfaced for context during deploys, not paged.

### `octravpn-traffic`

- **`OctravpnReceiptSigningStalled`** — bytes climbing > 1 KiB/s, but
  receipts signed flat for 5m. *Severity: warning.* The receipt
  journal floor or signing key is wedged; run `audit verify` against
  today's log.
- **`OctravpnSessionMapNearCap`** — `octravpn_active_sessions > 9000`
  for 5m. *Severity: warning.* Approaching `CONTROL_SESSIONS_CAP`;
  oldest sessions will evict and clients see "session not announced".

### `octravpn-slash-and-rpc`

- **`OctravpnSlashEvent`** — non-zero rate of
  `octravpn_slash_double_sign_total` over 5m. *Severity: critical.*
  Page immediately. Recovery procedure:
  [`tour-operator.md` §equivocation](tour-operator.md#equivocation--slash-detection--bond-loss--recovery).
- **`OctravpnRPCErrorRate`** — > 5% RPC error rate over 5m.
  *Severity: warning.* Either chain RPC is sick or the validator-
  health loop is hitting a nonce/fee path.
- **`OctravpnPreauthMintsBurst`** — > 100/s preauth mints for 5m.
  *Severity: warning.* Either expected batch onboarding or
  `OCTRAVPN_ADMIN_TOKEN` compromise. Rotate the token if in doubt.
- **`OctravpnWgHandshakeFailures`** — > 0.1 handshake-fails/s for
  5m. *Severity: warning.* Inspect tunnel logs for `boringtun decap
  error` lines; usually a misbehaving client or UDP-spoof DoS.

### Pending metrics

The `alerts.yml` carries commented-out rules for
`audit_log_fsync_queue_depth`, `audit_flush_seconds`,
`rpc_body_size_bytes`, etc. — uncomment as the underlying histograms
land in `NodeMetrics`.

### Suggested routing

| Severity | Where |
| --- | --- |
| `critical` | PagerDuty / Opsgenie / SMS — wake the operator on call |
| `warning` | Team chat channel — investigate within business hours |
| `info` | Context-only — surface in the dashboard, don't notify |

Each rule's `runbook_url` annotation points at
[`docs/observability.md`](../observability.md). Update the URLs in
your fork of `alerts.yml` if you self-host the docs.

---

## See also

- The reference for what metrics exist:
  [`deploy/observability/README.md`](../../deploy/observability/README.md).
- The general operator-side observability guide (audit verify
  workflow, capacity sizing, log rotation):
  [`../observability.md`](../observability.md).
- The mainnet runbook, including a step-7 monitoring bring-up:
  [`mainnet-deployment.md`](mainnet-deployment.md).
- The tour where these dashboards first appear:
  [`tour-operator.md`](tour-operator.md) (steps 9, 10, day-90).
