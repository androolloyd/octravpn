# OctraVPN observability pack

Prometheus + Grafana + Alertmanager for operating an OctraVPN node
fleet. Plain-Prometheus stack only — no Mimir / Thanos / VictoriaMetrics
and no log-shipping (Loki is a separate concern; this pack is metrics
+ alerts).

## What's in the box

| File                                       | Purpose                                                       |
| ------------------------------------------ | ------------------------------------------------------------- |
| `prometheus.yml`                           | Scrape config — `octravpn-nodes` job, file-discovery targets. |
| `targets.json` + `targets.json.example`    | The file-discovery target list.                               |
| `alerts.yml`                               | Alertmanager rules — node-down, attestation-stale, etc.       |
| `alertmanager.yml`                         | Local-test Alertmanager config (drops alerts by default).     |
| `grafana/octravpn-overview.json`           | Fleet-wide dashboard.                                         |
| `grafana/octravpn-tailnet.json`            | Per-tailnet dashboard (mostly TODO until metrics land).       |
| `grafana/provisioning/`                    | Datasource + dashboard auto-load for Grafana.                 |
| `docker-compose.yml`                       | Standalone stack for local validation.                        |

## Quick start — local validation

From the repo root:

```sh
docker compose -f deploy/observability/docker-compose.yml up
```

That brings up Prometheus (`:9090`), Grafana (`:3000`, default
admin/admin), and Alertmanager (`:9093`). With a node running on the
same host on its default control port (51821), the
`OctraVPN — Overview` dashboard should populate within ~30s.

To add more nodes, edit `targets.json` in this directory — Prometheus
re-reads it every 30s, no restart needed.

## Wiring into an existing Prometheus

You don't need the compose stack. Two integration points:

1. **Scrape config.** Merge the `scrape_configs.octravpn-nodes` block
   from `prometheus.yml` into your existing `prometheus.yml`. Adjust
   the `file_sd_configs.files` path to where you keep target lists.
2. **Alert rules.** Drop `alerts.yml` somewhere under your
   `rule_files:` glob.

For Grafana, import the two dashboards JSON files manually (Dashboards
→ Import) or copy the provisioning directory into your Grafana
installation.

## Metrics the pack consumes

Sourced from `crates/octravpn-node/src/control.rs::NodeMetrics` and the
`metrics()` handler in the same file (Prometheus text exposition
format, no auth — see the security note below):

| Metric                              | Type    | Source field on `NodeMetrics`        |
| ----------------------------------- | ------- | ------------------------------------ |
| `octravpn_announces_total`          | counter | `announces_total`                    |
| `octravpn_state_lookups_total`      | counter | `state_lookups_total`                |
| `octravpn_receipts_signed_total`    | counter | `receipts_signed_total`              |
| `octravpn_bytes_served_total`       | counter | `OnionRouter::total_bytes()`         |
| `octravpn_active_sessions`          | gauge   | `BoundedMap::len()` (control-plane)  |
| `octravpn_last_attestation_unix`    | gauge   | `last_attestation_unix`              |
| `octravpn_uptime_seconds`           | counter | `now - started_at_unix`              |

## Metrics the pack would like, but the node doesn't expose yet

These are flagged inline (TODO panels in the dashboards, commented-out
alert rules) so the wiring lands as soon as the metric does:

- `audit_log_fsync_queue_depth` / `audit_flush_seconds` — audit fsync
  vs flush latency from the perf-bench finding.
- `slash_double_sign_total` — chain-side event needs to be surfaced.
- `preauth_mints_total` / `preauth_redemptions_total` — one-line
  `AtomicU64::fetch_add` at `mint_preauth` / `PreauthMinter::redeem`
  call sites.
- `rpc_requests_total{result}` — needed for the 5%-error-rate alert.
- RPC body size and control-plane HTTP latency histograms.
- WireGuard handshake success/fail counters; Tailscale peers
  reachable; DERP usage (none wired in v0).
- Per-tailnet `tailnet_members`, IP allocator utilization, member
  join/leave, magic-DNS query rate.

None of these is a hard blocker — the stack works fine with what's
exposed today. Each is a one-line addition to `NodeMetrics` plus a
`fetch_add` at the call site, plus three lines in the `metrics()`
handler.

## Notes on the spec deviations

The original ask said scrape `<host>:51820/metrics`. The control plane
actually listens on `0.0.0.0:51821` by default (`default_control_listen`
in `crates/octravpn-node/src/config.rs`); 51820 is the WireGuard data
plane. All scrape configs use 51821.

The original ask said gate `/metrics` behind a bearer token via
`OCTRAVPN_METRICS_TOKEN`. The endpoint is NOT auth-gated in the node
today — it sits behind the rate-limit middleware on the same router as
`/health`. The `prometheus.yml` carries a commented-out `authorization:`
block ready to use once an operator terminates auth in a reverse
proxy.

## Cardinality

Per-session metrics are deliberately absent — session IDs are 32-byte
random and a per-session label would explode Prometheus' tsdb. The
exposed counters are aggregated across all sessions; per-session
forensics live in the audit log (`docs/observability.md` covers the
`audit verify` workflow).
