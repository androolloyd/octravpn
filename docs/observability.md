# Observability runbook

Operator-facing runbook for the Prometheus + Grafana + Alertmanager
stack shipped in `deploy/observability/`. Read alongside the
`README.md` there: that document covers wiring; this one covers
"the alert fired, now what."

For every alert: **what does it mean**, **what to check**, **what to
do**. Each section's anchor matches the `runbook_url` in
`deploy/observability/alerts.yml`.

## Prerequisites

- Shell access to the node host (the `octravpn-node` process).
- The node's audit-log directory (default `./audit`, configurable via
  `[control].audit_dir` in `node.toml`).
- The `octravpn-node audit verify` and `octravpn-node audit replay`
  subcommands — they ship with the same binary the node runs from.

---

## OctravpnNodeDown {#octravpnnodedown}

**Meaning.** Prometheus has been unable to scrape `/metrics` on a
target for >2 minutes. Either the process crashed, the control plane
port (51821 by default) is unreachable, or the network path between
Prometheus and the node is broken.

**Check.**

1. `curl -s http://<node>:51821/health` — direct probe, bypasses
   Prometheus. If this works, the issue is in the scrape path
   (network, DNS, firewall) not the node.
2. On the node host: `systemctl status octravpn-node` (or whatever
   supervisor you use). Look for OOM kills, segfault traces.
3. Inspect logs from the last 10 minutes for panics — the node's
   default log target is stderr; `journalctl -u octravpn-node -n 200`
   on a systemd host.

**Fix.**

- If the process crashed, the receipt journal (P1-8/9) preserves the
  highest seq it ever signed for every session. Restarting the node
  is safe: the next receipt jumps past the journal floor rather than
  resetting to seq=1. See `crates/octravpn-node/src/control.rs` —
  `journal_floor` lookup in `get_state`.
- Before resuming traffic, run `octravpn-node audit verify` against
  today's audit file (`audit-YYYY-MM-DD.jsonl` under the audit dir).
  A clean chain means no in-flight records were corrupted. A break
  means the file was truncated by the crash or tampered with — in
  either case stop and investigate before bringing the node back up.

---

## OctravpnAttestationStale {#octravpnattestationstale}

**Meaning.** The hub's attestation loop hasn't successfully refreshed
the on-chain validator check in >5m. The `/health` endpoint will be
returning 503 to load balancers (see `HEALTH_ATTESTATION_FRESHNESS_S`
in `control.rs`).

**Check.**

1. `curl -s http://<node>:51821/health | jq .` — confirms the
   `last_attestation_unix` field and computes age for you.
2. From the node host, hit your chain RPC directly: a node-side
   attestation failure is almost always "the RPC endpoint is wedged"
   not "we lost validator status." Compare the node's configured
   chain RPC URL (`[chain]` section of `node.toml`) against a known
   good probe.
3. If the RPC is healthy but the node still doesn't refresh, check
   for jail events — the wallet may have been slashed off the
   validator set.

**Fix.**

- If chain RPC is down, the alert clears as soon as it comes back; no
  node-side action needed. Leave the node up — it serves existing
  sessions correctly, the alert is a freshness-of-on-chain-state
  signal not a serving-correctness signal.
- If the wallet was jailed, you need to unjail (chain-specific) and
  let the next attestation tick recover.
- If neither: restart the node. The attestation loop occasionally
  wedges on transient errors; a restart is benign (receipt journal
  ensures no replay), and uptime is cheap.

---

## OctravpnNodeRestarted {#octravpnnoderestarted}

**Meaning.** Process uptime is <5m. Informational — fires on every
deploy and every crash recovery.

**Check.** Was the restart planned? If yes, ignore. If no, follow the
`OctravpnNodeDown` runbook above to investigate the cause.

---

## OctravpnReceiptSigningStalled {#octravpnreceiptsigningstalled}

**Meaning.** `bytes_served_total` is climbing >1 KiB/s averaged over
5m, but `receipts_signed_total` is flat. The node is forwarding
traffic but not signing receipt proposals. Three root causes:

1. **Receipt journal P1-8/9 floor violation.** A race condition
   inside `bump` returns `SeqNotMonotonic`, the handler returns 409,
   no signature is produced. Search node logs for `"receipt seq
   floor violation; refusing to sign"`.
2. **Client never calls `GET /session/:id`.** Less likely (clients
   are expected to fetch proposals at settlement), but possible if a
   client is misconfigured.
3. **Node signing key is missing.** Less likely (the node wouldn't
   have started); but the file at `[node].keypair_path` could have
   been removed at runtime.

**Check.**

1. Logs for `receipt seq floor violation` — points at case 1.
2. `curl -s http://<node>:51821/metrics | grep octravpn_state_lookups_total`
   — if this is also flat, no client is even calling `/session/:id`
   (case 2). If it's growing, the node is being called but failing
   internally (case 1 or 3).
3. Existence + size of the receipt journal file (default
   `./state/receipts.bin`) — corruption here would block every
   sign.

**Fix.**

- Case 1: investigate the race. `BoundedMap` is in-process; this
  should be impossible under normal operation. File a bug.
- Case 2: client-side issue; no node-side fix.
- Case 3: stop the node, restore the journal from backup, run
  `octravpn-node audit verify`, then restart. Sessions that signed
  before the gap will continue from their highest known seq.

---

## OctravpnSessionMapNearCap {#octravpnsessionmapnearcap}

**Meaning.** The control-plane `BoundedMap` is tracking >9000
sessions (cap is 10000). Past the cap, the oldest entries evict and
their clients see `"session not announced"` and have to re-announce.

**Check.**

1. Genuine load increase? Sessions should age out at
   `CONTROL_SESSION_TTL = 1h`; if you have ~10k concurrent paying
   sessions, congratulations.
2. Sweeper wedged? Look for `"control plane sweep"` debug log lines —
   the sweeper runs every `CONTROL_SWEEP_PERIOD = 60s` and logs the
   evicted count.

**Fix.**

- If sweeper is fine and load is real: this is a config problem.
  `CONTROL_SESSIONS_CAP` is a `pub(crate) const` — raising it
  requires rebuilding the binary. Consider whether multiple smaller
  nodes are a better answer than one giant node.
- If sweeper is wedged: restart. Sessions persist via the receipt
  journal, so re-announces by reconnecting clients pick up cleanly
  (next seq jumps past the journal floor).

---

## TODO alerts (not yet wired)

These alerts exist as commented-out rules in `alerts.yml` because
they depend on `NodeMetrics` fields that aren't exposed yet. Each
runbook section is here so a future contributor can land the metric
+ alert + runbook together.

### OctravpnAuditLogFsyncBacklog {#octravpnauditlogfsyncbacklog}

When wired: queue depth on the audit-write `spawn_blocking` worker
crossed 100. Means audit-log writes are queueing — investigate disk
I/O latency on the audit dir's filesystem. Run
`octravpn-node audit verify` on today's file to confirm nothing has
already been dropped.

### OctravpnSlashEvent {#octravpnslashevent}

When wired: the chain attestation loop saw a `slash_double_sign`
event attributed to this node's wallet. Critical — stop the node
immediately, take a forensic copy of the audit dir, and run
`octravpn-node audit replay --session <id>` against any
contemporaneous sessions to reconstruct what the node signed. Two
co-signed receipts at the same `(session_id, seq)` is the on-chain
proof you're defending against; the audit log is your local evidence
of what actually happened.

### OctravpnRPCFailureRate {#octravpnrpcfailurerate}

When wired: control-plane HTTP error rate >5% over 5m. Almost
certainly rate-limit middleware shedding load — check
`crates/octravpn-node/src/rate_limit.rs` defaults against current
traffic. If rate limiter is innocent, look for upstream blockers
(disk full, journal write errors).
