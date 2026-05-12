# Deployment Runbook

This is the operator-facing playbook for taking OctraVPN from a
fresh checkout to a running paid endpoint on testnet, then to mainnet,
and reacting to common incidents. Audience: ops engineers who already
know how to run an Octra protocol validator.

## 1. Pre-flight

Before touching any host:

- [ ] You're a registered Octra protocol validator (confirm via
      `octra cast call <chain_addr> is_validator --rpc-url ...`).
- [ ] You have an unencrypted-in-RAM, encrypted-at-rest copy of the
      validator wallet (see `docs/validator-hardening.md` §2).
- [ ] The host satisfies the systemd hardening profile (run
      `systemd-analyze security octravpn-node` after install; target
      ≤ 1.5).
- [ ] Outbound to the Octra RPC (`rpc_url`) reachable from the host.
- [ ] Inbound UDP port for WireGuard (default `51820/udp`) reachable
      from the public internet.
- [ ] If exposing the control plane externally: TLS reverse proxy
      configured (see `docs/operator-guide.md` §5a).
- [ ] Monitoring stack (Prometheus + Grafana + Loki) collecting from
      the textfile collector path you'll point the alerts at.

Smoke probe the Octra side:

```sh
RPC=https://testnet.octra.network/rpc
PROG=oct<deployed-OctraVPN-program-addr>

octra cast rpc node_status   --rpc-url "$RPC"
octra cast call "$PROG" get_params       --rpc-url "$RPC"
octra cast call "$PROG" list_tailnets    --rpc-url "$RPC"
```

All three should succeed before you start the node.

## 2. Staging deploy

We strongly recommend an internal staging environment that runs
against testnet for at least 48 hours under realistic load before
mainnet bring-up.

```sh
# 1. Pull the latest signed release.
RELEASE=https://github.com/anthropic/octravpn/releases/latest
curl -LO "$RELEASE/download/octravpn-node-$(uname -s)-$(uname -m)"
cosign verify-blob \
  --certificate-identity-regexp '.*github.com/anthropic/octravpn.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature octravpn-node-*.sig \
  octravpn-node-*  # required for supply-chain integrity

# 2. Install + permissions.
sudo install -m 0755 octravpn-node /usr/local/bin/
sudo useradd -r -s /bin/false octravpn

# 3. Config — see `docs/operator-guide.md` for the schema.
sudo install -d -m 0750 -o root -g octravpn /etc/octravpn
sudo install -m 0640 -o root -g octravpn node.toml /etc/octravpn/
sudo install -m 0400 -o root -g octravpn wallet.key /etc/octravpn/
sudo install -m 0400 -o root -g octravpn wg.key /etc/octravpn/

# 4. systemd hardening overrides from validator-hardening.md §1.1.
sudo install -d /etc/systemd/system/octravpn-node.service.d/
sudo install -m 0644 override.conf \
  /etc/systemd/system/octravpn-node.service.d/

# 5. Boot.
sudo systemctl daemon-reload
sudo systemctl enable --now octravpn-node
```

Verify within 60s:

```sh
curl -sS http://localhost:51821/health | jq
# expect: { "status": "ok", ... }

journalctl -u octravpn-node -n 100 --no-pager
# expect: "register_endpoint submitted", "control plane listening",
#         "tunnel listening", "audit log open"
```

## 3. Staging acceptance tests

Run from a separate workstation against the testnet:

```sh
RPC=...
PROG=...

# Discover this validator in the active-endpoint list.
octravpn nodes --rpc-url "$RPC"
# Confirm your validator addr appears.

# Create a tailnet, add a member, open a session, settle.
# (Same flow as docker/e2e-tailnet.sh but against testnet.)
./docker/e2e-tailnet.sh  # set OCTRAVPN_E2E_RPC=$RPC
```

Watch:

- `octravpn_announces_total` rises as the client opens sessions.
- `octravpn_bytes_served_total` increments through traffic flow.
- `octravpn_last_attestation_unix` stays within 60s of `now`.
- No 5xx in the audit-chain integrity probe (§6 below).

## 4. Production bring-up

Move from staging to mainnet only after:

- [ ] Staging has run ≥ 48 h with no manual interventions.
- [ ] You've simulated the four incident playbooks below at least once.
- [ ] On-call rotation is in place with paging on the alerts listed
      in `docs/validator-hardening.md` §6.
- [ ] Wallet → cold storage backup verified by a dry-run restore.

The mainnet deploy is identical to staging except for the `rpc_url`
and `program_addr` values in `node.toml`.

Stagger your endpoint registration across operators — don't register
all 10 endpoints at the same epoch; let each new endpoint warm up
(serve a few thousand bytes) before you add the next.

## 5. Monitoring stack

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: octravpn-node
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:51821']
        labels:
          validator: <your-validator-addr>
    metrics_path: /metrics
```

Add the rules from `docs/validator-hardening.md` §6.

Grafana panels — at minimum:

| Panel                  | Query                                                                |
| ---------------------- | -------------------------------------------------------------------- |
| Active sessions        | `octravpn_active_sessions`                                           |
| Bytes / sec            | `rate(octravpn_bytes_served_total[1m])`                              |
| Receipt sign rate      | `rate(octravpn_receipts_signed_total[1m])`                           |
| Attestation freshness  | `time() - octravpn_last_attestation_unix`                            |
| Uptime                 | `octravpn_uptime_seconds`                                            |

## 6. Daily housekeeping (cron)

```cron
# Audit-chain integrity — runs every 5 minutes, gauge updated atomically.
*/5 * * * * octravpn /usr/local/bin/octravpn-node verify-audit-log \
  /var/log/octravpn/audit/audit-$(date -u +\%F).jsonl \
  > /var/lib/node_exporter/textfile/octravpn_audit.prom 2>&1 \
  || echo 'octravpn_audit_chain_broken 1' \
     > /var/lib/node_exporter/textfile/octravpn_audit.prom

# Earnings claim — daily; small enough to keep your accumulator low risk.
17 3 * * * octravpn /usr/local/bin/octravpn-node claim-earnings \
  --config /etc/octravpn/node.toml

# Backup of audit + accumulator.
22 3 * * * root rsync -a /var/log/octravpn/ /var/lib/octravpn/*.acc \
  backup-host:octravpn/$(hostname)/
```

## 7. Incident playbooks

### 7.1 `/health` 503 attestation_stale

Cause: the node hasn't successfully verified its
`is_octra_validator` status within 5 min.

```sh
# Step 1 — is the Octra RPC reachable?
octra cast rpc node_status --rpc-url <RPC_URL>

# Step 2 — is this validator still bonded on Octra?
octra cast rpc octra_isValidator --params '["<your-validator-addr>"]' --rpc-url <RPC_URL>

# Step 3 — if false, you've been jailed at the protocol layer.
#         The dVPN endpoint becomes inactive automatically because
#         `register_endpoint` / `settle_session` gate on this.
#         Resolution is an Octra-side concern (re-bond, dispute, etc.).
```

While jailed, **don't** restart the node aggressively — the chain
state already reflects "not a validator", so further restarts won't
help and may spam your peers with retried registers.

### 7.2 Sudden control-plane traffic spike

The rate limiter (`100 req/s sustained, 200 burst per IP`) will
return 429 to anyone past the bucket. If alerts fire:

```sh
journalctl -u octravpn-node | grep '429' | awk '{print $NF}' | sort | uniq -c | sort -rn | head
```

Identify the top-N source IPs. If they're legitimate clients:
relax the limit via env:

```sh
sudo systemctl edit octravpn-node
# [Service]
# Environment="OCTRAVPN_RATE_BURST=500"
# Environment="OCTRAVPN_RATE_PER_SEC=200"
sudo systemctl restart octravpn-node
```

If they're attackers: front-line nftables drop (see hardening §4.3).

### 7.3 Audit chain break detected

```sh
# Step 1 — confirm the break point.
octravpn-node verify-audit-log <file>
# → "audit chain break at line N: ..."

# Step 2 — exfiltrate the entire file + .audit.key + journalctl logs
#          since N to off-host storage for forensics.
sudo tar czf /tmp/audit-incident-$(date -u +%F-%H%M).tgz \
  /var/log/octravpn/audit/ \
  /var/log/octravpn/audit/.audit.key

# Step 3 — assume host compromise. Stop the node, rebuild from
#          known-good base image, restore wallet/wg keys from your
#          offline backup, regenerate audit key.
sudo systemctl stop octravpn-node
# rebuild ...

# Step 4 — investigate. If breakage tracks to a specific tx hash,
#          the chain has the authoritative copy of that event.
```

### 7.4 Treasury drain or equivocation evidence received

You receive a JSON blob claiming you double-signed:

```sh
# Step 1 — verify locally before responding.
octravpn slash-evidence verify ./alleged-evidence.json

# Step 2 — VALID:
#   - Your receipt-signing key was compromised. Rotate immediately.
sudo octravpn-node rotate-keys --config /etc/octravpn/node.toml

# Step 3 — VALID but you don't believe it: file a dispute through
#   Octra protocol channels. The evidence isn't your problem; the
#   slashing distribution is.

# Step 4 — INVALID: the blob fails signature verification. Reply
#   to the claimant pointing at the verify error; no action needed.
```

### 7.5 Reconciliation drift

If the local earnings accumulator (`<wallet>.acc`) diverges from the
on-chain encrypted ledger:

```sh
# Step 1 — diff.
octravpn-node reconcile-earnings --config /etc/octravpn/node.toml --dry-run

# Step 2 — if the local accumulator is BEHIND chain, ingest the missed
#         SessionSettled events.
octravpn-node reconcile-earnings --config /etc/octravpn/node.toml

# Step 3 — if the local accumulator is AHEAD of chain (you tried to
#         claim more than the chain credits), STOP — somebody has
#         tampered with the .acc file. Restore from backup; do not
#         submit a claim until parity is restored.
```

## 8. Rollback

If a release introduces a regression:

```sh
# 1. Pull the previous version.
sudo systemctl stop octravpn-node
curl -LO https://github.com/anthropic/octravpn/releases/<prev>/octravpn-node
cosign verify-blob ...
sudo install octravpn-node /usr/local/bin/
sudo systemctl start octravpn-node

# 2. The audit log + accumulator + wallet are forward-compatible
#    across patch versions; minor/major versions may need a migration
#    note in the release notes.
```

Never roll back the AML program version on chain without coordinating
across all validators — that's a protocol-level event handled by
governance.

## 9. Decommission

```sh
# 1. Stop accepting new sessions (retire on chain).
sudo octravpn-node retire --config /etc/octravpn/node.toml

# 2. Wait for in-flight sessions to settle (~ session_grace_epochs).
watch -n 30 'curl -sS http://localhost:51821/metrics | grep active_sessions'

# 3. Claim final earnings.
sudo octravpn-node claim-earnings --config /etc/octravpn/node.toml

# 4. Backup everything off-host.
sudo tar czf /tmp/octravpn-final-$(date -u +%F).tgz \
  /etc/octravpn/ /var/log/octravpn/ /var/lib/octravpn/

# 5. Tear down.
sudo systemctl disable --now octravpn-node
sudo rm -f /usr/local/bin/octravpn-node
sudo userdel -r octravpn
```

Keep the final tarball offline indefinitely — equivocation evidence
can surface long after retirement.

## 10. Release-engineering checklist (for the project, not operators)

For every release tag:

- [ ] `cargo test --workspace` all green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo audit` no advisories
- [ ] OU snapshot regenerated when AML changes
- [ ] `./docker/e2e.sh` passes
- [ ] `./docker/e2e-tailnet.sh` passes
- [ ] Lean / TLA+ / Tamarin proofs re-run (advisory but tracked)
- [ ] Cosign-signed multi-arch OCI images published
- [ ] Deb / RPM / MSI / PKG artifacts attached to release
- [ ] SBOM (CycloneDX) attached
- [ ] CHANGELOG.md entry with breaking-change call-outs
- [ ] Operator-facing migration notes if config or AML changed
