# Deployment Runbook

This is the operator-facing playbook for taking OctraVPN from a
fresh checkout to a running paid endpoint on testnet, then to
mainnet, and reacting to common incidents.

> **Deploying the v3 AML program itself** (not just bringing up
> nodes against an already-deployed program) requires the
> owner-wallet ceremony documented in
> [`docs/mainnet-ceremony.md`](mainnet-ceremony.md) — m-of-n
> cold-key signing party plus `scripts/ceremony/{mainnet-deploy,
> verify-deploy}.sh`. Run that ceremony before §1 of this
> runbook applies to mainnet.

**v1 model** (per `docs/aml-gap-analysis.md`): Operators stake OU
in the OctraVPN AML program; you do NOT need to be an Octra
protocol validator. Equivocation slashing is currently governance
(off-chain evidence → owner-signed slash tx); v1.1 moves to
permissionless on-chain slashing once Octra exposes
`verify_ed25519` in AML.

## 1. Pre-flight

Before touching any host:

- [ ] You have at least `MIN_ENDPOINT_STAKE` (1 000 OCT = 10⁹ OU) in
      OU available to bond as operator stake.
- [ ] You have an unencrypted-in-RAM, encrypted-at-rest copy of the
      operator wallet (see `docs/validator-hardening.md` §2).
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

### 7.1 `/health` 503 stake_below_minimum

Cause: the operator's `endpoint_stake` has fallen below
`MIN_ENDPOINT_STAKE` — either an unbonding was initiated, or
governance slashed the operator.

```sh
# Step 1 — read the on-chain stake for your address.
octra cast call <octravpn-program> get_endpoint_stake \
  --params '["<your-operator-addr>"]' --rpc-url <RPC_URL>

# Step 2 — is the slashed flag set?
octra cast call <octravpn-program> is_endpoint_slashed \
  --params '["<your-operator-addr>"]' --rpc-url <RPC_URL>
# If true → you have been governance-slashed (permanent at this
#           address). Recovery is impossible at the same wallet.
#           File a dispute via the governance channel.

# Step 3 — if not slashed but stake is 0, check unbonding state.
octra cast call <octravpn-program> get_endpoint_unbonding \
  --params '["<your-operator-addr>"]' --rpc-url <RPC_URL>
# Non-zero stake here means you started an unbond. Either complete
# it (finalize_unbond after grace) or re-bond:
#   octravpn-node bond --amount 1000000000
```

While the endpoint is inactive, **don't** restart the node
aggressively — the chain state already reflects inactivity, and
restarts only spam your peers with retried registers.

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

---

## 11. v2 substrate deploy (Circle-native)

§1–§10 cover the v1.1 path. v2 is the slim-registry program where
operators are **circles** (Octra IEEs), not wallet addresses. Both
protocol versions are live; pick per-operator via
`[chain].protocol_version`.

### 11.1 Deploy a new v2 program (governance only)

Skip to §11.2 if joining an existing deployment.

Constructor (5 ints): `min_session_deposit`, `min_tailnet_deposit`,
`min_circle_stake` (≥ 100_000_000 OU), `session_grace_epochs`,
`unbond_grace_epochs` (≥ 1000). Canonical devnet invocation (matches
`oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`):

```sh
forge create program/main-v2.aml \
  --rpc-url https://devnet.octrascan.io/rpc \
  --key ~/.octra/governance.wallet \
  --constructor-args 100 10 1000000000 100 1000
# args: min_session_deposit, min_tailnet_deposit, min_circle_stake,
#       session_grace_epochs, unbond_grace_epochs

octra cast call <new-prog-addr> get_params --rpc-url "$RPC"
# Smoke probe: returns the constructor args verbatim.
```

### 11.2 Operator bring-up against an existing v2 program

The 3-tx boot (`deploy_circle` → `circle_asset_put_encrypted
/policy.json` → `register_circle`) runs automatically on first
`octravpn-node run` — no `bond` subcommand. Differences from §2:

- `node.toml` uses the v2 stanzas in `docs/tutorial-validator.md`
  Appendix.
- `validator_addr` MUST be a fresh, single-purpose, zero-history
  wallet (`docs/v2-operator-key-hygiene.md` §1).
- The wallet must hold ≥ `MIN_CIRCLE_STAKE` (1000 OCT) + tx fees, else
  `register_circle` reverts `"initial stake below minimum"`.

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now octravpn-node
sudo journalctl -u octravpn-node -f | grep '^v2 '
# Expected: deploy_circle → policy bundle uploaded → register_circle → endpoint active

octra cast call $V2_PROG get_circle '["<circle-id>"]'         # active == 1
octra cast call $V2_PROG get_circle_stake '["<circle-id>"]'   # >= MIN_CIRCLE_STAKE
```

The slim registry does not expose a public list — discovery resolves
sealed-asset reads against the `circle_id` directly.

### 11.3 `cast register-pvac` (HFHE pubkey registration)

The v2 program currently stores placeholder HFHE pubkey + zero
ciphertext. When the GPL-isolated PVAC sidecar
(`pvac-sidecar/README.md`) produces a real key:

```sh
octra cast register-pvac \
  --wallet ~/.octra/op-2026-Q2.wallet \
  --pvac-pubkey /etc/octravpn/pvac.pub \
  --rpc-url https://octra.network/rpc
```

Signs the literal-string domain-separated message
`"register_pvac|" + addr + "|" + sha256_hex(pk_blob)` (per
`docs/octra-research.md` §8).

**Operational blocker on devnet:** devnet RPC nginx caps POST bodies
at 1 MiB; a real PVAC pubkey is ~4 MB → `413 Payload Too Large`.
Works against mainnet. Track devnet cap raise in
`docs/v2-threat-model.md`. Until lifted, devnet operators boot with
placeholder HFHE state — `register_circle` accepts placeholders as
opaque bytes, so v2 boot itself is NOT blocked.

### 11.4 Migrating v1.1 → v2

No in-place migration (different programs, different addresses). Order:
`retire` v1.1 → wait for settles → `claim-earnings` → generate a
**fresh** deploy wallet (reuse leaks the v1.1 → v2 linking publicly;
`v2-operator-key-hygiene.md` §1) → fund ≥ `MIN_CIRCLE_STAKE` + fees →
flip `protocol_version = "v2"`, update `program_addr`, restart.

### 11.5 v2 incident deltas (vs §7)

- **Circle slashed** — `is_circle_slashed` returns true → the circle
  is permanently dead. Delete `circle.toml` and restart; the next
  boot derives a fresh `circle_id` (deploy nonce advances). The prior
  bond is gone (burned + bounty).
- **`register_circle` reverts "initial stake below minimum"** —
  top up the wallet; the 3-tx flow resumes on next restart.
- **Sealed-passphrase rotated mid-flight** — bump
  `[chain].sealed_passphrase`, delete `policy_plaintext_hash` from
  `circle.toml`, restart. The daemon re-uploads `/policy.json` under
  the new passphrase. Coordinate distribution via
  `v2-operator-key-hygiene.md` §5.
- **`receipts.bin` corruption** — file is tempfile-fsync-rename so
  partial writes are impossible. Unreadable at boot → daemon refuses
  to start (rather than rolling the floor to 0). Restore from backup;
  for any session whose floor cannot be recovered, **refuse to sign**
  rather than risk an unknown-seq double-sign. Treat seq-floor loss
  as a key compromise — rotate per `validator-hardening.md` §7.
