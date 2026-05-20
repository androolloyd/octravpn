# Operator troubleshooting — per-symptom recipes

Operator-specific debugging. The general client-side and chain-side
catalog lives in [`../troubleshooting.md`](../troubleshooting.md);
this file focuses on the failure shapes a running operator sees, in
the order they tend to bite during the
[`tour-operator.md`](tour-operator.md) walkthrough.

Each entry: **symptom**, the **most-likely root cause** ordered by
frequency, and a **recipe** that recovers without bricking the bond.

---

## Daemon won't boot

The most common boot-time errors and what they mean.

### Symptom — `PlaintextKeyOnDisk: <path>`

**Cause.** `[chain].require_sealed_keys = true` in your `node.toml`,
but the configured `wallet_secret_path` or `tunnel.wg_secret_path`
still points at a plaintext file. The strict loader
(`octra-foundry/crates/octra-core/src/util.rs::read_secret_32_or_sealed`)
refuses to silently fall back.

**Recipe.**

```bash
export OCTRAVPN_KEY_PASSPHRASE='<strong passphrase>'

# Seal the plaintext files in place — writes *.sealed siblings atomically.
octravpn-node --config /etc/octravpn/node.toml seal-keys

# Confirm the sealed file is real (first 16 bytes = "OCTRA-WALLET-V1\0")
xxd /etc/octravpn/wallet.key.sealed | head -1

# Point node.toml at the *.sealed paths. Then delete the plaintext:
octravpn-node --config /etc/octravpn/node.toml seal-keys --remove-plaintext
```

See [`../v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md)
for the full procedure.

### Symptom — `seal-keys: passphrase: no candidate found`

**Cause.** Strict mode is on AND none of the four passphrase sources
resolved:
`--passphrase` > `--passphrase-file` > `--passphrase-stdin` >
`OCTRAVPN_KEY_PASSPHRASE` env > TTY prompt.

systemd-launched daemons have no TTY. Set the env var via
`EnvironmentFile=/etc/octravpn/keys.env` (chmod 0600, one line:
`OCTRAVPN_KEY_PASSPHRASE=…`).

### Symptom — `Address already in use` (port 51820 / 51821 / 51823 / 443)

**Cause.** Another process is bound to a port the daemon needs.

**Recipe.**

```bash
sudo ss -tulnp | grep -E '(51820|51821|51823|:443)'
```

Either kill the squatter or change the daemon's bind in `node.toml`:

```toml
[tunnel]
listen = "0.0.0.0:51820"   # WG data plane

[control]
listen = "127.0.0.1:51821" # control plane + /metrics + /health

[analytics]
listen = "127.0.0.1:51823" # historical analytics indexer
```

If you must move 443, also update the SAN on your TLS cert; clients
auto-dial port 443 on the SAN you advertise.

### Symptom — `config schema: missing field <X>` at boot

**Cause.** Your `node.toml` is missing a required field that was
added in a newer schema version.

**Recipe.** Always run `config validate` before promoting a TOML:

```bash
octravpn-node config validate /etc/octravpn/node.toml
```

The validator emits the missing-field name verbatim. For air-gapped CI,
use `--offline` to skip the chain probe but still catch schema drift.

---

## Sessions opened but no receipts signed

### Symptom

Grafana shows `octravpn_active_sessions > 0` and
`octravpn_bytes_served_total` rising, but
`octravpn_receipts_signed_total` is flat. The alertmanager fires
`OctravpnReceiptSigningStalled` after 5m.

### Most likely cause — control-plane bearer-token mismatch

The control plane gates session-create / receipt-sign on a bearer
token in `[control].api_token` (or unset, in which case all requests
fail authn). When the client and daemon disagree on the token, the
client opens a session via chain (which is unauthenticated) but the
operator's `/session/:id/receipt` handler rejects the receipt write
with 401.

**Recipe.**

1. Confirm token alignment:

   ```bash
   grep api_token /etc/octravpn/node.toml
   ```

2. Distribute the token to your authorised clients out-of-band.
   Rotate the token in `node.toml` and `systemctl reload octravpn-node`
   if you suspect leakage.

### Other causes (in order of frequency)

- **Receipt journal floor violation.** The P1-8/9 invariant rejects
  any signed receipt seq that's not strictly above the journal floor.
  If a previous crash left the journal in an inconsistent state, every
  new receipt write returns 409. Inspect:

  ```bash
  octravpn-node receipt-verify <session-id-hex> \
      --journal-path /var/lib/octravpn/state/receipts.bin \
      --audit-path   /var/lib/octravpn/state/audit.log
  ```

  The CLI reports the current floor and every audit-log entry naming
  the same session.

- **Signing key missing.** The WG private key in
  `[tunnel].wg_secret_path` can't be read (file moved, permissions
  changed). Check with `octravpn-node health --config …` — the local
  probe loads both key files.

---

## `settle_confirm` reverts

Six common causes, in roughly the order they show up.

### Cause — chain RPC unreachable

**Symptom.** Submission fails before reaching consensus. CLI prints
`rpc error: connect timeout`.

**Recipe.** Probe the RPC endpoint independently:

```bash
octra cast rpc node_status --rpc "$RPC_URL"
```

If that also fails, the issue is network or upstream. Confirm
`[chain].rpc_url` in `node.toml` is reachable from the host.

### Cause — fee too low

**Symptom.** RPC accepts the tx but it never lands. `octra cast
transaction <hash>` shows `status: dropped`.

**Recipe.** Bump the fee envelope. The CLI uses the standard
`--fee 1000` default; for congested periods, override per-call.

### Cause — nonce drift

**Symptom.** RPC returns `nonce too low` or `nonce too high`.

**Recipe.** The CLI reads the current nonce from
`octra_get_balance(addr).nonce` before each submission. Drift comes
from concurrent submitters using the same wallet — don't do that. If
you ran two settle commands in parallel for two different sessions,
re-submit the failed one; the chain has the updated nonce now.

### Cause — chain-side `fhe_load_pk` revert (legacy v2 path)

**Symptom.** Sessions open and meter, but `settle_confirm` reverts at
the HFHE-verify step. Affects v2 deployments only.

**Status.** Known issue — see
[`../troubleshooting.md` "HFHE / `settle_confirm` reverts"](../troubleshooting.md#hfhe--settle_confirm-reverts)
and [`../octra-dev-questions.md §1`](../octra-dev-questions.md).
AML `fhe_load_pk` reverts in our contracts even after a successful
`octra_registerPvacPubkey`. The v3 path uses sha256 commitments + an
off-chain PVAC sidecar ([`pvac-sidecar`](../../pvac-sidecar)), which
sidesteps `fhe_load_pk` entirely.

**Recipe.**

- On v2: have the client run `claim_no_show(session_id)` post-grace
  to recover their deposit. Re-platform to v3.
- On v3: this revert is impossible; if you're seeing it on v3, your
  client is mis-pointed at a v2 program address.

### Cause — opener / operator `bytes_used` disagreement (dispute)

**Symptom.** `settle_confirm` returns `false` (accepted=false) rather
than reverting. The session enters dispute.

**Status.** Open audit finding **C-1** — disputed sessions are
permanent stuck-funds today. See
[`../audit/2026-05-20-deep-security-audit.md`](../audit/2026-05-20-deep-security-audit.md).

**Recipe.** No on-chain recovery. Cross-walk the audit log + receipt
journal to determine who was right; archive the evidence; bill or
refund off-chain. Mitigation: cap `max_pay` per session.

### Cause — circle retired or slashed

**Symptom.** `settle_confirm` reverts with `"circle not active"` or
`"previously slashed"`.

**Recipe.** The session opened against your circle when it was
active; it can no longer settle. Opener should run `claim_no_show`
post-grace. Your bond is the source of any owed credit, but the chain
won't auto-route it — operate the post-mortem off-chain.

---

## DERP relay refused

### Symptom

Daemon boots cleanly but logs `DERP relay: TLS handshake failed`.
Clients can't reach you over DERP-fallback paths; direct UDP works.

### Cause — TLS cert issues

**Recipe.**

```bash
# Check the cert + key the daemon loaded:
openssl x509 -in /etc/octravpn/tls/cert.pem -noout -dates -subject -ext subjectAltName

# Probe from outside:
openssl s_client -connect <san>:443 -servername <san> </dev/null 2>/dev/null \
    | openssl x509 -noout -dates -subject
```

The SAN must match what clients resolve your control plane to. Cert
not-after must be in the future. Renewal procedure:
[`tls-rotation.md`](tls-rotation.md).

### Cause — port 443 blocked

**Recipe.** From outside the host:

```bash
curl -vk https://<san>:443/key 2>&1 | head -20
```

If you see `Connection refused` or `connect: no route to host`, the
upstream firewall isn't forwarding 443. Confirm your hosting provider's
security group allows inbound TCP 443.

### Cause — docker compose health-check failures (tape 08 shape)

**Symptom.** In the docker devnet, the DERP relay container restarts
in a loop, health-checks failing. The issue we observed at tape 08
(`docker compose ps` shows
`octravpn-derp ... (unhealthy)`): the
`healthcheck:` block in `deploy/observability/docker-compose.yml`
probes `/derp` before the noise-static key has been written. The
container is healthy ~5s later than the probe expects.

**Recipe.** Bump the health-check `start_period` from the default
`5s` to `30s`. Long-term fix is in the daemon (delay `/derp`
listener bind until noise key is loaded) — tracked.

---

## WireGuard handshake timeout

### Symptom

Client logs `wireguard: handshake did not complete after 5 seconds`.
`octravpn_wg_handshake_fail_total` ticks up on your side, fires
`OctravpnWgHandshakeFailures` warning at 0.1/s sustained.

### Cause — UDP 51820 firewall

**Recipe.** Confirm 51820 is open inbound UDP:

```bash
sudo ufw status                       # Ubuntu / Debian
sudo firewall-cmd --list-all          # Fedora / RHEL family

# From outside the host:
nc -zvu <public-ip> 51820
```

Stateful firewalls + NAT will sometimes drop the first UDP packet of a
new flow; a one-shot probe failing is not conclusive. Watch the
counter over a 5m window.

### Cause — MTU mismatch

**Symptom.** Handshake completes intermittently but data-plane
packets larger than ~1280 bytes are silently dropped. Clients report
"works for ping, hangs on file downloads."

**Recipe.** Set `[tunnel].mtu = 1280` in `node.toml`. WireGuard's
overhead is 32 bytes on IPv4 / 52 bytes on IPv6; the on-wire MTU your
upstream actually carries is usually 1500 minus PPPoE/IPSec/GRE
headers. 1280 is conservative and always works.

### Cause — `disco_key` not propagating (Wall-7, rare)

**Symptom.** A specific subset of clients (typically stock Tailscale
v1.78+) handshakes fine on the control plane (`/map` returns OK) but
WireGuard never completes. Your logs show `disco: unknown disco_key
mkey:…` for that node.

**Status.** Known but rare. The wire-layer `disco_key` registration
went in at Wall-7 (the tailscale-interop work); a stale daemon that
predates the fix won't forward `disco_key` from `/map` to the
boringtun peer table.

**Recipe.** Confirm your daemon version is past the Wall-7 fix
(`octravpn-node --version` post-2026-Q1). If older, upgrade via your
package manager. If newer and still affected, file an issue with the
client's noise pubkey, your daemon version, and a 1-minute audit-log
slice spanning the failed handshake.

---

## Audit log won't verify

### Symptom

`octravpn-node audit verify` exits non-zero with a chain-break or
HMAC-mismatch error. The alertmanager fires
`OctravpnReceiptSigningStalled` because the journal floor disagrees
with the log.

### Cause — HMAC key drift

The HMAC key file conventionally lives at `<audit_dir>/.audit.key`
(or `<audit_path>.key` for single-file layouts). If the file was
moved, regenerated, or copied from a different node, every line of
the log fails verification.

**Recipe.**

```bash
# Try the canonical discovery first:
octravpn-node audit verify \
    --audit-path /var/lib/octravpn/state/audit.log

# Or point at the key explicitly:
octravpn-node audit verify \
    --audit-path /var/lib/octravpn/state/audit.log \
    --hmac-key   /var/lib/octravpn/state/.audit.key
```

If the key truly is lost, the audit log is no longer cryptographically
verifiable — preserve it as evidence and start a fresh audit dir.

### Cause — file truncation

**Symptom.** Verify reports `unexpected EOF mid-line` at line N.

**Cause.** Disk filled (kernel killed an `fsync`), or someone ran
`>file` instead of `>>file` to the log path.

**Recipe.**

```bash
# Find the disk filling issue:
df -h /var/lib/octravpn
journalctl -u octravpn-node | grep -i "no space"

# Rotate and start a fresh file:
sudo systemctl stop octravpn-node
mv /var/lib/octravpn/state/audit.log /var/lib/octravpn/state/audit.log.broken
sudo systemctl start octravpn-node
# The daemon writes a fresh audit-YYYY-MM-DD.jsonl with a fresh HMAC
# state. The .broken file is preserved for forensics.
```

### Cause — `FileVerifyReport.signed_seqs` cross-check failure

**Symptom.** Verify exits 0 on HMAC chain integrity but `receipt-verify
<session-id>` reports an audit-log entry whose `seq` is above the
journal's recorded floor for that session.

**Status.** This is the P1-8/9 invariant violation the operator
surfaces are designed to catch. The
[`FileVerifyReport`](../../crates/octravpn-node/src/audit/verify.rs)
returns a `signed_seqs: BTreeMap<sid, BTreeSet<seq>>` so the CLI can
walk both sides without a second pass through the log.

**Recipe.** Treat as a forensic event:

```bash
# 1. Pinpoint the offending session.
octravpn-node receipt-verify <session-id-hex> \
    --journal-path /var/lib/octravpn/state/receipts.bin \
    --audit-path   /var/lib/octravpn/state/audit.log \
    --json > /tmp/receipt-incident.json

# 2. Walk the log slice for the same session id manually:
octravpn-node audit replay \
    --audit-path /var/lib/octravpn/state/audit.log \
    --session-id <hex>
```

Either the journal was rolled back (file restored from backup —
recover by reseeding from the audit log), or a process other than the
daemon wrote receipts (very bad — implies key compromise; rotate per
[`tour-operator.md` §key compromise](tour-operator.md#key-compromise--emergency-unseal--fresh-wallet-rotation)).

---

## Where to next

- The full tour through everything above:
  [`tour-operator.md`](tour-operator.md).
- General troubleshooting (client-side, chain-side):
  [`../troubleshooting.md`](../troubleshooting.md).
- Mainnet runbook (every flag for every step):
  [`mainnet-deployment.md`](mainnet-deployment.md).
- Dashboards that surface the symptoms above:
  [`dashboards.md`](dashboards.md).
