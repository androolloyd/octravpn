# Operator tour — first 90 days

A guided walkthrough from "I want to run an OctraVPN validator" to "I'm
serving paid sessions and my bond is slash-resistant." Twelve numbered
steps you can follow in order, plus day-30 and day-90 maintenance
markers.

Where this fits in the docs tree:

- This file — the **tour**. Sequential. Skim once, then follow with the
  CLI open in another terminal.
- [`mainnet-deployment.md`](mainnet-deployment.md) — the reference
  runbook. Read it after the tour when you need every flag and every
  port.
- [`v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md) — the
  fresh-wallet doctrine and the `seal-keys` recipe. **Step 1 below
  summarises this; read the full doc before mainnet.**
- [`v3/call-flows.md`](../v3/call-flows.md) — every on-chain entrypoint
  the tour invokes, with revert reasons. Use as a debugging reference
  when a `v3 …` command reverts.
- [`troubleshooting.md`](troubleshooting.md) — per-symptom diagnostics
  for the things in this tour that go wrong.
- [`dashboards.md`](dashboards.md) — the Grafana panels referenced in
  steps 9 and 10.

Every CLI command in this tour exists today. If a flag looks wrong, run
`octravpn-node --help`, then `octravpn-node <subcmd> --help` —
`clap`-derived help is the source of truth.

---

## Pre-flight

### Hardware

| Resource | Floor | Comfort |
| --- | --- | --- |
| CPU | 2 vCPU x86_64 or arm64 | 4 vCPU |
| RAM | 1 GiB | 4 GiB |
| Disk | 10 GiB SSD | 50 GiB SSD |
| Network | 100 Mbit/s symmetric, unmetered | 1 Gbit/s |

The audit log grows ~200 bytes per signed receipt. At a sustained
1 MiB/s of paid traffic that's roughly 100 MiB of audit log per day; plan
log rotation if you expect more. See
[`mainnet-deployment.md` §9](mainnet-deployment.md).

### Network

| Port | Direction | Protocol | Purpose |
| --- | --- | --- | --- |
| 443 | inbound | TCP | TLS-terminated control plane (`/key`, `/ts2021`, `/machine/…`) |
| 51820 | inbound | UDP | WireGuard data plane |
| 51821 | inbound | TCP | Plain-HTTP control + `/metrics` + `/health` (loopback or private network only) |
| 51823 | inbound | TCP | Analytics indexer `/metrics`, `/analytics/series`, `/analytics/health` (optional) |
| any | outbound | TCP/443 | Chain RPC + DERP relay |

51823 is the analytics-indexer default ([`config.rs` `default_analytics_listen`](../../crates/octravpn-node/src/config.rs));
keep it on loopback unless you front it with a reverse proxy that
terminates TLS and bearer-auth.

### OS

Per [`release.md`](../release.md): Ubuntu 22.04/24.04, Debian 12,
Rocky/RHEL/Alma 9, Fedora 39+, amd64 + arm64. Other distros build from
source.

### A note on funding wallet hygiene — DO NOT SKIP

Read [`v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md)
before continuing. The summary that drives Step 1 below:

- The wallet you use to `register` your circle is **on-chain forever**
  as the operator of that circle. Every governance call you make
  re-binds it.
- If that wallet has ever touched a DEX, your salary, a faucet you
  signed up for with your real email, or any other identifiable
  service, the operator role inherits all of that linkability.
- **The fix is mechanical: generate a brand-new wallet for every
  operator circle.** Fund it via stealth send from your main wallet.
  Never reuse it for anything else.

That's it — the rest of the hygiene doc fills in mechanics. Steps 1
and 2 below execute the rule.

---

## Step 1 — Generate a fresh single-purpose deploy wallet

```bash
# Generate a new wallet — outputs address + secret hex
octra cast wallet new
# Example:
#   address: oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm
#   secret : f14173ec...   (HEX, 32 bytes)
```

Save the secret hex to cold storage (paper, hardware key, encrypted
USB). Then write it to disk encrypted:

```bash
octra cast wallet encrypt \
    --secret-hex f14173ec...60252b3 \
    --out ~/.octra/op-2026-Q2.wallet
# Prompts for a passphrase; envelope is OCTRA-WALLET-V1.
```

Verify the file actually got encrypted (no plaintext hex visible):

```bash
file ~/.octra/op-2026-Q2.wallet
xxd ~/.octra/op-2026-Q2.wallet | head -1
# First 16 bytes must read "OCTRA-WALLET-V1\0"
```

The envelope is PBKDF2-HMAC-SHA256 (200k iters) → ChaCha20-Poly1305.
Implementation lives in the sibling `octra-foundry` workspace
(`octra-foundry/crates/octra-core/src/wallet_enc.rs`); see
[`v2-operator-key-hygiene.md §2`](../v2-operator-key-hygiene.md) for
the audit pointers.

**Do not** reuse a wallet from another operator deployment. If you're
running two operator circles, that's two wallets.

---

## Step 2 — Fund via stealth send from your main wallet

```bash
# From a funding wallet that holds OCT. The output is unlinkable to
# the funding wallet on chain.
octra cast stealth send \
    --to oct8Tdgu...   # the fresh wallet from step 1
    --amount 1010_000_000  # 1010 OCT — bond (1000) + gas headroom (~10)
```

Then verify the destination wallet sees the balance:

```bash
octra cast balance --addr oct8Tdgu...
```

For the alternative funding paths (devnet faucet, mixer) see
[`v2-operator-key-hygiene.md §3`](../v2-operator-key-hygiene.md).

> The fresh wallet should now be the **only** wallet that will ever
> sign operator-circle transactions. From here on, every command in
> this tour uses that wallet as `[chain].wallet_secret_path` in
> `node.toml`.

---

## Step 3 — Install `octravpn-node`

The per-OS install paths (`.deb`, `.rpm`, macOS `.pkg`, Windows `.msi`,
Homebrew, source build) live in [`docs/install.md`](../install.md).
Pick one and run it.

Post-install sanity:

```bash
octravpn-node --version
octravpn-node --help            # see the top-level subcommand list
octravpn-node v3 --help         # every non-boot v3 entrypoint
octravpn-node headscale --help  # embedded tailnet admin CLI
```

Each subcommand has its own `--help`. Anything that looks like it
should exist but isn't there, run `--help` first.

After install, lay out the state dir per the package's postinst
(`/etc/octravpn/`, `/var/lib/octravpn/`, `/var/log/octravpn/`) and
write a minimal `node.toml` per [`mainnet-deployment.md §3`](mainnet-deployment.md).
The tour assumes `/etc/octravpn/node.toml` from here on.

---

## Step 4 — Seal the wallet + WG keys

Plaintext keys on disk is the most common foot-gun on a production
host. `seal-keys` wraps both the wallet secret and the WireGuard static
key under one passphrase envelope:

```bash
# Pick a strong passphrase. The threat model assumes ≥ 64 bits of
# entropy against PBKDF2-200k brute force.
export OCTRAVPN_KEY_PASSPHRASE="$(openssl rand -base64 24)"

# Seal both keys. Writes <path>.sealed atomically; keeps the
# plaintext sources for now so you can verify the daemon boots before
# you delete them.
octravpn-node --config /etc/octravpn/node.toml seal-keys
```

Confirm the sealed envelope is real:

```bash
xxd /etc/octravpn/wg.key.sealed | head -1
# First 16 bytes: "OCTRA-WALLET-V1\0"
```

Now point your TOML at the sealed paths AND enable strict mode:

```toml
[chain]
wallet_secret_path  = "/etc/octravpn/wallet.key.sealed"
require_sealed_keys = true

[tunnel]
wg_secret_path = "/etc/octravpn/wg.key.sealed"
```

Once the daemon boots cleanly (step 8), come back and run:

```bash
octravpn-node --config /etc/octravpn/node.toml seal-keys --remove-plaintext
```

Passphrase resolution order (per
[`cli/seal.rs`](../../crates/octravpn-node/src/cli/seal.rs)):
`--passphrase` > `--passphrase-file` > `--passphrase-stdin` >
`OCTRAVPN_KEY_PASSPHRASE` env > TTY prompt. systemd-launched daemons
have no TTY — use `EnvironmentFile=/etc/octravpn/keys.env` per
[`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md).

If the daemon refuses to boot with `PlaintextKeyOnDisk`, see
[`troubleshooting.md`](troubleshooting.md#daemon-wont-boot).

---

## Step 5 — Validate the config

Before bonding any OCT or making any chain transaction, prove your
`node.toml` is internally consistent and your RPC + program are
reachable:

```bash
octravpn-node config validate /etc/octravpn/node.toml
```

This is the `#232` operator surface and it covers:

- TOML schema parses cleanly.
- Both configured key files load (sealed or plaintext, per strict mode).
- The RPC endpoint at `[chain].rpc_url` is reachable.
- The deployed `[chain].program_addr` responds to a no-side-effects view
  call (`get_params`).

Exit code 0 means every check passed. Non-zero exits with the first
failure surfaced. Add `--json` to feed downstream tooling.

If you're in an air-gapped CI shell, `--offline` skips the chain
probes:

```bash
octravpn-node config validate --offline /etc/octravpn/node.toml
```

---

## Step 6 — Bond the operator stake

Bonding deposits your operator stake into `circle_bond[circle]` on
chain. Without a bond, `register` cannot complete (slash-resistant
operation requires skin in the game).

```bash
octravpn-node --config /etc/octravpn/node.toml bond --amount 1000000000
# 1_000_000_000 OU = 1000 OCT (the default MIN_CIRCLE_STAKE)
```

The CLI takes `--amount` in raw OU (1 OCT = 1_000_000 OU). The
v1.1-style `bond` subcommand top-ups the current operator's circle; if
you're working from a different circle id, use the v3 form:

```bash
octravpn-node v3 bond --circle oct… --amount 1000000000
```

Both call `payable bond_endpoint(circle)` — see
[`v3/call-flows.md` §bond_endpoint](../v3/call-flows.md).

If this command fails with "insufficient balance", you didn't fund the
deploy wallet with enough OCT in step 2 (need 1000 + gas).

---

## Step 7 — Register the operator circle

Register binds your endpoint on chain. In v3 this is the
`register_circle` boot flow — atomic register + bond + receipt-pubkey
binding. The daemon's `register` subcommand drives it in one call:

```bash
octravpn-node --config /etc/octravpn/node.toml register
```

What goes on chain:

- `circle_owner[circle] = your fresh wallet`
- `circle_receipt_pk[circle] = derived from your WG static key`
- `circle_state_root[circle] = sha256 of the initial /policy.json`
- `circle_active[circle] = 1`

Full call-flow + revert reasons:
[`v3/call-flows.md` §1 `register_circle`](../v3/call-flows.md).

`register` is **idempotent**: re-running on an already-registered
circle is a no-op. Safe to put in your deploy script.

If `register` reverts with `"previously slashed"`, the circle id has a
slash record on chain — you need a fresh circle id, which means a fresh
wallet (back to step 1).

---

## Step 8 — Boot the daemon

```bash
# Either via systemd (preferred — installed by the .deb/.rpm postinst):
sudo systemctl start octravpn-node

# Or directly in the foreground for the first boot, so you can read
# the startup logs:
octravpn-node --config /etc/octravpn/node.toml run
```

A clean boot logs roughly:

```text
[INFO] config schema validated
[INFO] strict sealed-keys: wallet+WG loaded from envelope
[INFO] chain RPC ok program_addr=oct…
[INFO] receipt journal opened at ./state/receipts.bin (floor=0)
[INFO] audit log opened ./state/audit-2026-05-20.jsonl (key OK)
[INFO] control plane listening on 127.0.0.1:51821
[INFO] WireGuard listening on 0.0.0.0:51820
[INFO] DERP relay reachable
[INFO] attestation loop started, period=30s
```

If the daemon dies before "attestation loop started", see
[`troubleshooting.md#daemon-wont-boot`](troubleshooting.md#daemon-wont-boot).

---

## Step 9 — Verify the loop is alive

Two probes that cover everything:

```bash
# 1. Local + remote health roll-up. Reads on-chain stake + slashed +
#    unbonding state, then hits the running daemon's GET /health.
octravpn-node health \
    --config /etc/octravpn/node.toml \
    --remote http://localhost:51821
```

Healthy output reports `attested_within: <30s`, `stake: 1000000000 OU`,
`slashed: false`, `unbonding: false`. JSON form: `--json`.

```bash
# 2. Mesh roster — confirms the tailnet control plane is wired.
#    Replaces the deprecated `mesh status`.
octravpn-node headscale nodes list \
    --server http://localhost:51821 \
    --token "$HEADSCALE_ADMIN_TOKEN"
```

An empty roster is fine for a fresh operator — the first member
registration happens in step 10. What you want is a clean response,
not an error.

Open the Grafana dashboard (`OctraVPN — Overview`) at this point. Every
panel should be green and reporting a value, with `Active sessions`
at 0. Setup: [`dashboards.md`](dashboards.md).

---

## Step 10 — Your first session arrives

A client opens a session via the v3 `open_session(tailnet_id, circle,
max_pay)` flow (see [`v3/call-flows.md` §open_session](../v3/call-flows.md)).
On your side, three things happen in parallel:

**Logs.** `journalctl -u octravpn-node -f` will show:

```text
[INFO] session opened id=<32-byte-hex> tailnet=<id> max_pay=<ou>
[INFO] receipt seq=0 bytes=0 signed
[INFO] receipt seq=1 bytes=<n> signed
…
```

**Audit log.** Pipe-tail with HMAC verification on every line — a chain
break interrupts output with a clear marker:

```bash
octravpn-node audit-tail --follow --audit-path /var/lib/octravpn/state/audit.log
```

The same path lives behind `octravpn-node audit replay` (one-shot
pretty-print) and `audit verify` (full crypto verification across the
whole file).

**Metrics.** On the Grafana overview dashboard:

- `octravpn_active_sessions` → 1 (then increments).
- `octravpn_receipts_signed_total` → rising at the receipt cadence.
- `octravpn_bytes_served_total` → rising.

If `bytes_served` rises but `receipts_signed` is flat, the
`OctravpnReceiptSigningStalled` alert will fire in 5m. That means the
receipt journal floor has rejected a write (P1-8/9 invariant) — see
[`troubleshooting.md#sessions-opened-but-no-receipts`](troubleshooting.md#sessions-opened-but-no-receipts).

---

## Step 11 — Settle the closed session

When the client stops paying, the session closes. The two-tx settle is
deliberate (audit-2026-05-20 §C-1 made this halfway-honest design call):

**Half 1 — operator side.** You submit `settle_claim(session_id,
bytes_used)`:

```bash
octravpn-node settle-claim --session-id <id> --bytes-used <n>
# or the v3 form:
octravpn-node v3 settle-claim --session-id <id> --bytes-used <n>
```

The chain remembers `(session_id, bytes_used)` against your circle's
receipt pubkey. **Equivocation — submitting a different `bytes_used`
for the same session id, ever — triggers `slash_double_sign`
in AML.** The operator side of that contract is enforced by the chain;
you cannot ever "fix" a wrong `bytes_used` retroactively. Get it right
the first time. The byte count comes from your receipt journal floor
([`receipt-verify`](#operator-day-30-maintenance) verifies it).

**Half 2 — opener side.** The client submits `settle_confirm(session_id,
bytes_used, net, settle_blinding)`. If the opener's `bytes_used`
matches yours, the settle credits your earnings ledger. If they
disagree, the session enters dispute.

> **Open audit finding.** Dispute is currently a permanent
> stuck-funds state — there is no chain-side resolver. See
> [`docs/audit/2026-05-20-deep-security-audit.md` §C-1](../audit/2026-05-20-deep-security-audit.md).
> Mitigation today: be a good operator. Sign receipts honestly,
> settle them honestly, monitor for client opener equivocation in
> your audit log.

If the opener never submits `settle_confirm`, after `session_grace`
they can call `claim_no_show(session_id)` to recover their deposit.
After `opened_at + session_grace * sweep_multiplier`, *anyone* can call
`sweep_expired_session(session_id)` for a bounty
([`v3/call-flows.md` §sweep](../v3/call-flows.md)).

---

## Step 12 — Claim your earnings

Earnings accumulate in `circle_earnings_total[circle] -
circle_earnings_claimed[circle]`. Pull them when you want:

```bash
# v1.1-style — pulls all unclaimed earnings for your current circle.
octravpn-node claim-earnings

# v3 form — pull a specific amount from a specific circle.
octravpn-node v3 claim-earnings --circle oct… --amount 1000000000
```

The earnings hit your operator wallet as a native Octra transfer. From
there it's your call — keep in the operator wallet, send to a cold
wallet, send to an exchange. **Reminder:** anything that wallet does
re-binds its on-chain history. Use a stealth send to anywhere else.

If the call reverts with `"insufficient earnings"`, the amount you
asked for exceeds your current `total - claimed`. Query with:

```bash
octra cast call <program_addr> get_circle_earnings <circle_id>
```

---

## Day-30 maintenance

By day 30 you should have a few weeks of receipts and a couple of
audit-log rotations. Two things to do:

### Rotate the sealed-keys passphrase

Quarterly cadence is the default, but doing one at the day-30 mark
gives you a known-good rehearsal before any real incident:

1. Pick a fresh passphrase.
2. `unseal-keys --tmpdir /run/octravpn-rotate` (refuses to write to
   anything that isn't tmpfs/ramfs).
3. Re-seal the now-plaintext files under the new passphrase
   (`seal-keys` is idempotent — re-running on the same source is a
   no-op when the destination already exists; rotate by passing
   `--remove-plaintext` after manual `unseal` + `seal` with the new
   PP).
4. Update `OCTRAVPN_KEY_PASSPHRASE` in your secret store.
5. Restart the daemon (`systemctl restart octravpn-node`); strict-mode
   `[chain].require_sealed_keys = true` validates the new envelope on
   boot.

The full rotation runbook for the **PVAC, TLS, and policy
passphrases** lives in:

- [`pvac-rotation.md`](pvac-rotation.md) — PVAC keypair.
- [`tls-rotation.md`](tls-rotation.md) — the rustls cert behind
  `mesh serve --https-listen :443`.
- [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md) —
  the sealed-asset (`/policy.json`) passphrase.

### Cross-check the receipt journal against the audit log

```bash
octravpn-node receipt-verify <session-id-hex> \
    --journal-path /var/lib/octravpn/state/receipts.bin \
    --audit-path   /var/lib/octravpn/state/audit.log
```

This walks the receipt-journal floor for the session and reports
every audit-log entry naming the same session. Drift = a forensic
event — see
[`audit/README.md`](../../crates/octravpn-node/src/audit/README.md)
for what `FileVerifyReport.signed_seqs` cross-checks.

---

## Day-90 ops — monitoring + alerting

By day 90 you've got enough metric history to set thresholds that
aren't a guess. Concrete actions:

### Wire the dashboards

The pack at
[`deploy/observability/`](../../deploy/observability/) ships:

- `grafana/octravpn-overview.json` — fleet view (sessions, settlements,
  WG handshakes, slash events).
- `grafana/dashboards/octravpn-analytics.json` — the #231 historical
  indexer view (sessions/sec, claims/sec, treasury bytes, slash events
  with retention).

Standing them up: [`dashboards.md`](dashboards.md).

### Enable the analytics indexer

In `node.toml`:

```toml
[analytics]
enabled = true
listen  = "127.0.0.1:51823"
# token  = "<bearer>"   # gate /metrics + /analytics/series
```

Then the daemon spawns an in-process indexer that watches your audit
log and exposes:

- `GET /metrics` — Prometheus counters per tumbling bucket.
- `GET /analytics/series?metric=<name>&bucket=<window>` — the
  underlying JSON time series.
- `GET /analytics/health` — `first_break` from the chain-verify
  walker, unauthenticated.

Per-window metric names:
`octravpn_analytics_sessions_opened{window="5m"}`,
`…_claims_settled{window="5m"}`, `…_receipts_signed{window="5m"}`,
`…_treasury_bytes{window="1d"}`, `…_slash_events{window="1d"}`.

### Alertmanager rules

Shipped at [`deploy/observability/alerts.yml`](../../deploy/observability/alerts.yml).
Critical pages (`OctravpnNodeDown`, `OctravpnAttestationStale`,
`OctravpnSlashEvent`) should route to PagerDuty / Opsgenie / phone.
Warnings (`OctravpnReceiptSigningStalled`,
`OctravpnSessionMapNearCap`, `OctravpnRPCErrorRate`,
`OctravpnPreauthMintsBurst`, `OctravpnWgHandshakeFailures`) should
route to a chat channel.

The rule files reference runbooks in
[`docs/observability.md`](../observability.md) — make sure your
Alertmanager `runbook_url` annotations resolve to your fork's path if
you self-host the docs.

---

## Common failure modes + recovery

### Equivocation — slash detection → bond loss → recovery

**Symptom.** Your bond shrinks unexpectedly. `octravpn-node health`
reports `slashed: true`. The Grafana panel
`Slash events (lifetime)` ticks up. The alertmanager fires
`OctravpnSlashEvent` (critical).

**Root cause.** Either you submitted two `settle_claim` calls with
different `bytes_used` for the same session id (operator bug — almost
always a copy/paste error from the receipt journal), or your receipt
pubkey signed two distinct payloads that some watcher submitted via
`slash_double_sign`.

**Recovery.**

1. Stop the daemon.
2. `audit verify` the local audit log to find the two conflicting
   entries:

   ```bash
   octravpn-node audit verify \
       --audit-path /var/lib/octravpn/state/audit.log
   ```

3. The bond is gone. The circle is permanently `slashed = 1` and
   cannot be re-registered.
4. Generate a fresh wallet (back to step 1), deploy a new circle id,
   register it.
5. **Diagnose first**, otherwise the new circle will hit the same
   slash. The two most common causes are (a) you re-keyed the receipt
   pubkey but kept the old journal, so a "replay" wrote a fresh
   `bytes_used` for an old session; (b) you ran two nodes against the
   same circle id and they raced — never do this.

### Network outage → session sweep

**Symptom.** Your machine was offline during a session. When you come
back online, some sessions are gone (a sweeper called
`sweep_expired_session` and earned a bounty).

**Recovery.** Nothing to do — sweeping pays the **sweeper**, not you,
and refunds the opener the un-spent deposit. The sessions you sweep are
revenue lost. Mitigation: hot standby and shorter `session_grace` if
your environment allows it. Per
[`v3/call-flows.md` §sweep](../v3/call-flows.md), the sweep window is
`opened_at + session_grace * sweep_multiplier`.

### Key compromise → emergency unseal → fresh wallet rotation

**Symptom.** You suspect your sealed-keys passphrase leaked (committed
to a repo, posted in a chat, stored in a plaintext `.env` that was
backed up to the wrong place).

**Recovery — under 15 minutes if the rotation rehearsal in day-30 was
done.**

1. **Immediately** retire the operator circle on chain:

   ```bash
   octravpn-node v3 retire --circle <id>
   # flips circle_active[circle] = 0; no new sessions can open
   ```

2. Stop the daemon. **Do not** restart it until step 5.
3. Emergency unseal the keys onto tmpfs:

   ```bash
   octravpn-node unseal-keys --tmpdir /run/octravpn-rescue
   ```

   The destination MUST be on a tmpfs/ramfs mount; the CLI refuses
   anything else (per
   [`cli/seal.rs`](../../crates/octravpn-node/src/cli/seal.rs)).

4. Rotate the receipt pubkey on chain so future receipts use a new
   key. Generate a new WG static key first, derive its ed25519 pubkey,
   then:

   ```bash
   octravpn-node v3 rotate-receipt-pubkey \
       --circle <id> --new-pubkey-b64 <44-char-b64>
   ```

5. Generate a **fresh wallet** (back to step 1). The compromised
   wallet's residual stake can be reclaimed via
   `v3 unbond` + `v3 finalize-unbond` after the grace period
   ([`v3/call-flows.md` §unbond](../v3/call-flows.md)), but the
   operator role itself moves to the new wallet via a fresh
   `register` against a fresh circle id.

If the compromise included the WG private key itself, every receipt
signed under it is potentially repudiable; you cannot "fix" old
sessions but the new circle starts clean.

---

## Where to next

- Tailnet-owner workflows (control the member set + policy + treasury):
  [`docs/tailnet-owners/tour-owner.md`](../tailnet-owners/tour-owner.md).
- DERP fronting, obfs4 bridges, the obscure shielding stack:
  [`derp-fronting.md`](derp-fronting.md), [`obfs4-bridge.md`](obfs4-bridge.md).
- The CLI migration table (`mesh status` → `headscale nodes list`
  etc.): [`cli-migration.md`](cli-migration.md).
- Per-symptom debugging: [`troubleshooting.md`](troubleshooting.md).
- The reference runbook: [`mainnet-deployment.md`](mainnet-deployment.md).

If you got here, you're an operator. Welcome.
