# Validator / Endpoint Operator Guide

This guide is for **Octra validators** who want to also run a paid
OctraVPN endpoint — a relay (for tailnet members behind NAT) and/or
an exit node (for anonymous internet egress). It assumes you're
already familiar with running a validator at the protocol layer.

## What you need

- A registered Octra protocol validator wallet. The OctraVPN program
  refuses to register endpoints for anyone who isn't currently an
  Octra validator.
- A public IP on UDP 51820 (or whatever you set as `tunnel.listen`).
- Linux/macOS/Windows server with the `octravpn-node` binary
  installed.
- Patience for a small number of OU in fees while you experiment.

## 1. Install

Prebuilt binaries (preferred):

```sh
# macOS / Linux
curl -L -o octravpn-node \
    https://github.com/anthropic/octravpn/releases/latest/download/octravpn-node-$(uname -s)-$(uname -m)
chmod +x octravpn-node
sudo mv octravpn-node /usr/local/bin/

# Or via cargo:
cargo install --path crates/octravpn-node
```

Verify with `octravpn-node --version`.

## 2. Generate keys

The node needs two on-disk keys:

```sh
# Wallet (used to sign tx). Reuse your validator wallet.
cp ~/.octra/wallet.hex /etc/octravpn/wallet.hex
chmod 600 /etc/octravpn/wallet.hex

# WireGuard master (a 32-byte secret from which receipt-signing +
# noise keys are derived via HKDF):
octravpn keygen --out /etc/octravpn/wg.key
chmod 600 /etc/octravpn/wg.key
```

Optionally encrypt the wallet at rest:

```sh
OCTRAVPN_WALLET_PASSPHRASE=$(read -s) octravpn wallet-encrypt \
    --in /etc/octravpn/wallet.hex \
    --out /etc/octravpn/wallet.enc
```

The daemon will read either format; encrypted wallets need the
passphrase via `OCTRAVPN_WALLET_PASSPHRASE` env var at start.

## 3. Configure

`/etc/octravpn/node.toml`:

```toml
[chain]
rpc_url            = "https://rpc.octra.network"
program_addr       = "octPROG..."        # the deployed OctraVPN program
validator_addr     = "octV..."           # your Octra validator address
wallet_secret_path = "/etc/octravpn/wallet.hex"

[tunnel]
public_endpoint    = "203.0.113.7:51820"   # what clients dial
listen             = "0.0.0.0:51820"
wg_secret_path     = "/etc/octravpn/wg.key"

[pricing]
price_per_mb       = 100                   # 100 OU = 0.0001 OCT per MB
region             = "eu-west"

[control]
listen             = "127.0.0.1:51821"
audit_dir          = "/var/log/octravpn/audit"

[attestation]
poll_interval_secs = 30
```

A couple things to know:

- `validator_addr` is your operator wallet (the v1 model dropped
  the Octra-validator gate; you stake in-program instead).
- `price_per_mb` is in raw OU. At 100 OU/MB and 1 GB/hr of relayed
  traffic, you earn ~100 000 OU/hr = 0.1 OCT/hr.

## 4. Bond + register the endpoint

Two-step setup (one-time):

```sh
# Step 1: bond stake (>= MIN_ENDPOINT_STAKE = 1000 OCT = 10^9 OU)
sudo octravpn-node bond --amount 1000000000 --config /etc/octravpn/node.toml

# Step 2: register the endpoint on chain
sudo octravpn-node register --config /etc/octravpn/node.toml
```

The register step:

1. Reads `get_endpoint_stake(validator_addr)` and confirms
   `>= MIN_ENDPOINT_STAKE`. Bails out with a clear message if your
   bond is short.
2. Submits `register_endpoint(endpoint, wg_pub, hfhe_pub,
   initial_enc_zero, region, price_per_mb, receipt_pubkey)` to the
   program. The 7th param is your **ed25519 receipt-signing pubkey**
   (HKDF-derived from `wg_secret` at startup) and is what the v1.1
   `slash_double_sign` entrypoint will verify against if you ever
   sign two contradictory receipts for the same `(session, seq)`.
   Lose your `wg_secret` and an attacker can sign on your behalf →
   bond is at risk; treat the file as 0600 and back it up.
3. Logs the resulting tx hash.

`register` is idempotent; you can re-run it safely. The chain
remembers your endpoint until you `retire_endpoint` or
`unbond_endpoint`.

## 5. Run

```sh
sudo octravpn-node run --config /etc/octravpn/node.toml
```

Or via systemd (a unit file ships in `deploy/systemd/`):

```sh
sudo systemctl enable --now octravpn-node
```

The daemon:

- Re-checks Octra-validator membership every `poll_interval_secs`.
  If you lose validator status, a warning lands in the log; clients
  will stop using you immediately (the program's session
  settlements gate on the chain-side check).
- Serves the WireGuard tunnel.
- Serves the HTTP control plane (used by clients to fetch dual-signed
  receipt proposals at settlement).
- Writes an HMAC-chained audit log to `audit_dir`. Tamper detection
  via `octravpn-node verify-audit-log <file>` (any altered or removed
  line is reported by index).

## 5a. TLS for the control plane

For production we expect operators to terminate TLS at a reverse
proxy. Two reasons:

1. WireGuard already encrypts the data plane end-to-end — the control
   plane carries only session-announce + receipt-proposal payloads,
   neither of which is sensitive on the wire (the receipt is signed
   by both ends, the announce is just a session id + ephemeral pubkey).
2. Cert lifecycle (Let's Encrypt, renewals, OCSP stapling) is well
   solved by Caddy / nginx / traefik. Embedding rustls into the node
   binary would duplicate that without operational benefit.

### Caddy

```caddy
control.example.com {
    reverse_proxy http://127.0.0.1:51821
}
```

That's the whole config. Caddy auto-provisions a certificate via
Let's Encrypt. Bind the node to `127.0.0.1:51821` (not `0.0.0.0`) and
point Caddy at it.

### nginx (with snippets)

```nginx
server {
    listen 443 ssl;
    server_name control.example.com;
    ssl_certificate     /etc/letsencrypt/live/control.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/control.example.com/privkey.pem;
    ssl_protocols       TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:51821;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # SSE keepalive for `/events`.
        proxy_buffering off;
    }
}
```

Either way, set the node's `[control].listen` to `127.0.0.1:51821`
so it's unreachable except through the proxy.

### Why not embed TLS?

We deliberately didn't bundle rustls in `octravpn-node`. Pros of
embedding (single binary, no proxy dependency) don't outweigh the
ops cost (cert rotation, ACME plumbing, ALPN negotiation). The
crate stays small; ops use whatever proxy they already run.

## 6. Inspect

Health: `curl -s http://localhost:51821/health`

```json
{
  "status": "ok",
  "uptime_s": 12345,
  "last_attestation_unix": 1715212345
}
```

Returns HTTP 503 if you've gone stale (no Octra-validator
confirmation in >5 minutes); operators should alert on this.

Metrics: `curl -s http://localhost:51821/metrics`

```
octravpn_announces_total 42
octravpn_state_lookups_total 100
octravpn_receipts_signed_total 38
octravpn_bytes_served_total 1023456
octravpn_active_sessions 7
octravpn_last_attestation_unix 1715212345
octravpn_uptime_seconds 12345
```

Plug into Prometheus / Grafana for production dashboards.

## 7. Claiming earnings

Earnings accumulate as an encrypted Pedersen commitment on chain.
Periodically claim them out:

```sh
sudo octravpn-node claim-earnings --config /etc/octravpn/node.toml
```

This:

1. Reads the local accumulator (`.acc` file next to your wallet).
2. Opens the on-chain Pedersen commitment against (amount, blind).
3. Submits a `claim_earnings` tx; the chain emits a stealth output
   for the amount to your derived view-pubkey.
4. Resets the local accumulator to zero.

You can also do this every settlement via a cron job; nothing
prevents claiming small amounts often (other than tx fees making it
not worth it).

## 8. Retiring

If you want to wind down:

```sh
sudo octravpn-node claim-earnings --config /etc/octravpn/node.toml
sudo octravpn-node retire --config /etc/octravpn/node.toml
sudo systemctl stop octravpn-node
```

`retire_endpoint` flips `active = 0` on your endpoint record; the
chain stops listing you for discovery and stops accepting new
sessions against you.

## 8a. Auditing receipt activity

The daemon writes two persistent forensic artifacts:

  - `audit_dir/audit-YYYY-MM-DD.jsonl` — one HMAC-chained record per
    state-changing request (announce, receipt_signed, lag, etc.).
  - `state/receipts.bin` — the per-session receipt-seq floor
    (P1-8/P1-9). One record per session_id: the highest seq the node
    has ever committed to signing.

Two operator commands inspect them. They run entirely off local files
— no chain or wallet access required — so you can run them on a
backup directory pulled from a hot-swapped host.

### `octravpn-node audit replay`

Pretty-print a merged timeline of every audit entry + every journal
record:

```sh
octravpn-node audit replay \
    --audit-path /var/log/octravpn/audit \
    --journal-path /var/lib/octravpn/receipts.bin
```

Output (example):

```
[2026-05-19T12:00:00Z]  session ab12cd…  announce  (audit)
[2026-05-19T12:00:03Z]  session ab12cd…  receipt_signed seq=1 bytes=1024  (audit)
[2026-05-19T12:00:06Z]  session ab12cd…  receipt_signed seq=2 bytes=2048  (audit)
[2026-05-19T12:00:08Z]  session ab12cd…  session_closed  (audit)
<no-ts>                 session ab12cd…  journal_floor seq=2  (journal)
```

Useful flags:

  - `--session <hex|u64>`  scope the timeline to a single session_id
    (either the 64-char hex form or the legacy v1 decimal u64).
  - `--since` / `--until`  Unix-seconds range filter.
  - `--format json`        one structured JSON object per line, for
    piping into `jq` or shipping to a log collector.

### `octravpn-node audit verify`

Full cryptographic verification:

```sh
octravpn-node audit verify \
    --audit-path /var/log/octravpn/audit \
    --journal-path /var/lib/octravpn/receipts.bin
```

Three checks run, in order:

  1. **Audit log HMAC chain.** Walks every line, recomputes
     `HMAC(key, prev_mac || record_json)`, and bails on the first
     mismatch with the offending line number.
  2. **Receipt journal monotonicity.** Confirms the on-disk codec
     parses, has the expected magic, and that no session_id repeats.
  3. **Cross-check.** Warns (not fails) when a journal record has no
     matching audit-log session_id, or vice versa. Asymmetry is
     normal — the audit log carries non-receipt entries like
     `announce` and `lag` — so this is informational only.

Exit codes are structured for shell harnesses:

  - `0` — all checks passed
  - `1` — verification failed (one of the strict checks)
  - `2` — IO or parse error (corrupt file, unreadable disk)
  - `3` — missing files (audit log absent, key file absent)

Run it nightly from cron; the chain break or duplicate-seq detection
is your in-the-loop signal that something has tampered with the log
or that the daemon crashed between journal-flush and journal-write.
If `verify` ever exits non-zero, snapshot the `audit_dir` and
`state/` directories before doing anything else — restarting may
overwrite the evidence.

The `verify-audit-log <path>` subcommand still exists as a deprecated
alias that runs only check (1); prefer `audit verify` going forward.

## 9. Operations checklist

- **Monitor `/health`**. Alert on 503 (stale attestation).
- **Watch the audit log**. It writes one JSONL entry per
  state-changing request. Run `octravpn-node audit verify` nightly to
  catch chain breaks (see §8a).
- **Backup `wallet.hex` + `wg.key` + `<wallet>.acc`**. The accumulator
  file lets you claim earnings even if you lose the chain history.
- **Mind the rate limiter**. Default 100 req/s sustained, 200 burst
  per source IP. If legitimate clients trip it (unlikely), bump it
  in code or fan out behind a reverse proxy.
- **Rotate the WireGuard master** if you suspect compromise — the
  receipt-signing subkey derives from it; clients have to re-handshake.

## 10. Economics quick reference

| Action                | Cost                                   |
| --------------------- | -------------------------------------- |
| Register endpoint     | One tx fee                             |
| Update endpoint       | One tx fee                             |
| Run                   | Bandwidth + electricity                |
| Claim earnings        | One tx fee + opening Pedersen          |

| Income                | Source                                 |
| --------------------- | -------------------------------------- |
| Per-byte relay fees   | `bytes_used × price_per_mb / 1M`       |
| (none from in-program bond) | (we don't bond at the app layer) |

You retain 100% of fees; the program takes no cut. Octra protocol
fees apply at the transaction layer as usual.

## 11. Help

- Logs: `journalctl -u octravpn-node` (systemd) or `octravpn-node`'s
  stdout when running standalone.
- Source: `crates/octravpn-node/`
- Issue tracker: https://github.com/anthropic/octravpn/issues
- Security: `SECURITY.md`

---

## 12. Running a v2 operator

The v2 substrate replaces the v1.1 `endpoints` map with an Octra
**Circle** (IEE) as the unit of operator identity. Pick the protocol
version with one flag; both are live on devnet and the same binary
serves both. **Source of truth: `docs/v2-operator-flow.md`** — this
section is orientation only.

### 12.1 v1.1 vs v2

```toml
[chain]
protocol_version = "v1.1"   # default; legacy bond + register path
protocol_version = "v2"     # opt in; 3-tx Circle-native boot
```

Devnet v2 program: `oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`.

### 12.2 The 3-tx v2 boot

`octravpn-node run` walks, persisting state after each step:

1. **`deploy_circle`** — submits an Octra tx with the canonical
   payload (`runtime=octb`, `privacy_class=sealed`); the resulting
   `circle_id` is content-addressed and predictable from `(deployer,
   nonce, payload)`.
2. **`circle_asset_put_encrypted /policy.json`** — encrypts the
   operator's runtime policy (endpoint URL, WG pubkey, region,
   tariffs, receipt pubkey) and uploads it. The chain sees only
   AES-GCM ciphertext + `key_id` + `plaintext_hash` + `resource_key`.
3. **`register_circle`** — payable contract call carrying
   `value = MIN_CIRCLE_STAKE` (default 1000 OCT). The single tx both
   registers the circle in the slim registry AND deposits the bond;
   v2 collapsed the v1.1 chicken-and-egg `bond + register` pair.

Logs prefix `v2 <step> submitted hash=…`.

### 12.3 Sealed-passphrase plumbing

The per-tailnet sealed-asset passphrase resolves in this order
(`hub.rs::sealed_passphrase`):

1. `[chain].sealed_passphrase` in the operator's TOML.
2. `OCTRAVPN_SEALED_PASSPHRASE` env var.

Daemon refuses to start v2 with `"v2 sealed-asset passphrase
required"` if neither is set. For rotation cadence see
`docs/v2-operator-key-hygiene.md` §5.

### 12.4 Circle state cache + idempotent restarts

`[chain].circle_state_path` (default `./state/circle.toml`) caches
`circle_id`, `deploy_nonce`, the three tx hashes, and the policy
plaintext hash. Restarts skip whatever the cache + chain say is
already done. Force re-derivation (e.g. prior circle slashed) by
deleting the cache. Inspect without RPC: `octravpn-node identity`.

### 12.5 Per-class pricing

```toml
[pricing]
price_per_mb          = 100   # v1.1 fallback if shared/internal omitted
price_per_mb_shared   = 100   # CLASS_SHARED (public-internet exit)
price_per_mb_internal = 0     # CLASS_INTERNAL (intra-tailnet; usually free)
```

Tariffs are stamped onto each `Session` at open time, so an operator
can serve multiple tiers without re-registering.

### 12.6 Receipt journal (P1-8 / P1-9)

A persistent `(session_id → last_signed_seq)` floor is fsync'd
**before** any receipt is signed. Default `./state/receipts.bin`;
override via `[control].receipt_journal_path`. After an OOM/SIGKILL
the floor reloads from disk and shadows the in-memory `last_seq` —
the daemon cannot be tricked into signing two distinct receipts at
the same `(session, seq)`, which is exactly what `slash_double_sign`
burns the bond for. Put the journal on durable storage you back up
with the wallet; ≈ 40 bytes per active session, no rotation needed.

### 12.7 Further reading

- `docs/v2-operator-flow.md` — full 4-step walkthrough + error cases.
- `docs/v2-operator-key-hygiene.md` — fresh-wallet rule, sealed-key
  storage, passphrase rotation.
- `docs/v2-threat-model.md` — P0/P1 fix queue.
- `docs/validator-hardening.md` §2.1 — `seal-keys` flow + strict mode.
- `docs/production-checklist.md` §H — v2 production gate items.
