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
listen             = "0.0.0.0:51821"
audit_dir          = "/var/log/octravpn/audit"

[attestation]
poll_interval_secs = 30
```

A couple things to know:

- `validator_addr` is your Octra protocol validator address. The
  program will refuse registration if `octra_isValidator(validator_addr)`
  returns false.
- `price_per_mb` is in raw OU. At 100 OU/MB and 1 GB/hr of relayed
  traffic, you earn ~100 000 OU/hr = 0.1 OCT/hr.

## 4. Register the endpoint

One-time setup:

```sh
sudo octravpn-node register --config /etc/octravpn/node.toml
```

This:

1. Pre-checks `octra_isValidator(validator_addr)` and bails out with
   a clear message if you're not a validator.
2. Submits `register_endpoint(endpoint, wg_pub, receipt_pub,
   view_pub, region, price_per_mb)` to the program.
3. Logs the resulting tx hash.

`register` is idempotent; you can re-run it safely. The chain
remembers your endpoint until you `retire_endpoint`.

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

## 9. Operations checklist

- **Monitor `/health`**. Alert on 503 (stale attestation).
- **Watch the audit log**. It writes one JSONL entry per
  state-changing request.
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
