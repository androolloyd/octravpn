# DERP domain-fronting (operators)

> Fourth layer of the v2 shielding stack: hide *which IP* our DERP
> relay terminates at by routing client TLS through a CDN-hosted
> Worker.  The first three layers (BoringTun + obfs4 + self-signed
> TLS DERP) make the bytes on the wire opaque; this layer makes the
> *destination address* opaque as well.

## 1. Why this exists

Today our DERP fleet lives on a small, stable set of IPs
(`derp-1.octravpn.…`, `derp-2.…`, etc).  An adversary who can't
break BoringTun and can't fingerprint obfs4 can still defeat the
relay story with a single iptables rule on the national gateway:

```text
DROP   any  ->  $DERP_POOL_IP/32
```

The censor pays zero collateral damage — those IPs only serve
octravpn DERP — and our clients lose every hop they had.

**Domain fronting moves the apparent destination IP onto a CDN
shared with the rest of the modern web.**  The censor now has a
choice: either let us through, or block every Cloudflare Worker
IP and break ~30% of the public internet on their network.

### What this defeats that obfs4 alone does **not**

obfs4 (and our self-signed TLS to `derp-1:443`) makes the
ClientHello and the inner cipherstream look like a generic TLS
session to a stranger's web app.  But the IP the client connects
to is still `derp-1.octravpn.example.org`'s address.  The censor
doesn't need to break the bytes — they just need a blocklist of
"known octravpn DERP egress IPs", which is cheap to maintain and
cheap to enforce (a single `ipset` lookup per SYN).

Fronting makes the connecting IP belong to Cloudflare's anycast
pool, which is *also* what every news site, SaaS app, and customer
support widget on the censor's network points at.  IP blocking
becomes politically infeasible.

## 2. Threat model

| Adversary capability                | Defeated by  |
|-------------------------------------|--------------|
| DPI fingerprint of WireGuard UDP    | BoringTun + DERP TLS wrap (L1) |
| DPI fingerprint of TLS metadata     | obfs4 prefix (L2)              |
| TLS MITM with national CA           | self-signed cert pinning (L3)  |
| **IP blocklist of DERP pool**       | **fronting (L4 — this doc)**   |
| Active probe for the Worker secret  | constant-time HMAC verify; 404 on fail |
| Replay of captured request          | timestamp + 5-minute skew window |

Out of scope: a censor who blocks the entire CDN — we have nothing
to offer there beyond "fall back to Tor".  In scope: every state
censor that today operates as IP-list-plus-DPI; that's most of
them.

## 3. CDN choice — Cloudflare Workers (vs alternatives)

We pick **Cloudflare Workers** because:

1. **Free tier handles ~100k req/day**, enough for a small operator
   pool without invoicing.  DERP requests are batched (one HTTPS
   connection multiplexes many DERP frames), so 100k/day is much
   more headroom than the raw number suggests.
2. **Workers don't get reaped** the way classic
   `cdn.cloudflare.com`-style domain fronting did in 2018-2023.
   The CDN treats them as first-class customer code, not as
   "someone else's domain accidentally allowed through SNI
   rewriting".
3. **Anycast IPs**.  The same IPs serve every Worker on the
   platform; blocking us blocks all of them.
4. **Stable wrangler tooling** — see deploy script below.

We considered:

- **Vercel Edge Functions** — works (same `Request`/`Response`
  shape) but the deploy CLI is more opinionated about full projects
  + the IP pool is smaller, so a state actor can blocklist
  Vercel-only and lose less.  The Worker source in
  `deploy/fronting/derp-front.js` *is* directly drop-in compatible
  with Vercel Edge (`export default { fetch }`) — operators who
  prefer Vercel can hand-wire the deploy.
- **Lambda@Edge / CloudFront** — works in theory; requires an AWS
  account with a payment method, harder for non-USA operators.
- **Snowflake-style WebRTC**.  Different threat model (single-hop
  peer-to-peer); we should add it as a separate layer, not as a
  replacement for fronting.

## 4. Deploy walkthrough

### 4.1 Prerequisites

- A Cloudflare account, free tier is fine.
- `wrangler` CLI on PATH:
  `npm install -g wrangler && wrangler login`.
- Your operator-side DERP origin running and reachable on the
  public internet at `derp.<your-domain>` (port 443, the same
  endpoint you put in `derp-map.json`).

### 4.2 One-shot deploy

```bash
./scripts/operators/deploy-fronting.sh \
  --real-host derp.octravpn.example.org \
  --name octravpn-front
```

The script does, in order:

1. `openssl rand -hex 32` — mints a fresh 32-byte HMAC key.
2. `wrangler secret put OCTRA_FRONT_KEY` — uploads it to the
   Worker.  The key never lands on disk in this repo.
3. `wrangler deploy` — pushes `derp-front.js`.
4. Smoke test with `curl`: confirms `https://${FRONT_HOST}/derp`
   returns `404` with no auth header (Worker is up and refusing
   strangers) and `404` with a garbage auth header (key check is
   doing its job).
5. Prints the `[tun.derp.front]` block ready to paste into
   `node.toml` on every operator node.

### 4.3 Wiring the client

Append to each node's `node.toml`:

```toml
[tun.derp.front]
enabled = true
front_host = "octravpn-front.workers.dev"
real_host = "derp.octravpn.example.org"
front_hmac_key = "a8…64 hex chars total…f3"
```

Restart the node.  Verify with `octravpn-node status` (or `journalctl
-u octravpn-node` — look for `derp::front` log lines confirming the
Worker URL).

### 4.4 Rotating the key

Re-run `deploy-fronting.sh`.  The old Worker secret is overwritten
in place; the old key stops working as soon as the new deploy lands.
Push the new `node.toml` snippet to every node.

## 5. Limits & cost

### 5.1 Cloudflare Workers free tier

- 100,000 requests/day, shared across all Workers on the account.
- 10ms CPU time per request.  Our Worker's hot path is
  `crypto.subtle.digest` + `crypto.subtle.sign`; ~1-2ms at our
  payload sizes.
- 1 MB max request body, 100 MB max if you upgrade to the paid
  ($5/mo) tier.  DERP frames are well under 1 MB.

For a 50-user operator with ~100 idle DERP keepalives/hour, the
math is `100 users × 100 req/hour × 24h = 240k/day` — already
over the free tier.  **Plan for the $5/mo plan** if you're running
a real operator.

### 5.2 Latency penalty

Each fronted request adds ~1 CDN hop in front of the DERP origin:

| segment                 | typical RTT |
|-------------------------|-------------|
| client → CDN edge       | 10-30 ms    |
| CDN edge → Worker exec  | 1-2 ms      |
| Worker → DERP origin    | 20-80 ms (depends on origin region) |
| **total added**         | **~30-110 ms** vs direct DERP |

Tolerable for control / signalling traffic; not great for VoIP.
The default config (`enabled = false`) keeps DERP direct, and the
node falls back to fronting only when direct dial fails.

### 5.3 Body-size headroom

We strip nothing from the body — the Worker is a transparent
proxy.  If the operator runs the paid plan, the cap is 100 MB
per request, which covers any DERP frame we'd realistically send.

## 6. Failure modes

| symptom                                    | likely cause                  | client behaviour |
|--------------------------------------------|-------------------------------|------------------|
| 404 from Worker                            | wrong HMAC or expired ts      | log + fall back to direct DERP |
| 502 / connection-reset from Worker         | upstream DERP origin down     | log + fall back to direct DERP |
| Worker hits CF rate limit (1000 req/min/IP) | too many clients sharing one egress | log + back off 30s, then retry direct |
| TLS error to `*.workers.dev`               | censor blocking workers.dev itself | log + fall back to direct DERP; surface in status |

The client never *prefers* fronting over direct DERP unless the
operator explicitly inverts the priority (a future
`prefer = "front"` knob, currently off).  The two paths are
parallel: direct DERP is tried first, fronting is the warm
secondary.

## 7. Operational checklist

- [ ] HMAC key minted via the deploy script (never reused from a
      previous deploy)
- [ ] `front_host` value matches what `wrangler deployments list`
      reports
- [ ] `real_host` matches the DERP origin's public DNS name
- [ ] `OCTRA_REAL_HOST_ALLOWLIST` (in `wrangler.toml`) populated
      with the same `real_host` value (defense-in-depth)
- [ ] Smoke test: `curl https://${FRONT_HOST}/derp` returns 404
      (Worker is up but refusing unauth)
- [ ] Node restarted with new `node.toml`; `derp::front` log lines
      show the Worker URL on startup
- [ ] At least one client successfully exchanges DERP frames via
      the front (check the Worker's request counter on the CF
      dashboard)

## 8. What lives where

| concern                          | file                                                            |
|----------------------------------|-----------------------------------------------------------------|
| Worker source                    | `deploy/fronting/derp-front.js`                                 |
| Worker config                    | `deploy/fronting/wrangler.toml`                                 |
| Deploy + key-minting script      | `scripts/operators/deploy-fronting.sh`                          |
| Client dialer                    | `crates/octravpn-tun/src/derp/front.rs`                         |
| Config schema                    | `FrontConfig` in `crates/octravpn-tun/src/derp/front.rs`        |

The canonical-form string used in the HMAC is defined in *both*
`front.rs::auth_tag` and `derp-front.js::authTag`; the Rust test
`auth_tag_known_answer` pins one value so accidental drift between
the two sides surfaces immediately.
