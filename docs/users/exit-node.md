# Exit-node routing

An **exit node** is a peer that lets you route your non-tailnet
internet traffic through them. Your egress IP becomes theirs, your
DNS resolution can flow through their resolver, and the WireGuard
tunnel to that peer becomes the path for everything outside
`100.64.0.0/10`.

This is the closest thing OctraVPN has to a "traditional VPN" UX —
hide your egress IP behind someone else's connection. It's still
strictly peer-to-peer-shaped: you pick which peer to exit through,
and that peer has to have explicitly offered to be an exit.

## 1. The two sides

### Operator side: declaring an exit

If you run a peer that's going to act as an exit, the **operator**
side of the dance (you'll find the full version in
[`../tailnet-user-guide.md`](../tailnet-user-guide.md) §3) is:

```sh
# Stock Tailscale clients (the standard path):
tailscale up --advertise-exit-node

# Chain-anchored: configure a paid validator exit for the tailnet
# (owner-only). Members can then route through that endpoint.
octravpn tailnet configure-exit \
    --tailnet my-tailnet \
    --validator octV1Validator...
```

`tailscale up --advertise-exit-node` is the stock Tailscale flag —
it announces in the peer's `MapNode` that this device is willing to
relay arbitrary egress. The control plane propagates the
advertisement to every other peer in the tailnet.

`octravpn tailnet configure-exit` is the chain-anchored alternative
— the owner names a validator endpoint as the tailnet's paid exit;
every byte through that exit is metered and paid from the tailnet
treasury (see §3).

There is **no** `octravpn tailnet advertise-exit` subcommand in
the current CLI — the `TailnetCmd` enum
([`crates/octravpn-client/src/tailnet.rs`](../../crates/octravpn-client/src/tailnet.rs))
has `ConfigureExit` and `AdvertiseSubnet` but not
`AdvertiseExit`. Earlier drafts of the user guide listed it; that
was forward-looking. Stick with `tailscale up
--advertise-exit-node` on the offering peer.

### Client side: using an exit

```sh
# Pick one — by hostname (MagicDNS resolves it) or by IP:
tailscale up --exit-node=desktop.my-tailnet.octra

# Allow local-LAN traffic to bypass the exit (recommended):
tailscale up --exit-node=desktop.my-tailnet.octra --exit-node-allow-lan-access

# Stop using any exit node:
tailscale up --exit-node=
```

(`tailscale up` is idempotent — re-running it just updates the
in-memory state without restarting the tunnel.)

To list which peers in your roster are advertising:

```sh
tailscale status                # the "exit-node" column shows which are offers
tailscale exit-node list        # explicit listing (newer Tailscale versions)
```

## 2. What changes when you exit-route

Three things flip the moment `--exit-node` is non-empty:

### Egress IP

Traffic for any destination outside `100.64.0.0/10` is encapsulated
in WireGuard and sent to the exit node. The exit node decrypts it
and routes it normally onto its public interface. Any service you
hit sees the **exit node's** public IP, not yours.

Verify:

```sh
curl ifconfig.me            # before: your ISP IP. after: the exit's IP.
curl https://api.ipify.org  # same idea, second opinion
```

If `ifconfig.me` still shows your ISP IP after `tailscale up
--exit-node=…`, the routing didn't actually flip — usually because
`--exit-node-allow-lan-access` was set and `ifconfig.me` is being
resolved to a CDN node that's reachable on your LAN. Use a server
that's definitely off-LAN.

### DNS

By default, `tailscale up --exit-node=…` also routes DNS through
the exit. Two consequences:

- **MagicDNS** for the tailnet still works (the resolver is at
  `100.64.0.1` and that traffic stays inside the tunnel).
- **Public DNS** now flows through the exit's upstream — typically
  whatever resolver the exit's `tailscale up` configured, or the
  tailnet's `[dns].extra_records` entries.

This means a hostile exit can poison your name resolution. Pin
DNS-over-HTTPS in the browser if you don't trust the exit:

```sh
# Firefox: about:preferences#privacy → DNS over HTTPS
# Chrome:  chrome://settings/security → Use secure DNS
```

Or override locally:

```sh
tailscale up --exit-node=…  --exit-node-allow-lan-access
# Then in /etc/resolv.conf or NetworkManager, pin to 1.1.1.1
```

### MTU

The WireGuard header is 60 bytes (IPv4) or 80 (IPv6). Your tailnet
tunnel's MTU drops by that amount to avoid fragmentation. The
typical end-result interface MTU is **1280** vs the LAN's 1500.

If you're seeing weird "slow connect, then stalls" behaviour over
the exit, MTU mismatch is a suspect:

```sh
# Probe the path MTU end-to-end:
tracepath -n example.com    # Linux
sudo mtr -r example.com     # macOS / Linux with mtr

# Force a smaller MSS at the SSH client level if you're tunneling
# through ssh as well:
ssh -o "MACs hmac-sha2-256" you@host
```

## 3. Per-class pricing (v2; gone in v3)

In the v2 chain program (`program/main-v2.aml`), exit routing was
metered at one of two rates based on the session class:

- `class = "shared"` — you and the exit are on different tailnets,
  or you're routing through a paid validator. Higher per-MB price.
- `class = "internal"` — you're on the same tailnet as the exit
  ("home-server" use case). Lower price, often zero.

The class lived on chain in `open_session(tid, circle, class,
max_pay)` and the settle math charged accordingly.

In **v3** (`program/main-v3.aml`), the class is **removed from the
chain**:

> v2 `open_session(tid, circle, class, max_pay)`
> v3 `open_session(tid, circle, max_pay)` — class removed
>
> — [`docs/v3/v3-vs-v2.md`](../v3/v3-vs-v2.md), per-entrypoint
> delta

Pricing moved into the operator-signed off-chain receipt, and the
exit-class distinction is now policy-level (the operator picks the
rate when signing the receipt; the chain just charges the receipted
amount). See
[`../v3-policy-schema.md`](../v3-policy-schema.md) for the on-asset
`price_per_mb_shared` / `price_per_mb_internal` fields.

For end users this means:

- v2 client → v2 chain: you pass `--class shared` (default) or
  `--class internal` to `octravpn connect-v2`.
- v3 client → v3 chain: no class flag; the operator's receipt
  determines the rate.
- Stock Tailscale on either: pricing is invisible to you because
  no on-chain session is opened — it's a normal peer-to-peer exit.

## 4. Diagnosing exit-route problems

```sh
tailscale netcheck              # NAT type, DERP regions, IPv6 reachability
tailscale status                # is the exit in "active" state?
tailscale ping desktop          # WG-level ping to the exit
curl -m5 -s ifconfig.me         # public-IP smoke test, short timeout
```

If `netcheck` reports "NAT type: hard" on both you and the exit,
you'll be falling back through a DERP relay — performance won't be
great even when it works.

If `tailscale status` shows the exit as `relay`-state, your WG
tunnel to that peer is going through DERP, which adds latency. Try
restarting both ends' Tailscale, or check that the exit's UDP port
isn't blocked upstream.

If `ifconfig.me` still shows your real IP:

1. Verify `tailscale up --exit-node=…` was idempotent and applied.
   Re-run with `-v`:
   ```sh
   tailscale up -v --exit-node=desktop.my-tailnet.octra
   ```
2. Check that the exit is actually advertising. From the exit
   peer:
   ```sh
   tailscale status --self | grep advertise   # should mention exit-node
   ```
3. Some operator ACLs explicitly forbid using a given exit — the
   `accept`/`drop` rules can refuse `dst = exit-node:…`.

## See also

- [`using.md`](using.md) §4 — the quick-tour overview
- [`magicdns.md`](magicdns.md) §"SplitDNS routes" — how the exit's
  DNS interacts with the tailnet resolver
- [`../tailnet-user-guide.md`](../tailnet-user-guide.md) §3 — the
  owner-side configure flow
- [`../v3/v3-vs-v2.md`](../v3/v3-vs-v2.md) — the v3 class-removal
  rationale
