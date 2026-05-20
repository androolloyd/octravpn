# MagicDNS on OctraVPN

The tailnet ships its own in-cluster DNS resolver. When you bring
your peer up, every other peer is reachable by a stable hostname
without you maintaining any host files. This page covers what gets
resolved, how the operator's base-domain config flows into your
search list, SplitDNS routes for `*.internal`-style zones, the
operator's extra records, and the failure modes that put you on the
"why doesn't `ping laptop` work" trail.

For a quick orientation, see [`using.md`](using.md) §2.

## 1. What gets resolved automatically

Every member of the tailnet, by their human-readable hostname,
under the `.octra` zone suffix:

```
<hostname>.<tailnet-id>.octra  →  100.64.x.y
```

The hostname is whatever the peer set with `--hostname` at startup
(default: the OS hostname). The tailnet id is the 64-char hex
identifier from `octravpn tailnet info`. So if your tailnet id is
`a1b2c3…` and your peer's hostname is `desktop`, others reach you
as `desktop.a1b2c3….octra`.

Implementation: [`crates/octravpn-mesh/src/magic_dns.rs`](../../crates/octravpn-mesh/src/magic_dns.rs).
The resolver:

- Listens on UDP at the tailnet router IP (`100.64.0.1`, default
  port 53). Falls back to `127.0.0.1:5353` if it can't bind 53
  (typical on developer laptops without `CAP_NET_BIND_SERVICE`).
- Answers `A` queries inside the `.octra` zone with the allocated
  IPv4.
- For everything else: `REFUSED` (the system resolver falls back to
  the upstream).

The tailnet router IP `100.64.0.1` is **the same across all
tailnets**. It works because each tailnet has its own WireGuard
interface — `100.64.0.1` inside tailnet A and `100.64.0.1` inside
tailnet B are reachable only through their respective tunnels.

## 2. The `base_domain` config (operator side)

If your operator runs a Tailscale-wire control plane (stock path,
not the chain-anchored one), they configure a **base domain** that
flows into your DNS search list. The field is `base_domain` in the
control plane's DNS config:

```toml
# In headscale-api / octravpn-node config:
[dns]
magic_dns   = true
base_domain = "users-tailnet.example.com"
```

The control plane emits this into every peer's `MapResponse.DNSConfig`
([`headscale-api/src/dns.rs:89`](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs)).
Stock `tailscale` writes the base domain into your
`/etc/resolv.conf` (Linux) / `scutil` DNS state (macOS) /
NRPT (Windows) as a **search domain** — that's why you can type
`ssh desktop` and have it resolve `desktop.users-tailnet.example.com`
automatically.

In the chain-anchored flow (`octravpn tailnet up`), the zone is
`<tailnet-id>.octra` and the embedded resolver has no separately-
configurable base domain — you reach the peer at
`<host>.<tailnet-id>.octra`, full stop. Use a `Host` block in
`~/.ssh/config` or shell aliases if you want short names.

## 3. SplitDNS routes

If your operator publishes specific zones (e.g. `*.internal`,
`*.corp.example.com`) that should resolve through their resolver
instead of public DNS, that's SplitDNS. The control plane sets up
per-zone routes in `MapResponse.DNSConfig.Routes`:

```json
{
  "Routes": {
    "internal":            ["100.64.0.1"],
    "corp.example.com":    ["100.64.0.1"]
  }
}
```

Stock `tailscale` reads these and configures the system resolver
to send queries for those suffixes to the tailnet resolver, while
everything else still goes to the public upstream.

End-user verification:

```sh
# Linux:
resolvectl domain          # should list the SplitDNS routes
resolvectl query host.internal A

# macOS:
scutil --dns | grep "search"

# Test the route directly:
dig @100.64.0.1 host.internal A
```

The OctraVPN-flavoured DNS model (in this repo,
[`crates/octravpn-mesh/src/magic_dns.rs`](../../crates/octravpn-mesh/src/magic_dns.rs))
doesn't ship per-zone route configuration yet — the embedded
resolver is strictly `*.octra`-zone-only. For full SplitDNS support
use the `juanfont/headscale`-wire control plane.

## 4. Extra records (operator-published static names)

The operator can publish static `name → IP` records that propagate
to every peer via `MapResponse.DNSConfig.ExtraRecords`. Typical
uses:

- `octravpn.example.com → 1.2.3.4` (an admin dashboard reachable
  by name across the tailnet)
- `metrics.internal → 100.64.0.42` (the operator's monitoring host)

The data type is `DnsRecord` in
[`headscale-api/src/dns.rs`](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs)
(`name`, `type`, `value`). Operators ship them either inline in the
control plane config or in a `extra_records.json` file watched by
`spawn_extra_records_watcher`.

End-user view: they appear in `dig` like any other A record:

```sh
dig +short metrics.internal       # returns 100.64.0.42
```

You don't have to do anything to receive them — they arrive on the
next `MapResponse` poll-wake (see §5).

## 5. Hot-reload

Changes to MagicDNS state — peer joins, peer leaves, ACL hash
bumps, new extra-record — propagate to all peers within ~1 second
via the control plane's long-poll wake mechanism. The pin tests
are in
[`headscale-api/tests/dns_e2e.rs`](/Users/androolloyd/Development/headscale-rs/headscale-api/tests/dns_e2e.rs):

- `set_extra_records_wakes_waiters_within_1s` — proves a new extra
  record arrives at every connected peer in under one second.
- `extra_records_file_watcher_picks_up_changes_and_wakes_waiters`
  — proves a file-watched extra-records source wakes the long-poll
  too.

In practice this means: when an operator publishes a new
`extra_records.json` entry, your `dig name.example.com` starts
resolving without you running `tailscale up` or restarting the
daemon. You may need to clear your **system resolver cache**
(`systemd-resolved`, `mDNSResponder` on macOS, `ipconfig
/flushdns` on Windows) if you're seeing stale answers — the
tailnet resolver is current, but the OS layer caches in front of
it.

## 6. Failure modes

### "Hostname doesn't resolve"

Standard failure. Walk this list:

```sh
tailscale ip                                          # are we even up?
tailscale status | grep <hostname>                    # does the peer exist?
dig @100.64.0.1 desktop.my-tailnet.octra              # ask the tailnet resolver directly
resolvectl status                                     # is the system pointing at it?
```

If `dig @100.64.0.1` works but plain `dig desktop.my-tailnet.octra`
doesn't, the system resolver isn't pointed at the tailnet. On
Linux, `tailscale up` normally fixes this via
`/etc/resolv.conf`, but a `NetworkManager` or `systemd-resolved`
override can clobber it. Force-reapply:

```sh
sudo tailscale set --accept-dns=true
```

### "Hostname collision"

Two peers registered the same `hostname` in the same tailnet — say,
both call themselves `laptop`. The embedded resolver is a
straight `HashMap` insert (see
[`crates/octravpn-mesh/src/magic_dns.rs:65-78`](../../crates/octravpn-mesh/src/magic_dns.rs)),
so the **last registration wins**. In practice that's whichever
peer most recently published its snapshot — undefined under churn.

This is a known gap. The current fix is operator-side: rename one
of the peers. A future iteration may auto-suffix collisions with
the node id, but that isn't shipped today.

Avoid it by giving each peer a distinct `--hostname` on `tailscale
up` / `octravpn tailnet up`.

### "SSHing by IP works but by hostname doesn't"

`ssh 100.64.x.y` succeeds, `ssh desktop.my-tailnet.octra` fails.
Either:

1. MagicDNS is **off** for your tailnet (operator config). The
   `[dns].magic_dns` boolean defaults to `true`; some operators
   explicitly disable it. Workaround: use IPs or maintain a local
   `~/.ssh/config` Host block.
2. Your system resolver doesn't accept the tailnet resolver as
   trusted. On Linux with `systemd-resolved` in strict mode,
   `~/.config/systemd/resolved.conf.d/` overrides can refuse
   non-LAN resolvers. Add `DNS=100.64.0.1` and `Domains=~octra`.

### "Stale answers after the operator changed something"

Your OS resolver caches the previous answer. Flush:

```sh
# Linux (systemd-resolved):
sudo resolvectl flush-caches

# macOS:
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

# Windows (admin):
ipconfig /flushdns
```

The tailnet resolver itself is event-driven (no TTL-based cache);
once the system caches are flushed, the next query is fresh.

## See also

- [`using.md`](using.md) §2 — quick orientation
- [`ssh.md`](ssh.md) §2 — how MagicDNS hooks into `ssh hostname`
- [`crates/octravpn-mesh/src/magic_dns.rs`](../../crates/octravpn-mesh/src/magic_dns.rs)
  — our embedded resolver
- [`headscale-api/src/dns.rs`](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs)
  — the upstream control-plane DNS layer (base_domain, extra
  records, SplitDNS)
- [`headscale-api/tests/dns_e2e.rs`](/Users/androolloyd/Development/headscale-rs/headscale-api/tests/dns_e2e.rs)
  — hot-reload + watcher tests
