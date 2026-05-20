# Connecting to a tailnet — the OS-agnostic flow

This page is the cross-OS reference for what actually happens when
you run `tailscale up --login-server ... --authkey ...`. Read it
after your per-OS install ([`linux.md`](linux.md) /
[`macos.md`](macos.md) / [`windows.md`](windows.md)) and before you
start using the tailnet daily (the stock `tailscale` CLI docs at
<https://tailscale.com/kb/> cover everyday `ping`, `status`,
`serve`, exit-node operations once you're joined).

## 1. What the operator gave you

Your tailnet owner should have sent you, out-of-band (Signal, Slack
DM, vault entry — anywhere that is **not** public):

### A preauth key

A short string. Two formats are in use, both work:

- **OctraVPN format** — `octrapreauth-<hex>`. Minted via the
  embedded `octravpn-node mesh mint-preauth` command (see
  [`crates/octravpn-node/src/cli/mesh.rs`](../../crates/octravpn-node/src/cli/mesh.rs)).
- **Headscale-stock format** — a 48-character hex blob. Minted via
  `octravpn-node headscale preauthkeys create --user <U>` (see
  [`docs/operators/cli-migration.md`](../operators/cli-migration.md)).

You don't need to know which format you got — `tailscale up` accepts
both via the same `--authkey` flag. Just paste the value verbatim.

Preauth keys are **single-use by default**. If you re-run
`tailscale up --authkey <key>` after a successful join, the second
run will fail with "key already used". This is expected; subsequent
`tailscale up` calls (after reboot etc.) should omit `--authkey` —
the local state at `/var/lib/tailscale/` (Linux) /
`/Library/Tailscale/` (macOS) / `C:\ProgramData\Tailscale\`
(Windows) is what re-authenticates.

Reusable keys exist (`--reusable` at mint time) but the operator
must opt into them; the default is the safer single-use shape.

### The login-server URL

A full URL like `https://mesh.example.org` or `https://mesh.example.org:443`.

- The scheme is **always `https://`** in production. Stock
  `tailscale` v1.78+ forces a parallel HTTPS-on-443 dial even when
  given a plain-HTTP URL; see
  [`docs/tailscale-interop-blocker.md`](../tailscale-interop-blocker.md)
  for the gory details. The operator already knows this and runs the
  control plane behind a TLS terminator.
- Do **not** append a path. The URL is just the host. The Tailscale
  client appends `/key`, `/machine/.../register`, `/machine/.../map`
  itself.

### (Optional) Tags

If the operator's network policy ([HuJSON policy file] on their
side) restricts who can do what by tag, they will tell you
something like:

```
tailscale up ... --advertise-tags=tag:eng,tag:office
```

You include those at `up` time. Tags you advertise must match what
the operator's policy permits — if you make up a tag, the policy
will reject your registration.

## 2. The exact command

The canonical form, identical across Linux / macOS / Windows except
for whether you need `sudo` (Linux/macOS yes, Windows runs the
service as LocalSystem so the CLI just talks to it):

```sh
# Linux / macOS
sudo tailscale up \
    --login-server https://mesh.example.org \
    --authkey octrapreauth-YOUR-KEY-HERE \
    --hostname my-laptop

# Windows (elevated PowerShell)
tailscale up `
    --login-server https://mesh.example.org `
    --authkey octrapreauth-YOUR-KEY-HERE `
    --hostname my-laptop
```

`--hostname` defaults to your machine's hostname; override it if you
want a specific name in your operator's roster.

## 3. `--ephemeral` vs persistent registration

`--ephemeral` flips one flag in the registration request: when your
device disconnects (logout, reboot if not configured to auto-up),
the operator's control plane **removes** it from the roster
automatically. Persistent registration (default) keeps the entry
forever until the operator deletes it.

When to pick each:

| Scenario                                         | Choice           |
|--------------------------------------------------|------------------|
| Your personal laptop / desktop / phone           | persistent      |
| A long-running server you SSH into via tailnet   | persistent      |
| A short-lived CI runner / disposable container   | `--ephemeral`   |
| A demo / temporary device that should self-clean | `--ephemeral`   |
| You don't know — your operator didn't specify    | persistent (default) |

`--ephemeral` is harmless if you guess wrong; the operator can
always remove a persistent entry, and ephemeral entries that
reconnect will just create a fresh registration each time.

## 4. Tagged vs untagged join

Two cases:

**Untagged (the default).** You join under your "user" identity (the
preauth key was minted under a specific user, e.g.
`octravpn-node headscale preauthkeys create --user alice`). All
policy decisions are scoped to that user.

**Tagged.** The operator's HuJSON policy declares ACL rules like
`"src": ["tag:eng"]`. You assert one or more tags at `up` time:

```sh
sudo tailscale up \
    --login-server https://mesh.example.org \
    --authkey ... \
    --advertise-tags=tag:eng,tag:laptop
```

The control plane verifies (per policy) that the user owning the
preauth key is authorized to assert those tags. If not, registration
fails immediately with a clear error.

If your operator hasn't mentioned tags, you don't have any. Move on.

## 5. What happens after `tailscale up` succeeds

In the first ~5–60 seconds:

1. **Roster propagation.** Your device shows up in every other
   tailnet member's `tailscale status` output. They show up in
   yours. The control plane delivers the roster via a long-polled
   `MapResponse` stream, so updates land within seconds.
2. **Your 100.64.x.x IP is assigned.** The IP is allocated by the
   operator's control plane out of CGNAT space (typically
   `100.64.0.0/10`). It's stable — re-joining the same tailnet from
   the same machine yields the same IP unless the operator
   explicitly recycles it.
3. **DERP relay bootstrap.** The client connects to one of the
   DERP regions the operator's MapResponse advertises. Even with no
   direct peer-to-peer connectivity, the relay path is now live.
4. **Peer-to-peer NAT traversal.** For each peer, the Tailscale
   discovery layer (DiscoKey + Endpoints) tries to negotiate a
   direct UDP path. When it succeeds, RTT drops from "DERP relay"
   to "direct".

You can watch this in real time:

```sh
tailscale status --json | jq '.Peer[] | {hostname:.HostName, online:.Online, relay:.Relay, addrs:.Addrs}'
```

## 6. The post-connect smoke test

The single command that proves end-to-end working state:

```sh
tailscale ping <peer-hostname>
```

This is the headline working command from the project's Wall-7
interop acceptance — see
[`docs/tailscale-interop-blocker.md`](../tailscale-interop-blocker.md)
§"Wall 7 closed". A successful ping has two flavours of healthy:

```
pong from desktop (100.64.0.7) via DERP(use1) in 84ms     # relay path
pong from desktop (100.64.0.7) via 192.0.2.4:41641 in 11ms # direct path
```

Either is a working join. Direct is just faster.

If `tailscale ping` returns nothing or "no route":

- Confirm the peer is up: `tailscale status` should list them with
  an IP, not `-`.
- If both you and the peer are behind symmetric NAT, only the DERP
  path works — that's normal, not broken.
- If even DERP fails, the issue is upstream (operator's relay is
  down or your network blocks egress to it).

## 7. Disconnecting cleanly

Three levels of "disconnect":

### Pause (interface down, registration kept)

```sh
sudo tailscale down
```

The `tailscale0` (Linux) / `utun*` (macOS) / Tailscale (Windows)
interface goes down. State is preserved. `tailscale up` (no
arguments) brings it back without needing a fresh preauth key.

### Logout (clear local registration)

```sh
sudo tailscale logout
```

This drops the registration. Re-joining requires a new preauth key
from your operator. Use this when you want to switch tailnets, or
when you're handing off the machine.

### Full uninstall

See [`uninstall.md`](uninstall.md). Removes the binary, the daemon,
and every state file per OS.

## 8. What state persists across reboots

| Location (Linux)              | Contents                                          |
|-------------------------------|---------------------------------------------------|
| `/var/lib/tailscale/`         | `tailscaled.state` — your machine key + registration |
| `/var/log/tailscale/`         | journal output, usually empty unless verbose      |
| `/etc/default/tailscaled`     | service-level env vars (operator may have populated) |

| Location (macOS)              | Contents                                          |
|-------------------------------|---------------------------------------------------|
| `/Library/Tailscale/`         | daemon state, system-wide                         |
| `~/Library/Group Containers/*.io.tailscale.ipn` | App Store GUI session state           |

| Location (Windows)            | Contents                                          |
|-------------------------------|---------------------------------------------------|
| `C:\ProgramData\Tailscale\`   | service state, machine key                        |
| `C:\Program Files\Tailscale\` | binaries                                          |

The single file that **must** be wiped for a fresh start is the
machine-key file under the OS-specific state directory.
`tailscale logout` is the supported way; manual deletion of those
files also works.

## 9. If something breaks

The headline failure modes by symptom:

| Symptom                                               | Look at                                                       |
|-------------------------------------------------------|---------------------------------------------------------------|
| `tailscale up` hangs without exit                     | TLS verify — per-OS troubleshooting §"TLS handshake" / §"hangs on TLS" |
| Command exits with "key already used"                 | You re-used a single-use preauth key. Ask operator for a new one. |
| Joined, but no peers visible in `tailscale status`    | Wait 30 s. If still empty, the operator's control plane never delivered a netmap — operator-side issue. |
| Peers visible but `tailscale ping` returns nothing    | NAT / firewall — §6 above. DERP fallback should still work; if not, operator's DERP relay is unreachable. |
| `100.64.x.x` IP shows but no interface in `ip addr`   | TUN device open failed — per-OS §"kernel module" / §"WinTUN driver" |
| DNS for `<peer>.<tailnet>` doesn't resolve            | Linux: dnsmasq vs systemd-resolved (see `linux.md` §6). macOS/Windows: `tailscale set --accept-dns=true`. |

Operator-side problems (their endpoint is unhealthy, their cert
expired, their relay is down) you point your operator at:

- [`docs/operators/tls-rotation.md`](../operators/tls-rotation.md)
- [`docs/operators/derp-fronting.md`](../operators/derp-fronting.md)
- [`docs/troubleshooting.md`](../troubleshooting.md) — full
  operator-side debugging.

Once `tailscale ping <peer>` returns RTTs, you are joined.
