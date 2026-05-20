# SSH over OctraVPN

SSH is the canonical "talk to another machine I trust" tool, and
it's the workflow we care most about getting right on the tailnet.
This page covers the SSH-specific bits: why it's a first-class flow,
how MagicDNS hooks into it, the per-user ACL block, and the failure
modes that bite people.

For everyday usage (where the IP comes from, exit-node routing, file
transfer) see [`using.md`](using.md).

## 1. Why SSH is a first-class flow

Two reasons:

1. **MagicDNS makes hostnames just work.** Once your peer registers
   itself in the tailnet, every other peer can resolve
   `<host>.<tailnet>.octra` to its `100.64.x.x` address without you
   maintaining any host files or DNS records. That's the whole reason
   MagicDNS exists.
2. **The ACL document has a dedicated `ssh:` block** — separate from
   the general `accept`/`drop` rules. You can give people transport
   access on port 22 without giving them shell access, or vice versa,
   and you can pin which Unix users on the destination they may
   authenticate as.

The `SshRule` schema lives in the canonical ACL crate at
`/Users/androolloyd/Development/headscale-rs/headscale-api-acl/src/lib.rs:124`
(re-exported through
[`crates/octravpn-mesh/src/acl.rs`](../../crates/octravpn-mesh/src/acl.rs)).

## 2. Setting up MagicDNS for `ssh hostname`

You want `ssh laptop` (no FQDN) to Just Work. Two things have to be
true:

1. **MagicDNS is on for your tailnet.** Your operator either set
   `[dns].magic_dns = true` in their control plane config (stock
   path) or you used `octravpn tailnet up --tailnet …` which spawns
   the embedded resolver on the tailnet router IP (`100.64.0.1`).
2. **Your system resolver is pointed at the tailnet's resolver.**
   On Linux/macOS, `tailscale up` configures `/etc/resolv.conf`
   (Linux) or `scutil`-managed DNS (macOS) for you. On Windows the
   Tailscale service handles it.

Verify:

```sh
# Linux (after tailscale up):
resolvectl status | grep "DNS Servers"  # should show 100.100.100.100 (stock)
                                        # or 100.64.0.1 (chain-anchored octravpn)

# macOS:
scutil --dns | grep "nameserver\[0\]"

# All platforms:
dig +short desktop.my-tailnet.octra     # should print the peer's 100.64.x.x
```

If `dig` returns nothing, MagicDNS isn't wired — see
[`magicdns.md`](magicdns.md) §"Failure modes".

Now `ssh desktop.my-tailnet.octra` works.

Short hostname (`ssh desktop`)? Two options:

- **Append the tailnet to your search domain.** The control plane
  emits its base domain in `MapResponse.DNSConfig.Domains`, and
  stock `tailscale` writes that into your search list. So `ssh
  desktop` succeeds because the resolver tries
  `desktop.<base-domain>` automatically.
- **Add a `Host` block to `~/.ssh/config`** if you want short names
  for a specific tailnet only:
  ```
  Host desktop
    HostName desktop.my-tailnet.octra
    User you
  ```

## 3. The ACL `ssh:` block

Your operator's ACL doc may include a top-level `ssh` array. Each
entry restricts SSH access independently of the general accept/drop
rules. Schema:

```toml
[[ssh]]
action = "accept"          # only "accept" is meaningful for SSH
src    = ["group:eng"]     # who may connect
dst    = ["autogroup:tagged"]  # which peers they may connect to
users  = ["root", "ubuntu"]    # which Unix users they may auth as
```

(See `headscale-api-acl::SshRule` —
`/Users/androolloyd/Development/headscale-rs/headscale-api-acl/src/lib.rs:124`.)

Key semantics:

- `users` is the **destination-side username**. Empty `users` array
  → no SSH access; the entry has to opt-in explicitly.
- `dst` accepts the same selector grammar as the general rules:
  `oct…` addresses, `tag:foo`, `group:bar`, `autogroup:tagged`,
  `*`, etc.
- An empty `ssh` array means **no SSH access between any peers** —
  the absence is *not* "accept everything". The general
  `accept`/`drop` rules still allow raw TCP/22, but stock-tailscale's
  embedded SSH server (`tailscale ssh`) and the operator's wire-layer
  SSH-gate check the `ssh` block specifically.

If your tailnet uses chain-anchored ACLs (TOML, signed by the
owner), the doc is fetched out-of-band and verified against the
on-chain hash. See
[`tailnet-user-guide.md`](../tailnet-user-guide.md) §5 for the
operator workflow.

## 4. `tailscale ssh` (authenticated-SSH from stock Tailscale)

Stock Tailscale has a `tailscale ssh` command that uses
tailnet-issued certificates instead of password / pubkey auth — the
destination peer trusts the control plane's authority over identity.

**Does our control plane preserve it?** Partially:

- The wire-level pieces (the `MapResponse` carrying SSH-policy
  attributes, the per-peer `node_key` and `disco_key`) are emitted —
  Wall 7 of the interop work shipped DiscoKey + Endpoints in
  `MapNode` so two stock clients can converge on direct WG.
- The control-plane SSH-CA endpoint (`/machine/<mkey>/ssh-action`)
  is **not** in our current `octravpn-node` control surface —
  [`docs/tailscale-interop-finding.md`](../tailscale-interop-finding.md)
  enumerates the missing endpoints. `tailscale ssh` returns
  "permission denied (publickey)" or a control-plane-side error
  when its CA lookup fails against our mesh.

In other words: **use plain `ssh`** between peers on this control
plane today; `tailscale ssh` is on the roadmap.

If your operator runs upstream `juanfont/headscale` (not
`octravpn-node`), they get the upstream's `tailscale ssh` behaviour
unchanged.

## 5. Common failure modes

### "Connection refused"

The destination peer is reachable (`ping` works, `tailscale ping`
returns OK) but `ssh` is refused. Always: there is no `sshd`
listening on port 22. Fixes per OS:

```sh
# Linux:
sudo systemctl status ssh   # is it running?
sudo systemctl enable --now ssh

# macOS (System Settings UI):
# General → Sharing → Remote Login → ON

# Windows (PowerShell admin):
Get-Service sshd
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

### "Connection timed out"

The TCP SYN isn't even getting an RST. Three usual suspects:

1. **ACL rule blocks port 22.** Check with the tailnet owner — the
   ACL doc's general rules can `drop` traffic to `tcp/22`
   independently of the `ssh:` block.
2. **Host firewall on the destination.** macOS Application Firewall,
   Linux `ufw`, Windows Defender Firewall — each can refuse 22 even
   though the tailnet path is open.
3. **Tunnel down between you and the peer.** `tailscale ping
   <peer>` will say so. Bring the tunnel back with
   `tailscale up`.

### "ssh: Could not resolve hostname laptop.my-tailnet.octra"

MagicDNS isn't resolving. See [`magicdns.md`](magicdns.md). Quick
checks:

```sh
tailscale ip                                       # are we up at all?
dig @100.64.0.1 desktop.my-tailnet.octra A         # ask the tailnet resolver directly
resolvectl status                                  # is the system pointing at it?
```

### "Permission denied (publickey)"

`sshd` is running, port is reachable, but no auth method accepted.
Usual fixes:

- Your public key isn't in `~/.ssh/authorized_keys` on the
  destination. Copy with `ssh-copy-id you@desktop.my-tailnet.octra`
  from a working session, or paste manually.
- The destination's `sshd_config` has `PasswordAuthentication no`
  and you don't have a key set up. Add a key.
- You're trying `tailscale ssh` against our control plane (see §4).
  Use plain `ssh`.

### "Host key verification failed"

The peer was reinstalled (new SSH host key) or someone is
intercepting (very unlikely on a tailnet). Compare the new
fingerprint with the peer owner out-of-band; if they confirm the
reinstall:

```sh
ssh-keygen -R desktop.my-tailnet.octra
ssh-keygen -R 100.64.x.y                            # also the IP
```

### "Too many authentication failures"

OpenSSH is offering every key in your agent. Pin to one:

```sh
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 you@desktop.my-tailnet.octra
```

## See also

- [`using.md`](using.md) §2 — the quick-tour version
- [`magicdns.md`](magicdns.md) — name-resolution details
- [`../tailnet-user-guide.md`](../tailnet-user-guide.md) — ACL
  authoring (for owners)
