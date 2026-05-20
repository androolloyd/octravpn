# Everyday OctraVPN — what you do after you're connected

You ran `tailscale up --login-server …` from
[`linux.md`](linux.md) / [`macos.md`](macos.md) /
[`windows.md`](windows.md), got back a `100.64.x.x` address, and
[`connect.md`](connect.md) confirmed you can see your peers in
`tailscale status`. This page is the tour of what you can actually
**do** now.

If something here doesn't work, the per-OS guide and
[`connect.md`](connect.md) §"Troubleshooting" cover the platform-level
gotchas (kernel modules, network extensions, MTU). This page assumes
you're already on the tailnet.

## 1. Your tailnet IP

```sh
tailscale ip          # prints your IPv4 + IPv6 on the tailnet
tailscale ip -4       # IPv4 only
```

The IPv4 is in the CGNAT range `100.64.0.0/10` (RFC 6598). It's stable
for as long as you stay a member with the same Octra address — the
allocator computes it as `sha256(tailnet_id || your_address)` projected
into the host range, so any peer can derive any other peer's IP
without coordination. See
[`crates/octravpn-mesh/src/ip_alloc.rs`](../../crates/octravpn-mesh/src/ip_alloc.rs)
for the exact derivation + the birthday-collision bounds (`~0.12 %`
at 100 members, `~11.7 %` at 1000).

To see everyone else:

```sh
tailscale status                # human-friendly roster
tailscale status --json | jq .  # machine-friendly
```

Each entry shows the peer's tailnet IP, hostname, OS, and the current
connection path (`direct`, `relay`, or `idle`).

## 2. SSH between peers

Once a peer has an SSH server running on port 22, you can `ssh` to it
by hostname:

```sh
ssh you@desktop.my-tailnet.octra
```

MagicDNS resolves `desktop.my-tailnet.octra` to the peer's
`100.64.x.x` address — that's the whole point of the embedded DNS
resolver. The zone suffix is **`octra`** (we don't use
`.ts.net` — that's a Tailscale-hosted product). See
[`magicdns.md`](magicdns.md) for how name resolution is wired and
[`ssh.md`](ssh.md) for the SSH-specific gotchas (per-user ACL rules,
`tailscale ssh`, common failure modes).

If `tailscale status` shows the peer but `ssh` hangs, jump to
[`ssh.md`](ssh.md) §"Common failure modes" — 90 % of the time it's an
ACL rule, a firewall on the peer, or `sshd` not actually running.

## 3. HTTP / TCP services on the tailnet

A peer can run any service on a port — `:8080`, `:5432`, `:3000` —
and other tailnet members reach it the same way they'd reach any
host on a normal LAN:

```sh
# On the peer hosting the service:
python3 -m http.server 8080

# From any other tailnet member:
curl http://laptop.my-tailnet.octra:8080/
```

No port-forwarding, no NAT traversal config — the WireGuard tunnel
between the two peers is point-to-point. The 3-peer mesh demo in
[`demo/tapes/08-3node-mesh.tape`](../../demo/tapes/08-3node-mesh.tape)
brings this whole flow up end-to-end (peers join, MagicDNS resolves,
direct tunnels open) — re-run with `vhs demo/tapes/08-3node-mesh.tape`
to see the timeline.

### `octravpn serve` (chain-anchored tailnets only)

If your tailnet uses the chain-anchored flow (your operator told you
to install the `octravpn` CLI), you can also register a service in
the on-chain tailnet registry so members discover it without
guessing the port:

```sh
octravpn serve add --port 8080 --path /metrics
octravpn serve list
octravpn serve remove --port 8080
```

These are local-config commands — they write the registration into
your peer snapshot, which is published to the tailnet on the next
mesh tick. The data plane is identical to "just listen on `:8080`";
this is metadata for the registry.

## 4. Exit-node routing

If a peer offers to be the **exit node** for your tailnet, you route
all your non-tailnet internet traffic through them. Your egress IP
becomes theirs.

The full flow + per-class pricing (in chain-anchored tailnets) lives
in [`exit-node.md`](exit-node.md). Short version:

```sh
# Pick one of the offered exit nodes:
tailscale up --exit-node=desktop.my-tailnet.octra --exit-node-allow-lan-access

# Stop using an exit node:
tailscale up --exit-node=
```

Verify the egress IP changed:

```sh
curl ifconfig.me   # should print the exit node's public IP, not yours
```

When an exit node is in use, traffic for everything *outside*
`100.64.0.0/10` flows through that peer's WireGuard tunnel. The MTU
on your tunnel interface drops to accommodate the WG header (typically
`1280` vs the LAN's `1500`) — see [`exit-node.md`](exit-node.md)
§"What changes when you exit-route".

## 5. Tagged-access (ACL gates)

Your tailnet owner publishes an ACL document — either a TOML doc
(chain-anchored flow) or a HuJSON policy doc (stock-Tailscale flow,
shipped via the operator's `headscale` policy file). The doc
restricts which peers can talk to which other peers and on what
ports.

You can't see the doc directly unless the owner shares it, but its
**hash** is anchored on chain for chain-anchored tailnets:

```sh
octravpn tailnet info --tailnet my-tailnet | grep acl_hash
```

Practical user-side rules:

- If a peer is in the roster (`tailscale status`) but every connection
  attempt is refused / times out, an ACL rule is probably blocking
  you. Ask the owner.
- ACL changes propagate via the long-poll wake — typically <2 s on
  every peer. You don't need to restart `tailscaled`.
- If your wallet address moved to a different ACL group, log out and
  back in (`tailscale logout` + `tailscale up`) to refresh the
  per-peer attribute set.

The ACL data model (groups, hosts, ipsets, tag_owners, ssh blocks)
is the same as Tailscale's — see
[`crates/octravpn-mesh/src/acl.rs`](../../crates/octravpn-mesh/src/acl.rs)
and the canonical evaluator in `headscale-api-acl`.

## 6. File transfer

### `tailscale file cp` (stock Tailscale's Taildrop)

If both peers are running stock Tailscale and the operator allows it
in policy:

```sh
# On the sending peer:
tailscale file cp ./report.pdf laptop.my-tailnet.octra:

# On the receiving peer:
tailscale file get .
```

Files queue at the receiver until they call `tailscale file get`.
Whether this works depends on the operator's Tailscale-policy doc —
some block Taildrop entirely.

### Plain `scp` / `rsync`

Always works if SSH does (see §2 / [`ssh.md`](ssh.md)):

```sh
scp ./report.pdf you@laptop.my-tailnet.octra:~/Documents/
rsync -avz ./project/ you@laptop.my-tailnet.octra:~/project/
```

`scp` over the tailnet doesn't traverse the public internet — the
bytes go peer-to-peer through the WireGuard tunnel.

## 7. Verifying connectivity

The four commands you'll run when something looks off:

```sh
tailscale ip                              # what's my tailnet IP
tailscale status                          # roster + connection paths
tailscale ping desktop.my-tailnet.octra   # WG-level ping, prints path
tailscale netcheck                        # DERP relay reachability, NAT type
```

`tailscale ping` is special — it bypasses the normal ping path and
tests the WireGuard tunnel directly. Output tells you whether you're
on a `direct` connection or falling back through a `derp` relay. The
3-peer interop harness (`docker/devnet/tailscale-interop/run-interop.sh`)
exits code 0 only when `tailscale ping` succeeds between two stock
clients connected to our control plane — that's the load-bearing
contract test for the wire protocol.

For chain-anchored tailnets, the chain-level inspector is:

```sh
octravpn tailnet info  --tailnet my-tailnet   # on-chain metadata
octravpn tailnet peers --tailnet my-tailnet   # per-peer FSM state
```

`tailnet peers` reads the mesh manager's audit cache (Direct / Relay
/ Probing per peer) and falls back to a chain snapshot if no mesh
is currently up.

## 8. `oct://` URLs (chain-anchored tailnets)

Your operator may hand out `oct://<circle_id>/<path>` links — these
resolve to assets hosted inside an Octra circle (sealed JSON,
configs, policy documents, occasionally HTML).

Two ways to fetch:

```sh
octravpn fetch oct://octCircleX/policy.json        # raw → stdout
octravpn open-url oct://octCircleX/index.html      # render in browser
```

`open-url` dispatches to a local-only browser portal on
`127.0.0.1:51823` (start it explicitly with `octravpn portal`).
See [`oct-url-public.md`](oct-url-public.md) for the public-asset
flow and [`oct-url-sealed.md`](oct-url-sealed.md) for the sealed
(encrypted) variant where the portal makes you type a passphrase
before rendering plaintext.

## 9. Leaving the tailnet (for the day)

```sh
tailscale down            # disconnect, keep state for next time
```

To leave permanently — wipe local state, log out of the control
plane — see [`uninstall.md`](uninstall.md).

For chain-anchored tailnets, the **owner** removes you with
`octravpn tailnet remove-member`; you can't unilaterally leave from
the chain side. Locally, `tailscale logout` is enough.

## See also

- [`ssh.md`](ssh.md) — SSH-over-OctraVPN deep-dive, per-user rules,
  `tailscale ssh`
- [`magicdns.md`](magicdns.md) — name resolution, base domain,
  SplitDNS, extra records
- [`exit-node.md`](exit-node.md) — exit routing, MTU, per-class
  pricing
- [`oct-url-public.md`](oct-url-public.md) /
  [`oct-url-sealed.md`](oct-url-sealed.md) — the `oct://` URL flow
- [`../tailnet-user-guide.md`](../tailnet-user-guide.md) — for tailnet
  **owners**: create, add-member, set-acl, configure-exit, treasury
