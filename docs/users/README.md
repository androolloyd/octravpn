# OctraVPN — End-user guide

You are here because a colleague has set up an OctraVPN tailnet and
sent you a join key. These docs walk you through joining it, using
it day-to-day, and tearing it back down.

If you are the person *running* the tailnet — minting preauth keys,
hosting the control plane, configuring exit nodes — you want
[`docs/operators/`](../operators/) instead. See the
"Operator docs" section at the bottom of this page.

## What is OctraVPN, in 60 seconds

OctraVPN is a self-hosted Tailscale-style mesh VPN. Each device joins
a private network ("tailnet") via WireGuard tunnels coordinated by a
control plane your tailnet owner runs.

A few specifics that matter for end users:

- **It is not a paid VPN service.** OctraVPN does not have a
  subscription, an account portal, or a "buy a plan" page. Your access
  is a preauth key issued by whoever runs your tailnet, full stop.
- **The control plane is Tailscale-wire-compatible.** Stock
  `tailscale` clients (the open-source ones from
  <https://tailscale.com/download>) connect to it via the standard
  `--login-server` flag. You install Tailscale the normal way, then
  point it at your tailnet owner's URL.
- **Traffic is end-to-end encrypted WireGuard.** Peers talk directly
  whenever NAT allows; otherwise they fall back to a DERP relay your
  operator configures. Either way, the control plane never sees plain
  packet contents.
- **You may also see `octravpn` (the CLI).** That binary adds chain-
  anchored tailnet features (treasury-backed paid exits, on-chain ACL
  hashes) on top of the basic Tailscale flow. End users on a normal
  tailnet usually do **not** need it — your operator does. See
  [`docs/tailnet-user-guide.md`](../tailnet-user-guide.md) if your
  tailnet uses the chain-anchored flow.

## What you need before installing

Get these three values from your tailnet owner (Slack DM, Signal,
PGP — wherever they prefer):

1. **A preauth key.** A string like `octrapreauth-7a3f…d8b1` (or, for
   stock-headscale-format keys, a 48-hex-character blob). Single-use
   by default. Don't paste it anywhere public.
2. **The login-server URL.** Something like
   `https://mesh.example.org` (HTTPS-on-443). This is the operator's
   coordination endpoint.
3. **Whether the tailnet uses tags.** If the operator's policy
   requires it, they will tell you something like
   `--advertise-tags=tag:eng`. Otherwise skip.

You do **not** need an Octra wallet, an Octra account, or any
on-chain operations to join a tailnet this way. The chain-anchored
flow ([`docs/tailnet-user-guide.md`](../tailnet-user-guide.md)) is a
separate path your operator will tell you about explicitly.

## Install jump-table

Pick your operating system:

| OS         | Walk-through                  | What you'll install                          |
|------------|-------------------------------|----------------------------------------------|
| Linux      | [`linux.md`](linux.md)        | Stock `tailscale` from your distro + optional `octravpn` CLI |
| macOS      | [`macos.md`](macos.md)        | Tailscale.app (or CLI) from Homebrew + optional `octravpn` CLI |
| Windows    | [`windows.md`](windows.md)    | Tailscale MSI installer + optional `octravpn.exe` |

After install, the same per-OS guide walks you through the first
`tailscale up` (or `tailscale login` on macOS GUI) using the preauth
key.

## What to read next

1. **First time only:** the per-OS install guide above. Stop when
   it tells you "your tailscale IP is 100.64.x.x" — that means you
   are joined.
2. **Verifying the join + everyday use:**
   [`connect.md`](connect.md) — the OS-agnostic dance: where the
   preauth key goes, what `tailscale up` actually does, how to ping
   a peer, when to use `--ephemeral`, what gets persisted.
3. **When you leave the tailnet:** [`uninstall.md`](uninstall.md) —
   clean uninstall per OS, with the state-file paths each platform
   uses so you can wipe leftover material.

## If something breaks

Each per-OS guide has a "Troubleshooting" section near the end with
the platform-specific failure modes (kernel module missing on Linux,
Network Extension permission prompt on macOS, WinTUN driver on
Windows, etc.).

Cross-platform symptoms — `tailscale up` hangs, TLS handshake fails,
peer not visible — are covered in [`connect.md`](connect.md) §6.

If you are *running* the tailnet and something is broken on the
control-plane side, see the operator-side troubleshooting in
[`docs/troubleshooting.md`](../troubleshooting.md) and
[`docs/operators/tls-rotation.md`](../operators/tls-rotation.md).

## Operator docs (separated for safety)

If you are the tailnet owner, you want **these** instead:

- [`docs/operators/mainnet-deployment.md`](../operators/mainnet-deployment.md)
  — running a paid Octra-chain-anchored node.
- [`docs/operators/cli-migration.md`](../operators/cli-migration.md)
  — the embedded `octravpn-node headscale …` admin surface (mint
  preauth keys, list nodes, manage policy).
- [`docs/operators/tls-rotation.md`](../operators/tls-rotation.md) —
  TLS cert rotation on the control plane.
- [`docs/tailnet-user-guide.md`](../tailnet-user-guide.md) — the
  chain-anchored owner & member flow (`octravpn tailnet create`,
  `add-member`, `set-acl`, treasury, paid exits).
- [`docs/install.md`](../install.md) — the broader install guide
  including building from source.

End-users do not need any of the above. They are listed here so
contributors landing on this page know where the operator material
lives.
