# OctraVPN — Install Guide

Three install methods per platform: one-shot script (curl|sh / iex),
native package (deb / rpm / pkg / msi / Homebrew), or build from source.

## One-shot (recommended for trying it out)

### Linux / macOS

```sh
# Client only.
curl -fsSL https://octravpn.org/install.sh | sh

# Client + node + system service.
curl -fsSL https://octravpn.org/install.sh | sh -s -- --node

# Pin a version.
curl -fsSL https://octravpn.org/install.sh | sh -s -- --version=0.2.0 --node
```

The script:
- Detects your OS/arch.
- Downloads the matching release tarball from GitHub Releases.
- Verifies the signature with `minisign` if available (and the public
  key is at `~/.minisign/octravpn.pub` or `$OCTRAVPN_MINISIGN_PUBKEY`).
- Installs binaries to `/usr/local/bin/`.
- With `--node`: registers a `systemd` unit (Linux) or `launchd` plist
  (macOS) at `/etc/systemd/system/octravpn-node.service` /
  `/Library/LaunchDaemons/com.octravpn.node.plist`.
- On Linux, sets `CAP_NET_ADMIN + CAP_NET_BIND_SERVICE` on the node
  binary so it can open a TUN device without running as root.

### Windows (elevated PowerShell)

```powershell
iex (irm https://octravpn.org/install.ps1)

# Or with options:
iex "& { $(irm https://octravpn.org/install.ps1) } -Node -Version 0.2.0"
```

## Native packages

### Debian / Ubuntu

```sh
curl -fsSL https://octravpn.org/octravpn-node_${VERSION}_amd64.deb -o /tmp/x.deb
sudo apt install /tmp/x.deb
sudo systemctl enable --now octravpn-node
```

### Fedora / RHEL / Alma

```sh
sudo dnf install https://octravpn.org/octravpn-node-${VERSION}.x86_64.rpm
sudo systemctl enable --now octravpn-node
```

### macOS .pkg

Download the signed + notarized `.pkg` from
<https://github.com/octra-labs/octravpn/releases>, double-click,
follow the installer. The launchd service is auto-registered. Start it:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.octravpn.node.plist
```

### Homebrew

```sh
brew tap octra-labs/octravpn
brew install octravpn          # client only
brew install octravpn-node     # node + brew services
brew services start octravpn-node
```

### Windows .msi

Download the `.msi` from the releases page, double-click, follow the
installer. Then from an elevated PowerShell:

```powershell
& "${env:ProgramFiles}\OctraVPN\install-service.ps1"
```

## From source

```sh
git clone https://github.com/octra-labs/octravpn
cd octravpn

# Client (octravpn). This is the v1.1 + v2 user binary.
cargo build --release -p octravpn

# Operator daemon (octravpn-node).
cargo build --release -p octravpn-node
```

Binaries land at `target/release/octravpn` and
`target/release/octravpn-node`.

For chain-side operations (deploying operator circles, sealing
policy, posting tx envelopes against the v2 program) you also need
`octra cast` from the sibling [`octra-foundry`](https://github.com/octra-labs/octra-foundry)
repo:

```sh
git clone https://github.com/octra-labs/octra-foundry ../octra-foundry
cargo build --release --manifest-path ../octra-foundry/Cargo.toml -p octra-cast
# Binary at ../octra-foundry/target/release/octra-cast — symlink onto $PATH as `octra`.
```

For the encrypted-earnings settlement path you need the **pvac-sidecar**
daemon. It's GPL-isolated; build via docker:

```sh
docker build -t octravpn/pvac-sidecar -f pvac-sidecar/Dockerfile .
```

The sidecar exposes a local gRPC surface that `octravpn-node` consumes
for HFHE pubkey registration and the per-session encrypted-bytes
accumulator. See `docker-compose.yml` for how the devnet harness wires
it in.

## Provisioning

After install:

```sh
# Generate a wallet + config skeleton.
octravpn init --rpc-url https://octra.network/rpc \
              --program-addr oct...REAL_OCTRAVPN_PROGRAM_ADDR...

# Sanity check.
octravpn doctor
```

For node operators, similar:

```sh
sudo octravpn-node init --config /etc/octravpn/node.toml \
                        --rpc-url https://octra.network/rpc
sudo systemctl enable --now octravpn-node
```

## Environment variables for v2

The v2 substrate reads two passphrase env vars. Neither is prompted
for at runtime — set them in the shell that launches the binary (or
in your service unit's `Environment=` block):

| Variable | Used by | Purpose |
| --- | --- | --- |
| `OCTRAVPN_SEALED_PASSPHRASE` | client | Decrypts each operator circle's sealed `/policy.json`. Tailnet-wide; the same value across every member of a given tailnet. |
| `OCTRAVPN_KEY_PASSPHRASE` | node (operator) | Unwraps `*.sealed` wallet/WG secrets when `[chain].require_sealed_keys = true`. Per-operator. |

Both fall back to legacy / config-file paths for back-compat (see the
v2 client flow + key hygiene docs); production deployments should use
the env vars. Storing either in a plaintext `.env` defeats the point —
prefer your platform keyring (macOS Keychain, Linux kernel keyring,
GNOME secret-service, KeepassXC, AWS/GCP secret manager).

## Permissions cheat sheet

| OS | TUN-open path | Action |
| --- | --- | --- |
| Linux | `/dev/net/tun` ioctl | `setcap cap_net_admin,cap_net_bind_service+ep /usr/local/bin/octravpn-node` (done by install.sh) |
| macOS | `utun` kernel control | service must run as root (launchd default) |
| Windows | wintun driver | service runs as `LocalSystem`; install [wintun.dll](https://www.wireguard.com/install/) once |

## Verifying the install

```sh
octravpn doctor
```

Expected output:

```
[ ok ] config file readable
[ ok ] wallet secret loadable
[ ok ] TUN device subsystem present
[ ok ] kernel supports user namespaces (optional)

All checks passed.
```

Anything `[fail]` includes the precise reason. Common ones:

- `TUN device subsystem present: /dev/net/tun missing` — your kernel
  doesn't have the `tun` module loaded; `sudo modprobe tun`.
- `TUN device subsystem present: macOS utun requires root` —
  re-run via `sudo`, or use the launchd service (which runs as root).

## Uninstall

```sh
# Linux (deb)
sudo apt remove octravpn-node octravpn

# Linux (rpm)
sudo dnf remove octravpn-node octravpn

# macOS (brew)
brew uninstall octravpn-node octravpn
brew untap octra-labs/octravpn

# macOS (pkg)
sudo rm /Library/LaunchDaemons/com.octravpn.node.plist
sudo rm /usr/local/bin/octravpn /usr/local/bin/octravpn-node
sudo rm -rf /usr/local/etc/octravpn

# Windows
& "${env:ProgramFiles}\OctraVPN\uninstall-service.ps1"
# Then uninstall from Settings → Apps.
```
