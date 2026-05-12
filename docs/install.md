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
cargo build --release -p octravpn-client -p octravpn-node
```

Binaries land at `target/release/octravpn` and `target/release/octravpn-node`.

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
