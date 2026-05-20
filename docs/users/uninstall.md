# Uninstalling OctraVPN — per OS

This is the clean-removal reference. Follow whichever section
matches the OS you installed on. Each section removes (1) the
binaries, (2) the system service, (3) the state directories.

For partial cleanup — disconnect but keep the install ready to
re-join — use `tailscale logout` instead and stop here.

## Linux

```sh
# Disconnect first (drops the registration so re-join needs a fresh key)
sudo tailscale down
sudo tailscale logout

# Stop and disable the daemon
sudo systemctl disable --now tailscaled

# Remove the package
sudo apt remove --purge tailscale          # Debian / Ubuntu
sudo dnf remove tailscale                  # Fedora / RHEL / Rocky
sudo pacman -Rns tailscale                 # Arch / Manjaro
sudo rm /usr/local/bin/tailscale /usr/local/sbin/tailscaled  # tarball install

# State directories
sudo rm -rf /var/lib/tailscale
sudo rm -rf /var/log/tailscale
sudo rm -f /etc/default/tailscaled

# Optional: octravpn CLI (only if installed)
sudo rm -f /usr/local/bin/octravpn
rm -rf ~/.octravpn        # tailnet bookmarks + per-tailnet config
```

If you installed the operator-side daemon (you almost certainly did
not — see [`linux.md`](linux.md) §3), also remove:

```sh
sudo systemctl disable --now octravpn-node
sudo rm -f /etc/systemd/system/octravpn-node.service
sudo rm -f /etc/systemd/system/octravpn-attest.service
sudo rm -f /etc/systemd/system/octravpn-attest.timer
sudo rm -rf /etc/octravpn /var/lib/octravpn /var/log/octravpn
sudo userdel octravpn 2>/dev/null
sudo groupdel octravpn 2>/dev/null
```

The locations are pinned by [`deploy/debian/postinst`](../../deploy/debian/postinst).
Running `apt remove --purge octravpn-node` invokes `postrm` which
covers most of this automatically; the manual steps are for
tarball / source installs.

## macOS

```sh
# Disconnect first
sudo tailscale down
sudo tailscale logout
sudo brew services stop tailscale 2>/dev/null || true

# Remove the binary
brew uninstall tailscale 2>/dev/null || true
sudo rm -rf /Applications/Tailscale.app

# Remove the launchd plist (if Homebrew or manual install)
sudo launchctl bootout system /Library/LaunchDaemons/homebrew.mxcl.tailscale.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/homebrew.mxcl.tailscale.plist

# State directories
sudo rm -rf /Library/Tailscale
sudo rm -rf /Library/Application\ Support/Tailscale
rm -rf ~/Library/Containers/io.tailscale.ipn.macsys
rm -rf ~/Library/Group\ Containers/*.io.tailscale.ipn
rm -rf ~/Library/Caches/io.tailscale.ipn.macsys

# Network Extension entry: open System Settings →
# General → Login Items & Extensions → Network Extensions,
# select Tailscale, click "-", authenticate to remove.

# Optional: octravpn CLI
sudo rm -f /usr/local/bin/octravpn
rm -rf ~/.octravpn
```

If you installed the operator-side daemon via the macOS .pkg
([`deploy/macos-pkg/`](../../deploy/macos-pkg/)) or
[`deploy/launchd/com.octravpn.node.plist`](../../deploy/launchd/com.octravpn.node.plist):

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.octravpn.node.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.octravpn.node.plist
sudo rm -f /usr/local/bin/octravpn-node
sudo rm -rf /usr/local/etc/octravpn /usr/local/var/log/octravpn-node.*
```

## Windows

<!-- UNVERIFIED on this dev box -->

```powershell
# Disconnect first
tailscale down
tailscale logout

# Stop the service
Stop-Service Tailscale

# Uninstall the MSI
winget uninstall --id=tailscale.tailscale
# OR via Settings → Apps → Tailscale → Uninstall

# State directory (the uninstaller usually clears this, but check)
Remove-Item -Recurse -Force C:\ProgramData\Tailscale -ErrorAction SilentlyContinue

# Optional: octravpn CLI
Remove-Item -Recurse -Force "C:\Program Files\OctraVPN" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\ProgramData\OctraVPN" -ErrorAction SilentlyContinue
# Then remove C:\Program Files\OctraVPN from System Environment
# Variables → Path manually (Settings → System → About → Advanced
# system settings → Environment Variables).
```

If you installed the operator-side daemon via
[`deploy/windows/install-service.ps1`](../../deploy/windows/install-service.ps1):

```powershell
# The companion script removes the service cleanly
& "C:\Program Files\OctraVPN\uninstall-service.ps1"
```

That removes the `OctraVPN-Node` Windows service registration. The
binary and state directory removal above still apply.

## After uninstall

A clean machine has:

- No `tailscale` / `octravpn` / `octravpn-node` binary on `PATH`.
- No daemon running (`systemctl status tailscaled` →
  "Unit not found", `Get-Service Tailscale` → "Cannot find" on
  Windows).
- No state directory (per-OS list above).
- No Network Extension entry visible in System Settings (macOS only).

Re-installing later starts from scratch — you'll need a fresh
preauth key from your operator.
