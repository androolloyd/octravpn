# OctraVPN on Windows — install + first connect

This walks an end-user from a vanilla Windows 10/11 box to a working
WireGuard tunnel into someone else's OctraVPN tailnet. You will
install two pieces:

1. **Tailscale for Windows** — the stock signed MSI installer from
   <https://tailscale.com/download/windows>. This installs the
   Tailscale Windows service, the system-tray GUI, and the WinTUN
   driver. We use stock Tailscale unchanged.
2. **`octravpn.exe`** (this project's optional client). End users on
   a normal `--login-server` tailnet usually do **not** need it.

> <!-- UNVERIFIED on this dev box -->
> This guide was written on macOS. Every Windows-specific command
> below is sourced from the project's `deploy/windows/` scripts and
> public Tailscale documentation, but **none of it was end-to-end
> tested from a real Windows 10 / Windows 11 install during the
> writing of this document**. Sections that depend on Windows-only
> behaviour (driver install, Defender Firewall, group policy) are
> marked with the `<!-- UNVERIFIED -->` comment so the next person to
> polish this doc on Windows knows where to focus.

## 1. Install stock Tailscale

<!-- UNVERIFIED on this dev box -->

Two install paths:

### Option A — the MSI installer (recommended)

1. Browse to <https://tailscale.com/download/windows>.
2. Download `tailscale-setup-<version>.exe` (it is an MSI bundle).
3. Right-click → "Run as administrator".
4. Accept defaults. The installer:
   - Installs `tailscale.exe` and `tailscaled.exe` under
     `C:\Program Files\Tailscale\`.
   - Registers the "Tailscale" Windows service (set to Automatic
     start).
   - Installs the WinTUN driver (this is what creates the virtual
     adapter).
   - Adds the tray icon to your user session.

After install, open PowerShell and verify:

```powershell
tailscale version
Get-Service Tailscale
```

Service state should be `Running`. OctraVPN regression-tests against
Tailscale `1.78+`; older clients may not reach the post-DERP
datapath.

### Option B — winget

```powershell
winget install --id=tailscale.tailscale
```

Same end state, just scripted.

## 2. (Optional) Install `octravpn.exe`

<!-- UNVERIFIED on this dev box -->

Skip if your operator only gave you a preauth key + login-server.

### Via the project installer

From an **elevated** PowerShell (Run as administrator):

```powershell
iex (irm https://octravpn.org/install.ps1)
```

This runs [`deploy/install.ps1`](../../deploy/install.ps1) which:

- Downloads the matching `octravpn-<version>-x86_64-pc-windows-msvc.zip`
  (or `aarch64-...` for ARM64 boxes) from GitHub Releases.
- Extracts to `C:\Program Files\OctraVPN\`.
- Adds that directory to the system `PATH`.

Open a new PowerShell after install (so the updated PATH is picked
up) and verify:

```powershell
octravpn --help
```

### From a release ZIP

If `iex (irm ...)` is blocked by your corporate proxy, download the
release ZIP from the GitHub Releases page directly:

1. Right-click the ZIP → Properties → check "Unblock" → OK.
2. Extract to `C:\Program Files\OctraVPN\` (you'll need admin).
3. Add `C:\Program Files\OctraVPN` to **System Environment Variables
   → Path**.

## 3. Windows service vs the system-tray GUI

The MSI installs **both** sides of Tailscale:

- **The `Tailscale` Windows service** (`tailscaled.exe`, runs as
  `LocalSystem`). This is what actually owns the WinTUN adapter and
  speaks WireGuard. Always-on, survives logout.
- **The tray UI** (`tailscale.exe gui`, runs in your user session).
  It is a thin client of the service — login state, peer list,
  enable/disable toggles. Closing the tray does **not** disconnect.

For CLI joins (which is what we do below) you only need the service.
The tray is optional but useful for at-a-glance status.

<!-- UNVERIFIED on this dev box -->
The project's [`deploy/windows/install-service.ps1`](../../deploy/windows/install-service.ps1)
installs a different service — `OctraVPN-Node` — which is the
operator-side daemon, not the Tailscale client. End users **do not**
run that script. It is for the person hosting the mesh-control
endpoint.

## 4. First connect via PowerShell

Get from your operator:

- **Login-server URL** — usually `https://<host>:443`.
- **Preauth key** — single-use unless they said otherwise.

In an **elevated** PowerShell:

```powershell
tailscale up `
    --login-server https://mesh.example.org `
    --authkey octrapreauth-YOUR-KEY-HERE
```

Notes:

- The backtick `` ` `` is PowerShell's line continuation. If you
  prefer one line, drop them.
- `--authkey` consumes the key on first use. Subsequent `tailscale
  up` runs do not need it; registration state persists at
  `C:\ProgramData\Tailscale\`.
- Add `--hostname=<name>` if you want a specific name in the
  roster; defaults to `$env:COMPUTERNAME`.

The command blocks for up to ~60 s on initial register. On success
it returns with no output.

## 5. Verify

<!-- UNVERIFIED on this dev box -->

### `tailscale status`

```powershell
tailscale status
```

You should see your row plus one row per peer:

```text
100.64.0.3   andrew@desktop      windows   active; relay "use1"
100.64.0.7   colleague@laptop    macos     idle
```

### `Get-NetAdapter`

```powershell
Get-NetAdapter | Where-Object { $_.Name -like '*Tailscale*' }
```

You should see one adapter (driver: WinTUN) with `Up` status. If
absent, the WinTUN driver failed to bind — see Troubleshooting below.

### `Test-NetConnection`

```powershell
Test-NetConnection -ComputerName <peer-hostname> -Port 22
```

Replace `22` with a port you expect the peer to have open. A
`TcpTestSucceeded : True` confirms the WireGuard datapath is live.

### `tailscale ping` (headline test)

```powershell
tailscale ping <peer-hostname>
```

RTTs annotated `via DERP(...)` are relay-routed; bare UDP endpoint
RTTs are direct peer-to-peer. Either confirms a working join.

## 6. Troubleshooting

### WinTUN driver install fails

<!-- UNVERIFIED on this dev box -->

Symptom: the MSI install succeeds, but `Get-NetAdapter` shows no
Tailscale interface, and `tailscale status` reports "no state".

Causes & fixes:

- **Driver signing policy.** Some locked-down corporate images
  require all drivers to be signed by a specific CA. Tailscale's
  WinTUN driver is Microsoft-signed (WHQL); if your IT team has
  pinned a stricter policy, ask them to allowlist Tailscale.
- **Secure Boot blocking unsigned kernel mod.** Should never apply
  to a stock MSI, but if you sideloaded an older `wintun.dll`,
  remove it: `Remove-Item C:\Windows\System32\wintun.dll`.
- **Conflicting WireGuard install.** If you previously installed the
  standalone WireGuard for Windows app, uninstall it. They share the
  driver and the older copy may win.

After driver fixes:

```powershell
Restart-Service Tailscale
```

### Windows Defender Firewall blocks

<!-- UNVERIFIED on this dev box -->

The MSI installer adds firewall rules automatically, but corporate
GPO can revert them. Check:

```powershell
Get-NetFirewallRule -DisplayName "*Tailscale*"
```

If absent or `Enabled: False`, re-add (admin shell):

```powershell
New-NetFirewallRule -DisplayName "Tailscale" `
    -Direction Inbound `
    -Program "C:\Program Files\Tailscale\tailscaled.exe" `
    -Action Allow `
    -Profile Any
```

For UDP egress on 41641 (Tailscale's default WireGuard port) and
443 (control + DERP), ensure your firewall allows outbound; defaults
permit it, but locked-down profiles may need explicit rules.

### Split-tunneling quirks: Windows 10 vs 11

<!-- UNVERIFIED on this dev box -->

Windows 10 and 11 differ in how they handle "Use Tailscale as exit
node" + DNS:

- **Windows 11** honours per-route DNS correctly. Set an exit node
  in the tray and DNS for non-tailnet names resolves via your
  default; tailnet names via Tailscale.
- **Windows 10** sometimes leaks all DNS to the exit node. If you
  see DNS for non-tailnet names going via the exit, run:
  `tailscale set --accept-dns=false` and use the peer IPs directly.

This is a known Tailscale-on-Windows behavior, not OctraVPN-specific.

### Group policy override

<!-- UNVERIFIED on this dev box -->

If you're on a domain-joined machine, GPO may forbid VPN clients
entirely. Test:

```powershell
gpresult /R | Select-String -Pattern "VPN"
```

If a "No third-party VPN" policy is in effect, OctraVPN is blocked
at the OS layer and there is no client-side fix — work with your
IT team.

### TLS handshake failure

<!-- UNVERIFIED on this dev box -->

Symptom: `tailscale up` stalls then errors with a TLS message.

- **Self-signed cert.** Get the CA PEM from your operator, then
  import it into the system trust store:

  ```powershell
  Import-Certificate -FilePath "operator-ca.pem" `
      -CertStoreLocation Cert:\LocalMachine\Root
  ```

- **Time skew.** TLS fails if your clock is off. `w32tm /resync`.

## 7. Removing

<!-- UNVERIFIED on this dev box -->

```powershell
# Disconnect first
tailscale down
tailscale logout

# Stop the service
Stop-Service Tailscale
```

Uninstall via the Start menu → "Add or remove programs" → Tailscale →
Uninstall. Or scripted:

```powershell
winget uninstall --id=tailscale.tailscale
```

Clean state directories (the Tailscale uninstaller does this on
modern versions but it's safe to re-check):

```powershell
Remove-Item -Recurse -Force C:\ProgramData\Tailscale
```

If you also installed `octravpn.exe`:

```powershell
Remove-Item -Recurse -Force "C:\Program Files\OctraVPN"
Remove-Item -Recurse -Force "C:\ProgramData\OctraVPN"
# Plus remove C:\Program Files\OctraVPN from the system PATH manually.
```

See [`uninstall.md`](uninstall.md) for the cross-platform state-file
list.

## If something breaks

- Windows-specific driver / firewall / GPO issues — §6 above.
- Cross-platform connect issues — [`connect.md`](connect.md).
- Operator-side TLS / control-plane problems — point them at
  [`docs/operators/tls-rotation.md`](../operators/tls-rotation.md)
  and [`docs/troubleshooting.md`](../troubleshooting.md).
