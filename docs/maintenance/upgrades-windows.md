# OctraVPN — Windows upgrade runbook

<!-- UNVERIFIED — the dev box producing this runbook is macOS; the
     Windows commands below are derived from the install/uninstall
     flow in `docs/install.md` and the WinTUN driver model documented
     by WireGuard. Verify on a Windows host before promoting. -->

In-place upgrade of `octravpn-node` on Windows. The shipped install
path is an MSI; the daemon runs as a Windows service under
`LocalSystem`, and the data-plane uses the **WinTUN** kernel driver.

The four phases mirror Linux + macOS: **pre-flight**, **stop**,
**install**, **verify**.

## 0. Background

| Surface | Windows path |
|---|---|
| Binary | `C:\Program Files\OctraVPN\octravpn-node.exe` |
| Config | `%ProgramData%\octravpn\node.toml` |
| State (audit dir, journal, sealed keys) | `%ProgramData%\octravpn\state\` |
| Service name | `octravpn-node` |
| Service controller | PowerShell (`Get-Service`, `Restart-Service`) or `sc.exe` |
| WinTUN driver | `C:\Windows\System32\drivers\wintun.sys` (installed by WireGuard or our MSI) |
| Log file | `%ProgramData%\octravpn\logs\octravpn-node.log` <!-- UNVERIFIED — actual log path depends on MSI ship --> |

`%ProgramData%` is typically `C:\ProgramData` (an ACL-restricted
all-users location). The MSI sets ACLs so only `LocalSystem` and
admins can read the sealed-key files in
`%ProgramData%\octravpn\state\`.

## 1. Pre-flight (on the OLD binary)

Run an elevated PowerShell (Win+X → Terminal (Admin)). Same four
checks as the other OSes:

```powershell
# 1.1 Config validates against current binary.
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    --config "$env:ProgramData\octravpn\node.toml" `
    config validate

# 1.2 Audit chain is clean.
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    --config "$env:ProgramData\octravpn\node.toml" `
    audit verify `
    --audit-path "$env:ProgramData\octravpn\state\audit\" `
    --journal-path "$env:ProgramData\octravpn\state\receipts.bin"

# 1.3 Health probe (chain + local + daemon HTTP).
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    --config "$env:ProgramData\octravpn\node.toml" `
    health `
    --remote http://localhost:51821

# 1.4 Current version.
& 'C:\Program Files\OctraVPN\octravpn-node.exe' --version
```

All four must exit 0. A non-zero exit on **audit verify** is the
high-stakes failure — see [audit-verify.md](audit-verify.md) before
continuing.

Capture the §1.3 output; the post-upgrade comparison wants the
same chain state.

## 2. Stop the service

```powershell
Stop-Service -Name octravpn-node
Get-Service  -Name octravpn-node | Format-List Name,Status,StartType
# Status must read 'Stopped'.
```

Confirm the process is gone:

```powershell
Get-Process -Name octravpn-node -ErrorAction SilentlyContinue
# No output = process exited cleanly.
```

If the service hangs in `StopPending` for >30s, take a process dump
before forcing it down — that's a graceful-shutdown bug we want a
repro for:

```powershell
# Capture (administrative):
Get-Process -Name octravpn-node | ForEach-Object {
    & 'C:\Windows\System32\rundll32.exe' 'C:\Windows\System32\comsvcs.dll' MiniDump $_.Id "$env:TEMP\octravpn-stop.dmp" full
}
# Then:
Stop-Service -Name octravpn-node -Force
```

## 3. Install the new version

### 3.1 MSI (signed installer)

```powershell
$VERSION = '<new-version>'
$URL = "https://github.com/octra-labs/octravpn/releases/download/v$VERSION/octravpn-node-$VERSION-x64.msi"
Invoke-WebRequest $URL -OutFile "$env:TEMP\octravpn-node.msi"

# (Optional) verify signature.
Get-AuthenticodeSignature "$env:TEMP\octravpn-node.msi" | Format-List

# Install — passive mode shows a progress bar but no prompts.
Start-Process msiexec.exe -ArgumentList '/i', "$env:TEMP\octravpn-node.msi", '/passive', '/norestart' -Wait
```

The MSI's upgrade table preserves the existing `%ProgramData%\octravpn\`
contents (config, state, sealed keys) and the service registration —
`Restart-Service` afterwards picks up the new binary against the
unchanged state.

> The MSI release artifact is not yet produced by the CI lane (see
> [`docs/release.md`](../release.md) which is Linux-only).
> Treat this section as the target shape; the actual MSI may not
> be downloadable from GitHub Releases for the version you're on.
> <!-- UNVERIFIED -->

### 3.2 Manual ZIP swap

If you installed from a ZIP (no MSI), swap the binary directly:

```powershell
$VERSION = '<new-version>'
$ZIP = "octravpn-$VERSION-x86_64-pc-windows-msvc.zip"
Invoke-WebRequest "https://github.com/octra-labs/octravpn/releases/download/v$VERSION/$ZIP" `
    -OutFile "$env:TEMP\$ZIP"

# Stash the previous binary for rollback.
Copy-Item 'C:\Program Files\OctraVPN\octravpn-node.exe' `
          'C:\Program Files\OctraVPN\octravpn-node.previous.exe'

Expand-Archive -Path "$env:TEMP\$ZIP" -DestinationPath "$env:TEMP\octravpn-extract" -Force
Copy-Item "$env:TEMP\octravpn-extract\octravpn-node.exe" `
          'C:\Program Files\OctraVPN\octravpn-node.exe' -Force
```

## 4. WinTUN driver compatibility

A new `octravpn-node` build may or may not require a new WinTUN
driver. The decision rule:

- We link against the `boringtun` crate (workspace dep
  `boringtun = "0.7"` in
  [`Cargo.toml`](../../Cargo.toml)). `boringtun` does not bundle a
  driver — it talks WireGuard over a userspace TUN device. On
  Windows, that means we **shell out to the WinTUN driver** the
  same way `wireguard-go` and the official WireGuard for Windows do.
- WinTUN's userspace API is stable across minor driver releases.
  An octravpn-node binary built against boringtun `0.7.x` works
  with any WinTUN driver `>= 0.14` (the API floor boringtun
  documents).
- The driver itself is shipped by the official WireGuard for
  Windows installer at <https://www.wireguard.com/install/>. Our
  MSI may bundle it or may declare a hard dependency on it being
  installed first — depends on the MSI build flags. <!-- UNVERIFIED -->

When to update the driver:

| Trigger | Action |
|---|---|
| `boringtun` major bump in our `Cargo.toml` (e.g. 0.7 → 0.8) | Check WinTUN minimum required API in the new crate's release notes; install the matching driver before the new node. |
| Octravpn-node release notes flag a WinTUN floor | Install matching driver before swapping the binary. |
| Otherwise | Driver swap is unnecessary; the userspace API contract is stable. |

To check the currently-installed driver version:

```powershell
Get-WmiObject Win32_PnPSignedDriver `
    | Where-Object { $_.DeviceName -like '*WinTUN*' } `
    | Select-Object DeviceName, DriverVersion
```

To upgrade the driver, download the latest WireGuard for Windows
installer and run it; the installer upgrades WinTUN in place
without touching octravpn-node state. Reboot when prompted.

> The `boringtun` version bump history in `Cargo.lock` is the
> authoritative signal for when the driver floor moves; we have not
> bumped within the v0.1 line, so as of v0.1.0 any WinTUN driver
> >=0.14 works. <!-- UNVERIFIED for future releases -->

## 5. Post-install verification

### 5.1 Schema validates against the new binary

```powershell
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    --config "$env:ProgramData\octravpn\node.toml" `
    config validate
```

Exit 0 expected. Non-zero = schema break or missing required field —
fix before starting the service.

### 5.2 Start the service

```powershell
Restart-Service -Name octravpn-node    # equivalent to Start when stopped
Get-Service     -Name octravpn-node | Format-List Name,Status,StartType
```

`Restart-Service` is the canonical Windows verb for "swap and
reload"; on a stopped service it acts as `Start-Service`.

### 5.3 Health probe (same as §1.3)

```powershell
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    --config "$env:ProgramData\octravpn\node.toml" `
    health `
    --remote http://localhost:51821
```

Compare against the §1.3 capture. Chain state must match; local-file
checks must all be `OK`.

### 5.4 Audit chain still clean

```powershell
& 'C:\Program Files\OctraVPN\octravpn-node.exe' `
    audit verify `
    --audit-path "$env:ProgramData\octravpn\state\audit\" `
    --journal-path "$env:ProgramData\octravpn\state\receipts.bin"
```

Exit 0 expected.

### 5.5 Version

```powershell
& 'C:\Program Files\OctraVPN\octravpn-node.exe' --version
```

### 5.6 Boot log

```powershell
Get-Content "$env:ProgramData\octravpn\logs\octravpn-node.log" -Tail 100
```

The log walks the same boot phases as the other OSes: chain ctx →
sealed keys → audit dir → receipt journal → control plane → tunnel.
A wedge at any phase is diagnosed via [recovery.md](recovery.md).

> The Windows logging path is not yet finalized — the daemon may
> write to a service log file under `%ProgramData%\octravpn\logs\`
> OR to the Windows Event Log under `Application` / Source
> `octravpn-node`. Try both:
> ```powershell
> Get-EventLog -LogName Application -Source octravpn-node -Newest 50
> ```
> <!-- UNVERIFIED -->

## 6. Rolling back

### 6.1 MSI rollback

```powershell
# Stop the service.
Stop-Service -Name octravpn-node

# Re-install the previous MSI (download it again, or cache it ahead
# of time alongside the new MSI).
Start-Process msiexec.exe -ArgumentList '/i', 'C:\Path\To\octravpn-node-<prev>-x64.msi', '/passive', '/norestart' -Wait

Restart-Service -Name octravpn-node
```

The MSI's upgrade table handles "newer-to-older" as a downgrade
when the previous package's `ProductVersion` is lower; the state on
disk is forward-compatible so this works.

### 6.2 ZIP rollback

```powershell
Stop-Service -Name octravpn-node
Move-Item 'C:\Program Files\OctraVPN\octravpn-node.previous.exe' `
          'C:\Program Files\OctraVPN\octravpn-node.exe' -Force
Restart-Service -Name octravpn-node
```

## 7. Common Windows-specific upgrade mistakes

1. **WinTUN driver mismatch ignored.** A boringtun bump that floats
   the WinTUN floor presents as `tunnel up failed: device not
   found` in the boot log; the daemon partially boots (audit dir
   opens, control plane binds) then fails to bring up the tunnel.
   Fix: install a current WireGuard for Windows release to refresh
   WinTUN. <!-- UNVERIFIED — observed pattern, not verified
   against this codebase -->
2. **Service config (passphrase / paths) cleared by the MSI.** If
   the upgrade MSI resets the service's `Environment` property
   (depends on how the MSI is built), the daemon loses
   `OCTRAVPN_KEY_PASSPHRASE` and fails sealed-keys unseal at boot.
   Restore the env var on the service:
   ```powershell
   sc.exe config octravpn-node `
       binPath= '"C:\Program Files\OctraVPN\octravpn-node.exe" --config "%ProgramData%\octravpn\node.toml" run'
   # Env vars are not part of the SCM config; use a Registry value
   # under HKLM\SYSTEM\CurrentControlSet\Services\octravpn-node\Environment
   # OR a setx /M call before service start. See `docs/install.md`
   # for the canonical bootstrap.
   ```
   <!-- UNVERIFIED -->
3. **`Restart-Service` succeeds but the daemon flaps.** If the
   service status oscillates between `Running` and `Stopped`, the
   Windows Service Manager is restarting after each crash. Read
   `octravpn-node.log` or the Application event log for the boot
   phase the daemon crashed in. See
   [recovery.md](recovery.md) for the phase-by-phase diagnosis.

## References

- [Linux upgrade runbook](upgrades-linux.md) — analogous flow with
  the deepest pre-flight + post-flight detail.
- [macOS upgrade runbook](upgrades-macos.md) — similar shape with
  launchd specifics.
- [Install guide](../install.md) — first-time install for Windows.
- [Recovery runbook](recovery.md) — boot-phase diagnostics.
- [WinTUN](https://www.wintun.net/) — driver documentation upstream.
- [WireGuard for Windows](https://www.wireguard.com/install/) —
  driver bundle source.
